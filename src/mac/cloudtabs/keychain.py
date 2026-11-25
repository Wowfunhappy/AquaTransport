"""Read the PCS key material needed for Safari from CKKS records."""
from __future__ import absolute_import, division, print_function, unicode_literals
from compat import text_type, binary_type, integer_types, UTC, b64decode, log
import base64
import datetime
import hashlib
import hmac
import plists as plistlib
import struct
from native import load_public,load_private,point_key
from client import CloudKit, parse, pb, one, sub, text, private_read, private_write
from crypto import x963, gcm_decrypt, siv_decrypt
from recover import peer_info, trust_metadata


def record_id(record):
    return text(sub(sub(record, 2), 1), 1)


def fields(record):
    result = {}
    for raw in record.get(7, []):
        field = parse(raw)
        name = text(sub(field, 1), 1)
        if not name or name in result:
            raise ValueError('Invalid or duplicate record field')
        result[name] = sub(field, 2)
    return result


def value(field):
    kind = one(field, 1)
    if one(field, 13, 0):
        raise ValueError('Unexpected CloudKit field encryption in CKKS')
    if kind in (1, 20):
        return one(field, 2, b'')
    if kind == 3:
        return text(field, 7)
    if kind == 7:
        n = one(field, 4, 0)
        return n - (1 << 64) if n >= 1 << 63 else n
    if kind == 8:
        data = one(field, 5)
        if not isinstance(data, binary_type) or len(data) != 8:
            raise ValueError('Invalid floating-point record field')
        return struct.unpack(b'<d', data)[0]
    if kind == 2:
        data = one(sub(field, 6), 1)
        if not isinstance(data, binary_type) or len(data) != 8:
            raise ValueError('Invalid date record field')
        # Preserve the raw CloudKit second count for CKKS authenticated data.
        # The Safari display converter separately applies the Apple epoch.
        return datetime.datetime.fromtimestamp(struct.unpack(b'<d', data)[0], UTC)
    if kind == 5:
        return text(sub(sub(sub(field, 9), 2), 1), 1)
    raise ValueError('Unsupported CKKS record field type %s' % kind)


def record_values(record):
    return {name: value(field) for name, field in fields(record).items()}


def unarchive(data):
    archive = plistlib.loads(data)
    objects = archive.get('$objects')
    if not isinstance(objects, list) or len(objects) > 65536:
        raise ValueError('Invalid key archive')
    active = set()
    def expand(item, depth=0):
        if depth > 64:
            raise ValueError('Key archive nesting limit')
        if isinstance(item, plistlib.UID):
            index = item.data
            if index >= len(objects) or index in active:
                raise ValueError('Cyclic or invalid key archive reference')
            active.add(index)
            result = expand(objects[index], depth+1)
            active.remove(index)
            return result
        if isinstance(item, list):
            return [expand(i, depth+1) for i in item]
        if isinstance(item, dict):
            values = {k: expand(v, depth+1) for k,v in item.items() if k != '$class'}
            if set(values) == {'NS.data'}:
                if not isinstance(values['NS.data'], binary_type):
                    raise ValueError('Invalid archived data')
                return values['NS.data']
            if 'NS.keys' in values and 'NS.objects' in values:
                keys, vals = values['NS.keys'], values['NS.objects']
                if len(keys) != len(vals) or any(not isinstance(k,text_type) for k in keys) or len(set(keys)) != len(keys):
                    raise ValueError('Invalid archived dictionary')
                return dict(zip(keys, vals))
            return values
        if isinstance(item,text_type) and item == '$null':
            return None
        if isinstance(item, (binary_type,text_type,float,bool,type(None))+integer_types):
            return item
        raise ValueError('Unsupported archived value')
    top = archive.get('$top', {})
    root = top.get('root', top.get('NSKeyedArchiveRootObjectKey'))
    if root is None:
        expected={'SFIESAuthenticationCode','SFCiphertext','SFEphemeralSenderPublicKeyExternaRepresentation'}
        if set(top)!=expected:
            raise ValueError('Missing archived key root')
        root=top
    return expand(root)


def decode_share(record, identity, peers):
    data = record_values(record)
    if data.get('receiver') != identity['peer']:
        return None
    sender = data.get('sender')
    if sender not in peers:
        raise ValueError('Unknown key-share signer')
    info = peer_info(peers[sender])
    key = load_public(one(info, 2))
    wrapped = b64decode(data['wrappedkey'])
    signed = (struct.pack(b'<q',data['version']) + data['receiver'].encode('utf-8') + sender.encode('utf-8') + wrapped +
              struct.pack(b'<qqq',data['curve'],data['epoch'],data['poisoned']))
    key.verify(b64decode(data['signature']), signed, 'sha256')
    archive = unarchive(wrapped)
    ephemeral = archive['SFEphemeralSenderPublicKeyExternaRepresentation']
    private = load_private(identity['encryption'])
    public = point_key(384,ephemeral)
    secret = private.exchange(public)
    material = x963(secret, ephemeral, 48)
    ciphertext = archive['SFCiphertext']
    if len(ciphertext) < 113:
        raise ValueError('Truncated key-share ciphertext')
    plain = gcm_decrypt(material[:32], material[32:], ciphertext[:-113], archive['SFIESAuthenticationCode'])
    decoded = parse(plain)
    key_id, zone, key_bytes = text(decoded,1),text(decoded,2),one(decoded,4)
    if not key_id or not zone or not isinstance(key_bytes,binary_type) or len(key_bytes)!=64:
        raise ValueError('Invalid recovered top-level key')
    return key_id, zone, key_bytes


def decrypt_item(record, keys):
    data = record_values(record)
    parent = data['parentkeyref']
    if parent not in keys:
        return None
    record_key = siv_decrypt(keys[parent],b64decode(data['wrappedkey']))
    if len(record_key)!=64 or data['encver'] not in (1,2):
        raise ValueError('Unsupported CKKS item encryption')
    aad = {'UUID':record_id(record).encode('utf-8'),'encver':struct.pack(b'<q',data['encver']),
           'gen':struct.pack(b'<q',data['gen']),'wrappedkey':parent.encode('utf-8')}
    if data['encver']==2:
        for key in ('pcsservice','pcspublicidentity','pcspublickey'):
            if key in data:
                aad[key]=struct.pack(b'<q',data[key]) if isinstance(data[key],integer_types) else data[key]
        excluded={'gen','pcspublickey','UUID','data','pcsservice','pcspublicidentity','parentkeyref','uploadver','wrappedkey','encver'}
        for name,item in data.items():
            if name in excluded or name.startswith('server_'):
                continue
            if isinstance(item,text_type): aad[name]=item.encode('utf-8')
            elif isinstance(item,binary_type): aad[name]=item
            elif isinstance(item,integer_types): aad[name]=struct.pack(b'<q',item)
            elif isinstance(item,float): aad[name]=struct.pack(b'<Q',int(item))
            elif isinstance(item,datetime.datetime): aad[name]=item.strftime('%Y-%m-%dT%H:%M:%SZ').encode('utf-8')
    encrypted=data['data']
    if len(encrypted)<32:raise ValueError('Truncated CKKS item')
    plain=siv_decrypt(record_key,encrypted[16:],[encrypted[:16]]+[aad[k] for k in sorted(aad)])
    unpadded=plain.rstrip(b'\0')
    if not unpadded.endswith(b'\x80'):raise ValueError('Invalid CKKS item padding')
    item=plistlib.loads(unpadded[:-1])
    if not isinstance(item,dict):raise ValueError('Invalid CKKS item payload')
    return item


def obtain_pcs_items():
    identity=plistlib.loads(private_read('recovered-identity.plist'))
    client=CloudKit('com.apple.security.keychain','com.apple.security.cuttlefish')
    peers,_=trust_metadata(client)
    raw=client.function('fetchRecoverableTLKShares',pb((1,identity['peer'])))
    private_write('recoverable-shares.pb',raw)
    keys={}
    for raw_share in parse(raw).get(1,[]):
        share=parse(raw_share)
        zone=text(share,1)
        if zone not in ('ProtectedCloudStorage','Manatee'):
            continue
        record=sub(sub(share,3),2)
        decoded=decode_share(record,identity,peers)
        if not decoded:continue
        key_id,actual_zone,key=decoded
        if actual_zone!=zone:raise ValueError('Key-share zone mismatch')
        keys[key_id]=key
        for child_tag in (2,3):
            child=sub(sub(sub(share,2),child_tag),2)
            if not child:continue
            values=record_values(child)
            unwrapped=siv_decrypt(key,b64decode(values['wrappedkey']))
            if len(unwrapped)!=64:raise ValueError('Invalid CKKS class key')
            keys[record_id(child)]=unwrapped
    log('Recovered cloud-storage wrapping keys:',len(keys),flush=True)
    if not keys:raise RuntimeError('No recoverable cloud-storage keys')
    private_write('pcs-wrapping-keys.plist',plistlib.dumps(keys,fmt=plistlib.FMT_BINARY))
    storage=CloudKit('com.apple.security.keychain','com.apple.securityd')
    storage.initialize()
    needed=[]
    for name in ('ProtectedCloudStorage','Manatee'):
        identifier=pb((1,pb((1,name),(2,6))),(2,pb((1,storage.user),(2,7))))
        raw_zone=pb((1,identifier))
        records=storage.records(identifier)
        private_write('keychain-'+name+'.plist',plistlib.dumps({'zone':raw_zone,'records':records},fmt=plistlib.FMT_BINARY))
        needed.extend(parse(record) for record in records)
    # Obtain older generations of wrapping keys from authenticated shares and
    # recursively unwrap class keys, without decrypting unrelated item contents.
    for record in needed:
        if text(sub(record,3),1)=='tlkshare':
            decoded=decode_share(record,identity,peers)
            if decoded:keys[decoded[0]]=decoded[2]
    for _ in range(len(needed)+1):
        changed=False
        for record in needed:
            if text(sub(record,3),1)!='synckey' or record_id(record) in keys:continue
            values=record_values(record);parent=values.get('parentkeyref')
            if parent in keys:
                decoded=siv_decrypt(keys[parent],b64decode(values['wrappedkey']))
                if len(decoded)!=64:raise ValueError('Invalid derived CKKS key')
                keys[record_id(record)]=decoded;changed=True
        if not changed:break
    private_write('pcs-wrapping-keys.plist',plistlib.dumps(keys,fmt=plistlib.FMT_BINARY))
    # Return only PCS item records; service-key selection precedes decryption.
    return [record for record in needed if text(sub(record,3),1)=='item'],keys


if __name__=='__main__':
    records,keys=obtain_pcs_items()
    log('Encrypted cloud-storage item candidates:',len(records),flush=True)
