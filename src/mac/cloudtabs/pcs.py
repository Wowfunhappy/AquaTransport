"""PCS key envelopes and authenticated CloudKit field decryption."""
from __future__ import absolute_import, division, print_function, unicode_literals
from compat import binary_type, byte_at, MissingFile, UTC
import datetime
import base64
import hashlib
import hmac
import os
import plists as plistlib
import struct
from native import derive_key
from compat import from_bytes, to_bytes, equal
from crypto import pbkdf2
from client import parse, one, sub, text, private_read, private_write
from crypto import kdf, gcm_decrypt, gcm_encrypt, rfc6637_unwrap, rfc6637_wrap, compact_private, public_bytes, N256
from der import decode, encode
from keychain import fields, record_values, decrypt_item


class KeyUnavailable(RuntimeError):
    pass


def key_x(key):
    return key.point[1:33]


def signature(key, node, data):
    values=node.sequence()
    if len(values)!=3 or values[1].integer()!=1:
        raise ValueError('Unsupported PCS signature')
    identifier=values[0].octets()
    public=key
    if identifier and not equal(identifier,public.point[1:33]):
        raise ValueError('PCS signing-key identifier mismatch')
    public.verify(values[2].octets(),data,'sha256')


class PCSKey(object):
    def __init__(self, key):
        if len(key)!=16:raise ValueError('Invalid PCS master-key size')
        self.key=key

    def identifier(self):
        label=kdf(self.key,b'master key id labell')
        return hmac.new(label,b'M key input data 2 u',hashlib.sha256).digest()

    def decrypt(self, encrypted, aad=b''):
        if len(encrypted)<30 or byte_at(encrypted,0)!=3:
            raise ValueError('Unsupported PCS ciphertext')
        length=byte_at(encrypted,3)
        if length>30:raise ValueError('Invalid PCS key identifier length')
        head=4+length
        if len(encrypted)<head+24:raise ValueError('Truncated PCS ciphertext')
        identifier=encrypted[1:3]+encrypted[4:head]
        if not equal(identifier,self.identifier()[:len(identifier)]):
            raise ValueError('PCS ciphertext key mismatch')
        key=kdf(self.key,b'encryption key key m')
        return gcm_decrypt(key,encrypted[head:head+12],encrypted[head+24:],encrypted[head+12:head+24],encrypted[:head]+aad)

    def signing_key(self):
        raw=pbkdf2('sha256',self.key,b'full master key',10,128)
        scalar=from_bytes(raw,'little') & ((1<<256)-1)
        if scalar>N256:scalar-=N256
        if not 0<scalar<N256:raise ValueError('Invalid PCS signing scalar')
        return derive_key(256,to_bytes(scalar,32))

    def encrypt(self,plaintext,aad=b''):
        identifier=self.identifier()
        header=b'\x03'+identifier[:2]+b'\x02'+identifier[2:4]
        iv=os.urandom(12)
        ciphertext,tag=gcm_encrypt(kdf(self.key,b'encryption key key m'),iv,plaintext,header+aad)
        return header+iv+tag+ciphertext


def zone_record_keys(zone,cache_name='safari-service-keys.plist'):
    service=service_key_for_zone(zone,cache_name)
    _,private=Protection(one(sub(zone,3),1)).unlock(service)
    if 6 not in zone:raise KeyUnavailable('Safari zone has no default record protection')
    keys,_=Protection(one(sub(zone,6),1)).unlock(private)
    if not keys:raise KeyUnavailable('Safari zone has no default record keys')
    return keys


def create_record_protection(parent):
    # Standard PCS version-5 per-record envelope, as used by native bookmarks.
    def integer(value):
        data=to_bytes(value,max(1,(value.bit_length()+7)//8))
        if byte_at(data,0)&128:data=b'\0'+data
        return encode(2,data)
    sequence=lambda *parts:encode(0x30,b''.join(parts))
    octets=lambda data:encode(4,data)
    def signed(key,data,self_signature=False):
        return sequence(octets(b'' if self_signature else key_x(key)),integer(1),octets(key.sign(data)))
    master=PCSKey(os.urandom(16));signing=master.signing_key()
    metadata=sequence(encode(0xa1,sequence(integer(0),octets(b''))))
    encrypted=master.encrypt(metadata)
    recipient=sequence(sequence(integer(3),octets(key_x(parent))),octets(rfc6637_wrap(parent,master.key)))
    keyset=sequence(integer(0),encode(0x31,recipient))
    public=sequence(integer(1),octets(signing.point))
    authenticated=keyset+encrypted+struct.pack(b'>IIII',3,1,0,1)+signing.point
    signature_data=sequence(integer(1),integer(3),public,signed(signing,authenticated,True))
    mac=hmac.new(kdf(master.key,b'hmackey-of-masterkey'),keyset+encrypted+signature_data,hashlib.sha256).digest()
    protection=encode(0x61,sequence(keyset,encode(0xa0,octets(encrypted)),encode(0xa1,sequence(integer(5),octets(signature_data))),octets(mac),encode(0xa2,octets(master.identifier()[:4])),encode(0xa3,signed(parent,authenticated))))
    return protection,master


def private_key(node):
    if node.tag==0x30:
        values=node.sequence()
        if not values:raise ValueError('Empty PCS private key')
        return compact_private(values[0].octets())
    if node.tag==0x65:
        if len(node.children)!=1:raise ValueError('Invalid PCS private-key envelope')
        data=node.children[0].octets()
        value=parse(data)
        return compact_private(one(sub(value,1),1))
    raise ValueError('Unsupported PCS private-key encoding')


class Protection(object):
    def __init__(self, data):
        self.root=decode(data)
        values=self.root.explicit(0x61).sequence()
        if not 5<=len(values)<=7:raise ValueError('Invalid PCS protection structure')
        self.keyset=values[0]
        self.meta=values[1].explicit(0xa0).octets()
        signature_data=values[2].explicit(0xa1).sequence()
        if len(signature_data)!=2:raise ValueError('Invalid PCS signature data')
        self.version=signature_data[0].integer()
        if self.version not in (4,5):raise ValueError('Unsupported PCS protection version')
        self.signed=decode(signature_data[1].octets())
        self.mac=values[3].octets()
        self.truncated=values[4].explicit(0xa2).octets()
        self.optional={v.tag:v for v in values[5:]}
        if len(self.optional)!=len(values)-5 or any(k not in (0xa3,0xa4) for k in self.optional):
            raise ValueError('Invalid optional PCS protection fields')
        keyset=self.keyset.sequence()
        if len(keyset) not in (2,3) or keyset[0].integer()!=0:
            raise ValueError('Unsupported PCS key set')
        self.entries=[]
        for share in keyset[1].sequence():
            entry=share.sequence()
            if len(entry) not in (2,3):raise ValueError('Invalid PCS wrapped key')
            ref=entry[0].sequence()
            if len(ref)!=2 or ref[0].integer()!=3 or len(ref[1].octets())!=32:
                raise ValueError('Invalid PCS recipient key')
            self.entries.append((ref[1].octets(),entry[1].octets(),entry[2].integer() if len(entry)==3 else 0))

    def required_keys(self):
        return {entry[0] for entry in self.entries}

    def unlock(self, private_keys):
        chosen=None
        for identifier,wrapped,flags in self.entries:
            for private in private_keys:
                if equal(identifier,key_x(private)):
                    chosen=(private,wrapped,flags);break
            if chosen:break
        if chosen is None:raise ValueError('No matching PCS recipient key')
        private,wrapped,flags=chosen
        if flags&~1:raise ValueError('Unsupported PCS recipient flags')
        readonly=bool(flags&1)
        master=PCSKey(rfc6637_unwrap(private,wrapped))
        signed=self.signed.sequence()
        if len(signed)<4:raise ValueError('Invalid PCS signed metadata')
        roll,kind=signed[0].integer(),signed[1].integer()
        public=signed[2].sequence()
        if len(public)!=2:raise ValueError('Invalid PCS signing-key reference')
        optional={v.tag:v for v in signed[4:]}
        if len(optional)!=len(signed)-4 or any(k not in (0xa0,0xa1,0xa2,0xa3) for k in optional):
            raise ValueError('Invalid PCS signature options')
        count=optional[0xa0].explicit(0xa0).integer() if 0xa0 in optional else 0
        data=(self.keyset.raw+self.meta+struct.pack(b'>IIII',kind,roll,count,public[0].integer())+public[1].octets())
        if 0xa3 in optional:data+=optional[0xa3].explicit(0xa3).raw
        if 0xa2 in optional:data+=optional[0xa2].explicit(0xa2).raw
        if 0xa3 in self.optional:
            signature(private,self.optional[0xa3].explicit(0xa3),data)
        if not readonly:
            signing=master.signing_key()
            if public[0].integer()!=1 or not equal(public[1].octets(),public_bytes(signing)):
                raise ValueError('PCS master signing-key mismatch')
            signature(signing,signed[3],data)
        if self.version!=5 and not readonly:
            master=PCSKey(kdf(master.key,b'MsaeEooevaX fooo 012'))
        if len(self.truncated) not in (2,4) or not equal(master.identifier()[:len(self.truncated)],self.truncated):
            raise ValueError('PCS protection key identifier mismatch')
        mac_data=self.keyset.raw+self.meta+self.signed.raw
        expected=hmac.new(kdf(master.key,b'hmackey-of-masterkey'),mac_data,hashlib.sha256).digest()
        if not equal(expected,self.mac):raise ValueError('PCS protection authentication failed')
        metadata=decode(master.decrypt(self.meta)).sequence()
        tagged={v.tag:v for v in metadata}
        if len(tagged)!=len(metadata) or any(k not in (0xa0,0xa1,0xa2) for k in tagged):
            raise ValueError('Invalid decrypted PCS metadata')
        keys=[master];private=[]
        if 0xa0 in tagged:
            for key in tagged[0xa0].explicit(0xa0).sequence():keys.append(PCSKey(key.octets()))
        if 0xa2 in tagged:
            for identity in tagged[0xa2].explicit(0xa2).sequence():
                identity_fields=identity.sequence()
                if len(identity_fields)!=2:raise ValueError('Invalid PCS identity metadata')
                keyset=decode(identity_fields[1].octets())
                inner=keyset.explicit(0x62).sequence()
                if len(inner)!=4 or len(inner[-1].octets())!=32:raise ValueError('Invalid PCS private-key set')
                unsigned=encode(0x62,encode(0x30,b''.join(v.raw for v in inner[:-1])))
                if not equal(hashlib.sha256(unsigned).digest(),inner[-1].octets()):
                    raise ValueError('PCS private-key set checksum mismatch')
                for item in inner[1].sequence():private.append(private_key(item))
        return keys,private


def service_key_for_zone(zone,cache_name='safari-service-keys.plist'):
    root=Protection(one(sub(zone,3),1))
    wanted=root.required_keys()
    try:
        entries=plistlib.loads(private_read(cache_name))
        if not isinstance(entries,list) or len(entries)>32 or any(not isinstance(data,binary_type) or len(data)!=64 for data in entries):raise KeyUnavailable('Invalid local Safari service keys')
        cached=[compact_private(data) for data in entries]
        if any(key_x(key) in wanted for key in cached):return cached
    except MissingFile:
        pass
    try:keys=plistlib.loads(private_read('pcs-wrapping-keys.plist'))
    except MissingFile:raise KeyUnavailable('Safari keys need to be unlocked')
    matches=[]
    for zone_name in ('ProtectedCloudStorage','Manatee'):
        cache=plistlib.loads(private_read('keychain-'+zone_name+'.plist'))
        for raw in cache['records']:
            record=parse(raw)
            if text(sub(record,3),1)!='item':continue
            public=fields(record).get('pcspublickey')
            if public is None or one(public,2) not in wanted:continue
            item=decrypt_item(record,keys)
            if item is None:raise ValueError('Missing Safari service-key wrapping key')
            data=item.get('v_Data')
            if not isinstance(data,binary_type):raise ValueError('Missing Safari PCS key data')
            key=private_key(decode(data))
            if key_x(key) not in wanted:raise ValueError('Safari PCS item public-key mismatch')
            matches.append(key)
    if not matches:raise ValueError('Safari service key not found in cloud storage')
    # Store only the service keys needed for Safari, not decrypted keychain items.
    saved=[key_x(key)+key.scalar() for key in matches]
    private_write(cache_name,plistlib.dumps(saved,fmt=plistlib.FMT_BINARY))
    return matches


def decrypt_zone(cache, persist=False,cache_name='safari-service-keys.plist',record_types=('CloudTab','CloudTabDevice'),field_binding=False):
    zone=parse(cache['zone'])
    service=service_key_for_zone(zone,cache_name)
    zone_keys,private=Protection(one(sub(zone,3),1)).unlock(service)
    default=[]
    if 6 in zone:
        default,_=Protection(one(sub(zone,6),1)).unlock(private)
    result=[]
    for raw in cache['records']:
        record=parse(raw)
        kind=text(sub(record,3),1)
        if kind not in record_types:continue
        identifier=sub(record,2)
        record_name=text(sub(identifier,1),1)
        zone_name=text(sub(sub(identifier,2),1),1)
        if not record_name or not zone_name:raise ValueError('Invalid encrypted tab record identifier')
        keys=default
        if 13 in record:keys,_=Protection(one(sub(record,13),1)).unlock(private)
        decoded={}
        for name,value in fields(record).items():
            if one(value,13,0):
                if not keys:raise ValueError('No record decryption keys')
                encrypted=one(value,2)
                if not isinstance(encrypted,binary_type) or len(encrypted)<6:raise ValueError('Invalid encrypted tab field')
                keyid=encrypted[1:3]+encrypted[4:4+byte_at(encrypted,3)]
                selected=next((key for key in keys if equal(key.identifier()[:len(keyid)],keyid)),None)
                if selected is None:raise ValueError('Tab field uses an unknown key')
                binding=name if field_binding else zone_name+'-'+record_name+'-'+name
                plain=selected.decrypt(encrypted,binding.encode('utf-8'))
                typ=one(value,1)
                if typ==3:decoded[name]=text(parse(plain),6)
                elif typ==2:decoded[name]=datetime.datetime(2001,1,1)+datetime.timedelta(seconds=struct.unpack(b'<d',one(sub(parse(plain),5),1))[0])
                elif typ==7:decoded[name]=one(parse(plain),3)
                elif typ==20:decoded[name]=plain
                else:raise ValueError('Unsupported encrypted tab field type')
            else:
                from keychain import value as field_value
                decoded[name]=field_value(value)
                if isinstance(decoded[name],datetime.datetime):decoded[name]=decoded[name].astimezone(UTC).replace(tzinfo=None)+datetime.timedelta(seconds=978307200)
        result.append({'id':record_name,'type':kind,'fields':decoded})
    if persist:private_write('decrypted-tabs.plist',plistlib.dumps(result,fmt=plistlib.FMT_BINARY))
    return result

