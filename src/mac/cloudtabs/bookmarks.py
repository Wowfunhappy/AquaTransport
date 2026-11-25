"""Native Safari bookmark/Reading List CloudKit bridge."""
from __future__ import absolute_import,division,print_function,unicode_literals
import datetime,hashlib,hmac,json,zlib,collections,uuid
import plists
from compat import binary_type,text_type,integer_types,byte_at,equal,MissingFile
from client import CloudKit,parse,sub,text,one,pb,private_read,private_write,STATE
from pcs import service_key_for_zone,Protection,decrypt_zone,create_record_protection
from keychain import fields,unarchive
from publish import identifier,archive_string
import bookmark_model as model
from events import post
import os

CONTAINER='com.apple.SafariShared.WBSCloudBookmarksStore'
KEY_CACHE='bookmarks-service-keys.plist'
RECORD_TYPES=('BookmarkLeaf','BookmarkList','EncryptionInfo','MigrationState')
ROOT_ROLES={'com.apple.Safari.TopBookmark':'Root','Favorites Bar':'BookmarksBar','Bookmarks Menu':'BookmarksMenu','Reading List':'ReadingList'}
ROLE_ORDER={'Root':0,'BookmarksBar':0,'BookmarksMenu':1,'ReadingList':2}

def client():return CloudKit(CONTAINER,'com.apple.SafariBookmarksSyncAgent')

def bookmark_zone(connection):
    zones=[raw for raw in connection.zones() if text(sub(parse(one(parse(raw),1)),1),1)=='Bookmarks']
    if len(zones)!=1:raise RuntimeError('Expected one Safari bookmarks zone')
    return zones[0]

def prepare_keys():
    connection=client();raw=bookmark_zone(connection);zone=parse(raw)
    service=service_key_for_zone(zone,KEY_CACHE)
    _,private=Protection(one(sub(zone,3),1)).unlock(service)
    if not private:raise RuntimeError('Safari bookmarks zone has no record-protection keys')

def read_records(connection,raw):
    records=connection.records(one(parse(raw),1))
    return records,decrypt_zone({'zone':raw,'records':records},cache_name=KEY_CACHE,record_types=RECORD_TYPES,field_binding=True)

def position_tree(data):
    if not data:return {}
    inflater=zlib.decompressobj();sentinel=b'AQ-END';decoded=inflater.decompress(data+sentinel,65537)
    if len(decoded)>65536 or inflater.unused_data!=sentinel:raise ValueError('Invalid bookmark order data')
    value=json.loads(decoded)
    if not isinstance(value,dict):raise ValueError('Invalid bookmark order dictionary')
    return value

def position(data,role=None):
    value=position_tree(data)
    if not value and role:return (ROLE_ORDER[role],)
    default=value.get('default')
    rows=default.get('sortValues') if isinstance(default,dict) else None
    if not isinstance(rows,list) or not rows or len(rows)>100:raise ValueError('Invalid bookmark sort values')
    for row in rows:
        if not isinstance(row,dict) or not isinstance(row.get('sortValue'),integer_types+(float,)) or not -1e30<row['sortValue']<1e30:
            raise ValueError('Invalid bookmark sort value')
    return tuple(row['sortValue'] for row in sorted(rows,key=lambda row:(row.get('deviceIdentifier',''),row.get('changeID',0))))

class Remote(object):
    def __init__(self,connection):
        self.connection=connection;self.raw_zone=bookmark_zone(connection);self.zone=parse(self.raw_zone);self.zone_id=one(self.zone,1)
        _,self.parent_keys=Protection(one(sub(self.zone,3),1)).unlock(service_key_for_zone(self.zone,KEY_CACHE))
        raw,decoded=read_records(connection,self.raw_zone)
        self.raw={text(sub(sub(parse(value),2),1),1):parse(value) for value in raw}
        self.decoded={value['id']:value for value in decoded};self.keys={};self.layers={}
        encryption=[r['fields'] for r in decoded if r['type']=='EncryptionInfo']
        if len(encryption)!=1:raise ValueError('Missing bookmark identity-key record')
        self.identity_key=encryption[0].get('Key');self.identity_key_id=encryption[0].get('KeyID')
        if not isinstance(self.identity_key,binary_type) or len(self.identity_key)!=16 or not isinstance(self.identity_key_id,binary_type) or len(self.identity_key_id)!=32:
            raise ValueError('Invalid bookmark identity key')
        self.items={};orders={};excluded=set()
        for name,record in self.decoded.items():
            if record['type'] not in ('BookmarkLeaf','BookmarkList'):continue
            values=record['fields'];role=ROOT_ROLES.get(name)
            if values.get('IsTabGroup'):excluded.add(name)
            title=self.string(name,'Title',values.get('Title',b''))
            url=self.string(name,'URL',values.get('URL',b''))
            if title or url:
                expected=self.identity_hash(title,url)
                if not equal(expected,values.get('IdentityHash',b'')):raise ValueError('Bookmark identity hash mismatch')
            node={'Kind':'folder' if record['type']=='BookmarkList' else 'leaf','Title':role or title,'Parent':values.get('ParentFolder',''),'Index':0}
            if role:node['Role']=role
            if node['Kind']=='leaf':node['URL']=url
            for field in ('DateAdded','DateLastViewed'):
                if field not in values:continue
                value=self.object(name,field,values[field])
                if value is None:continue
                if isinstance(value,dict) and set(value)==set(['NS.time']):node[field]=value['NS.time']
                elif isinstance(value,datetime.datetime):node[field]=(value-datetime.datetime(2001,1,1)).total_seconds()
                else:raise ValueError('Unsupported Reading List date representation')
            if 'PreviewText' in values:
                value=self.object(name,'PreviewText',values['PreviewText'])
                if value is not None:node['PreviewText']=value.decode('utf-8') if isinstance(value,binary_type) else value
            if values.get('HasUserDefinedPreviewText'):node['UserPreview']=True
            self.items[name]=node;orders[name]=position(values.get('Position',b''),role)
        # Mavericks has no Tab Groups. Keep those folders and their descendants
        # in iCloud without importing, editing, or deleting them here.
        while True:
            more={name for name,node in self.items.items() if node['Parent'] in excluded}-excluded
            if not more:break
            excluded.update(more)
        for name in excluded:self.items.pop(name,None)
        for parent in set(node['Parent'] for node in self.items.values()):
            children=sorted((name for name,node in self.items.items() if node['Parent']==parent),key=lambda name:(orders[name],name))
            for index,name in enumerate(children):self.items[name]['Index']=index
        roles=model.validate(self.items)
        model.normalize_root_order(self.items)
        if set(roles)!=set(ROOT_ROLES.values()):raise ValueError('Missing standard bookmark folders')

    def record_keys(self,name):
        if name not in self.keys:
            protection=one(sub(self.raw[name],13),1)
            if not protection:raise ValueError('Missing per-bookmark protection')
            self.keys[name]=Protection(protection).unlock(self.parent_keys)[0]
        return self.keys[name]

    def object(self,name,field,value):
        layers=1
        # Some original system folders retain an authenticated CKEncryptedData
        # envelope inside their encrypted field. Preserve that representation.
        for unused in range(2):
            if not isinstance(value,binary_type) or len(value)<30 or byte_at(value,0)!=3:break
            decoded=None
            for key in self.record_keys(name):
                try:decoded=key.decrypt(value,field.encode('utf-8'));break
                except ValueError:pass
            if decoded is None:break
            value=decoded;layers+=1
        self.layers[(name,field)]=layers
        if isinstance(value,binary_type) and value.startswith(b'bplist00'):value=unarchive(value)
        return value

    def string(self,name,field,value):
        value=self.object(name,field,value)
        if isinstance(value,binary_type):value=value.decode('utf-8')
        if value is None:return ''
        if not isinstance(value,text_type):raise ValueError('Invalid bookmark text representation')
        return value

    def identity_hash(self,title,url=''):
        data=title.encode('utf-8').split(b'\0',1)[0]
        if url:data+=b'/'+url.encode('utf-8').split(b'\0',1)[0]
        return hmac.new(self.identity_key,data,hashlib.sha256).digest()+self.identity_key_id[-4:]

def archive_date(seconds):
    return plists.dumps({'$archiver':'NSKeyedArchiver','$version':100000,'$objects':['$null',{'NS.time':float(seconds),'$class':plists.UID(2)},{'$classname':'NSDate','$classes':['NSDate','NSObject']}],'$top':{'root':plists.UID(1)}},fmt=plists.FMT_BINARY)

def value_field(name,kind,data):
    if kind==1:value=pb((1,1),(2,data))
    elif kind==3:value=pb((1,3),(7,data))
    elif kind==7:value=pb((1,7),(4,int(data)))
    elif kind==5:value=pb((1,5),(9,data))
    else:raise ValueError('Unsupported bookmark field encoding')
    return pb((1,pb((1,name))),(2,value))

def encrypted_field(name,data,key,layers=1):
    for unused in range(layers):data=key.encrypt(data,name.encode('utf-8'))
    return pb((1,pb((1,name))),(2,pb((1,20),(2,data),(13,1))))

def save_item(remote,name,node,device,guard,force_position=False):
    if name in ROOT_ROLES or node.get('Role'):return False
    previous=remote.items.get(name);raw=remote.raw.get(name);existing=raw is not None
    if existing and text(sub(raw,3),1) not in ('BookmarkLeaf','BookmarkList'):raise ValueError('Bookmark record collision')
    changes=[];remove=[];old_fields=remote.decoded[name]['fields'] if existing else {}
    if existing:
        key=remote.record_keys(name)[0];protection=one(raw,13);protection_tag=text(parse(protection),2)
        key_id=one(raw,24,key.identifier()[:4])
    else:
        protection_data,key=create_record_protection(remote.parent_keys[0])
        protection=pb((1,protection_data),(2,hashlib.sha1(protection_data).hexdigest().upper()))
        protection_tag=None;key_id=key.identifier()[:4]
    def encrypted(field,data):changes.append(encrypted_field(field,data,key,remote.layers.get((name,field),1)))
    def generation(group):
        number=old_fields.get(group+'_generation',0)
        if not isinstance(number,integer_types) or not 0<=number<(1<<63)-1:raise ValueError('Invalid bookmark generation')
        changes.extend([value_field(group+'_generation',7,number+1),value_field(group+'_deviceIdentifier',3,device)])
    if not previous or node['Title']!=previous['Title'] or node.get('URL')!=previous.get('URL'):
        encrypted('Title',node['Title'].encode('utf-8'))
        if node['Kind']=='leaf':encrypted('URL',node['URL'].encode('utf-8'))
        changes.append(value_field('IdentityHash',1,remote.identity_hash(node['Title'],node.get('URL',''))))
        generation('TitleURLAndIdentityHash' if node['Kind']=='leaf' else 'TitleAndIdentityHash')
    if not previous or force_position or (node['Parent'],node['Index'])!=(previous['Parent'],previous['Index']):
        # Native bookmark parents are weak references; delete children explicitly.
        changes.append(value_field('ParentFolder',5,pb((1,2),(2,identifier(node['Parent'],remote.zone_id)))))
        generation('ParentAndPosition')
        order=position_tree(old_fields.get('Position',b''))
        order['default']={'sortValues':[{'sortValue':node['Index']+1,'changeID':old_fields.get('ParentAndPosition_generation',0)+1,'deviceIdentifier':device}]}
        changes.append(value_field('Position',1,zlib.compress(json.dumps(order,sort_keys=True,separators=(',',':')).encode('utf-8'))))
    for field in ('DateAdded','DateLastViewed','PreviewText'):
        if (previous or {}).get(field)==node.get(field):continue
        if field in node:encrypted(field,archive_string(node[field]) if field=='PreviewText' else archive_date(node[field]))
        else:remove.append(field)
        generation('PreviewTextAndHasUserDefinedPreviewText' if field=='PreviewText' else field)
        if field=='PreviewText':changes.append(value_field('HasUserDefinedPreviewText',7,0))
    if not changes and not remove:return False
    record=pb((1,text(raw,1) if raw else None),(2,identifier(name,remote.zone_id)),(3,pb((1,'BookmarkList' if node['Kind']=='folder' else 'BookmarkLeaf'))),(13,protection),(24,key_id),*((7,value) for value in changes))
    payload=pb((1,record),(2,1),(6,3 if existing else 2),(7,text(sub(remote.zone,3),2)),(8,protection_tag),*((3,value) for value in remove))
    if not guard():raise RuntimeError('Safari account changed during bookmark upload')
    remote.connection.perform(210,payload,'/ckdatabase/api/client/record/save','CKDModifyRecordsOperation')
    return True

def upload(remote,merged,device,guard):
    model.validate(merged);written=deleted=0
    affected=set()
    for name in set(remote.items)|set(merged):
        old=remote.items.get(name);new=merged.get(name)
        if (old or new).get('Role'):continue
        if not old or not new or (old['Parent'],old['Index'])!=(new['Parent'],new['Index']):
            if old:affected.add(old['Parent'])
            if new:affected.add(new['Parent'])
    for name in sorted(merged,key=lambda key:(model.depth(merged,key),key)):
        written+=int(save_item(remote,name,merged[name],device,guard,merged[name]['Parent'] in affected))
    removals=set(remote.items)-set(merged)
    if removals:
        if not guard():raise RuntimeError('Safari account changed before bookmark deletion')
        fresh={text(sub(sub(parse(raw),2),1),1):parse(raw) for raw in remote.connection.records(remote.zone_id)}
        for name in removals:
            if name not in fresh:continue
            if not text(remote.raw[name],1) or text(fresh[name],1)!=text(remote.raw[name],1):raise RuntimeError('Bookmark changed concurrently before deletion')
            if remote.items[name]['Kind']=='folder':
                for child,record in fresh.items():
                    reference=fields(record).get('ParentFolder')
                    if reference and text(sub(sub(sub(reference,9),2),1),1)==name and child not in removals:
                        raise RuntimeError('Bookmark folder gained a child before deletion')
    for name in sorted(removals,key=lambda key:(-model.depth(remote.items,key),key)):
        if name in ROOT_ROLES or remote.items[name].get('Role'):raise ValueError('Refusing to remove a standard bookmark folder')
        if not guard():raise RuntimeError('Safari account changed during bookmark deletion')
        if name in fresh:
            remote.connection.perform(214,pb((1,identifier(name,remote.zone_id))),'/ckdatabase/api/client/record/delete','CKDModifyRecordsOperation');deleted+=1
    return written,deleted

def read_state(name,default=None):
    try:return plists.loads(private_read(name))
    except MissingFile:return default

def remove_state(name):
    try:(STATE/name).unlink()
    except MissingFile:pass

def synchronize(account,guard):
    # New features are authorized through the explicit Safari enable flow.
    # Merely finding an existing signed-in account never starts key recovery.
    try:private_read(KEY_CACHE)
    except MissingFile:return None
    snapshot=read_state('local-bookmarks.plist')
    if snapshot is None:return {'state':'waiting-for-native-bookmarks'}
    local=model.from_snapshot(snapshot,account)
    state=read_state('bookmarks-state.plist',{})
    if state and state.get('Version')!=1:raise ValueError('Unsupported bookmark sync state version')
    if state.get('Account')!=account:state={'Version':1,'Account':account,'Map':{},'Base':{}}
    pending=read_state('bookmarks-pending.plist');ack=read_state('bookmarks-ack.plist')
    if pending and pending.get('Account')==account and not state.get('Base') and snapshot['Token']!=pending.get('Expected'):
        # The first merge has not reached the native model yet. Retain its
        # observed local version so edits made while it was in flight survive.
        state['Base']=pending.get('Before',{})
    if pending and ack and pending.get('Account')==account and ack.get('Account')==account and pending.get('Transaction')==ack.get('Transaction'):
        if ack.get('Applied') is True:
            state['Base']=pending['Model'];state['Map']=pending['Map']
        elif ack.get('Reason')=='native-error':state['BlockedToken']=snapshot['Token']
        for name in ('bookmarks-pending.plist','bookmarks-incoming.plist','bookmarks-ack.plist'):remove_state(name)
        private_write('bookmarks-state.plist',plists.dumps(state,fmt=plists.FMT_BINARY))
    if state.get('BlockedToken')==snapshot['Token']:return {'state':'native-change-rejected'}
    state.pop('BlockedToken',None)
    if not guard():return None
    connection=client()
    if connection.account['dsid']!=account:raise ValueError('Bookmark credential account mismatch')
    remote=Remote(connection)
    canonical,mapping=model.map_native(local,remote.items,state,snapshot['DeviceID'])
    merged=model.merge(state.get('Base',{}),canonical,remote.items)
    native=model.to_native(merged,mapping,local,snapshot['DeviceID'])
    # Validate the complete native plan before any cloud mutation.
    native_model=model.from_snapshot({'Version':1,'Account':account,'DeviceID':snapshot['DeviceID'],'Token':snapshot['Token'],'Items':native},account)
    written,deleted=upload(remote,merged,snapshot['DeviceID'],guard)
    if not guard():return None
    state['Map']=mapping
    if native_model==local:
        state['Base']=merged
        for name in ('bookmarks-pending.plist','bookmarks-incoming.plist','bookmarks-ack.plist'):remove_state(name)
    else:
        transaction=text_type(uuid.uuid4()).upper()
        plan={'Version':1,'Account':account,'Transaction':transaction,'Expected':snapshot['Token'],'Items':native}
        pending={'Account':account,'Transaction':transaction,'Expected':snapshot['Token'],'Before':canonical,'Model':merged,'Map':mapping}
        private_write('bookmarks-pending.plist',plists.dumps(pending,fmt=plists.FMT_BINARY))
        private_write('bookmarks-incoming.plist',plists.dumps(plan,fmt=plists.FMT_BINARY))
        post('org.aquatransport.bookmarks.updated.%d'%os.getuid())
    private_write('bookmarks-state.plist',plists.dumps(state,fmt=plists.FMT_BINARY))
    reading=model.validate(merged)['ReadingList']
    reading_count=sum(1 for node in merged.values() if node['Kind']=='leaf' and node['Parent']==reading)
    total=sum(1 for node in merged.values() if node['Kind']=='leaf')
    return {'state':'ok' if native_model==local else 'applying-native-changes','bookmarks':total-reading_count,'readingList':reading_count,'uploaded':written,'deleted':deleted}
