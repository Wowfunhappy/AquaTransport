"""Event-driven, account-scoped Safari History CloudKit bridge."""
from __future__ import absolute_import,division,print_function,unicode_literals
import datetime,hashlib,json,os,uuid,zlib
import plists
from compat import binary_type,text_type,integer_types,MissingFile,urlsplit
from client import CloudKit,parse,sub,text,one,pb,private_read,private_write,STATE
from pcs import service_key_for_zone,Protection,decrypt_zone,create_record_protection
from publish import identifier
from events import post

CONTAINER='com.apple.SafariShared.History'
BUNDLE='com.apple.Safari'
KEY_CACHE='history-service-keys.plist'
WINDOW=30*24*60*60
DISTANT_PAST=-63114076800.0
TOMBSTONE_ATTRIBUTES=66049
TIME_TOLERANCE=0.11

def client():return CloudKit(CONTAINER,BUNDLE)

def history_zone(connection):
    zones=[raw for raw in connection.zones() if text(sub(parse(one(parse(raw),1)),1),1)=='History']
    if len(zones)!=1:raise RuntimeError('Expected one Safari History zone')
    return zones[0]

def prepare_keys():
    connection=client();zone=parse(history_zone(connection))
    service=service_key_for_zone(zone,KEY_CACHE)
    _,private=Protection(one(sub(zone,3),1)).unlock(service)
    if not private and 6 not in zone:raise RuntimeError('Safari History zone has no record-protection keys')

def validate_visit(value):
    if not isinstance(value,dict) or not isinstance(value.get('URL'),text_type) or not value['URL'] or len(value['URL'])>131072:return None
    if urlsplit(value['URL']).scheme.lower() not in ('http','https','ftp'):return None
    title=value.get('Title','')
    if not isinstance(title,text_type) or len(title)>65536:return None
    when=value.get('VisitTime')
    if not isinstance(when,integer_types+(float,)) or not -1e12<when<1e12:return None
    result={'URL':value['URL'],'Title':title,'Time':float(when),'HTTPNonGet':bool(value.get('HTTPNonGet')),'LoadSuccessful':bool(value.get('LoadSuccessful',True))}
    return result

def validate_tombstone(value):
    if not isinstance(value,dict):return None
    salt=value.get('URLSalt');digest=value.get('URLHash');start=value.get('StartTime');end=value.get('EndTime')
    if not isinstance(salt,binary_type) or len(salt)!=64 or not isinstance(digest,binary_type) or len(digest)!=64:return None
    if not isinstance(start,integer_types+(float,)) or not isinstance(end,integer_types+(float,)) or not -1e12<start<=end<1e12:return None
    return {'Salt':salt,'Hash':digest,'Start':float(start),'End':float(end)}

class Remote(object):
    def __init__(self,connection):
        self.connection=connection;self.raw_zone=history_zone(connection);self.zone=parse(self.raw_zone);self.zone_id=one(self.zone,1)
        service=service_key_for_zone(self.zone,KEY_CACHE);_,self.parent_keys=Protection(one(sub(self.zone,3),1)).unlock(service)
        if not self.parent_keys:raise RuntimeError('Safari History has no per-record protection key')
        raw=connection.records(self.zone_id)
        decoded=decrypt_zone({'zone':self.raw_zone,'records':raw},cache_name=KEY_CACHE,record_types=('Visits','Tombstones'))
        self.visits=[];self.tombstones=[]
        for record in decoded:
            fields=record['fields']
            if fields.get('Version') not in ((1,) if record['type']=='Visits' else (2,)):raise ValueError('Unsupported Safari History record version')
            data=fields.get('EncryptedData')
            if not isinstance(data,binary_type) or len(data)>4*1024*1024:raise ValueError('Invalid Safari History payload')
            inflater=zlib.decompressobj();sentinel=b'AQ-END';plain=inflater.decompress(data+sentinel,8*1024*1024+1)
            if len(plain)>8*1024*1024 or inflater.unused_data!=sentinel:raise ValueError('Invalid Safari History compression')
            payload=plists.loads(plain);values=payload.get(record['type']) if isinstance(payload,dict) and payload.get('ClientVersion')==3 else None
            if not isinstance(values,list) or len(values)>10000:raise ValueError('Invalid Safari History batch')
            target=self.visits if record['type']=='Visits' else self.tombstones;validator=validate_visit if record['type']=='Visits' else validate_tombstone
            for value in values:
                checked=validator(value)
                if checked is None:raise ValueError('Invalid Safari History entry')
                target.append(checked)

    def tombstoned(self,visit):
        encoded=visit['URL'].encode('utf-8')
        for tombstone in self.tombstones:
            if tombstone['Start']<=visit['Time']<=tombstone['End'] and hashlib.sha512(tombstone['Salt']+encoded).digest()==tombstone['Hash']:return True
        return False

    def current(self,cutoff):
        result={}
        for visit in self.visits:
            if visit['Time']<cutoff or self.tombstoned(visit):continue
            old=result.get(visit['URL'])
            if old is None or visit['Time']>old['Time']:result[visit['URL']]=visit
        return result

    def save_batch(self,kind,values,device,guard):
        if kind not in ('Visits','Tombstones') or not values:return
        record_id=text_type(uuid.uuid4()).upper();payload=plists.dumps({'ClientVersion':3,kind:values},fmt=plists.FMT_BINARY)
        compressed=zlib.compress(payload)
        protection,key=create_record_protection(self.parent_keys[0]);tag=hashlib.sha1(protection).hexdigest().upper()
        aad=('History-'+record_id+'-EncryptedData').encode('utf-8');encrypted=key.encrypt(compressed,aad)
        def field(name,value):return pb((1,pb((1,name))),(2,value))
        record=pb((2,identifier(record_id,self.zone_id)),(3,pb((1,kind))),(7,field('UUID',pb((1,3),(7,record_id)))),(7,field('Version',pb((1,7),(4,1 if kind=='Visits' else 2)))),(7,field('EncryptedData',pb((1,20),(2,encrypted),(13,1)))),(13,pb((1,protection),(2,tag))),(24,key.identifier()[:4]))
        request=pb((1,record),(2,1),(6,2),(7,text(sub(self.zone,3),2)))
        if not guard():raise RuntimeError('Safari account changed during History upload')
        self.connection.perform(210,request,'/ckdatabase/api/client/record/save','CKDModifyRecordsOperation')
        return record_id

def snapshot(account):
    try:value=plists.loads(private_read('local-history.plist'))
    except MissingFile:return None
    if not isinstance(value,dict) or value.get('Version')!=1 or value.get('Account')!=account:return None
    if not isinstance(value.get('DeviceID'),text_type) or not value['DeviceID'] or not isinstance(value.get('Token'),text_type) or len(value['Token'])!=64:return None
    entries=value.get('Entries')
    if not isinstance(entries,list) or len(entries)>10000:return None
    result={}
    for entry in entries:
        checked=validate_visit({'URL':entry.get('URL'),'Title':entry.get('Title',''),'VisitTime':entry.get('Time'),'HTTPNonGet':entry.get('HTTPNonGet'),'LoadSuccessful':entry.get('LoadSuccessful',True)}) if isinstance(entry,dict) else None
        if checked is None:return None
        old=result.get(checked['URL'])
        if old is None or checked['Time']>old['Time']:result[checked['URL']]=checked
    return value,result

def read_state(name,default=None):
    try:return plists.loads(private_read(name))
    except MissingFile:return default

def remove_state(name):
    try:(STATE/name).unlink()
    except MissingFile:pass

def secure_tombstone(url,end,device):
    salt=os.urandom(64)
    return {'Attributes':TOMBSTONE_ATTRIBUTES,'StartTime':DISTANT_PAST,'EndTime':float(end),'UDID':device,'URLSalt':salt,'URLHash':hashlib.sha512(salt+url.encode('utf-8')).digest()}

def synchronize(account,guard):
    try:private_read(KEY_CACHE)
    except MissingFile:return None
    captured=snapshot(account)
    if captured is None:return {'state':'waiting-for-native-history'}
    native,local=captured;now=(datetime.datetime.utcnow()-datetime.datetime(2001,1,1)).total_seconds();cutoff=now-WINDOW
    state=read_state('history-state.plist',{})
    if state and (state.get('Version')!=1 or state.get('Account')!=account):state={}
    if not state:state={'Version':1,'Account':account,'Base':{}}
    pending=read_state('history-pending.plist');ack=read_state('history-ack.plist')
    if pending and ack and pending.get('Account')==account and ack.get('Account')==account and pending.get('Transaction')==ack.get('Transaction'):
        ignored=ack.get('Ignored',[])
        if not isinstance(ignored,list) or len(ignored)>10000 or any(not isinstance(url,text_type) or len(url)>131072 for url in ignored):raise ValueError('Invalid native History ignore list')
        known=set(state.get('Ignored',[]));known.update(ignored);state['Ignored']=sorted(known)
        if ack.get('Applied') is True:state['Base']={url:value for url,value in pending['Model'].items() if url not in known}
        elif ack.get('Reason')=='native-error':state['BlockedToken']=native['Token']
        for name in ('history-pending.plist','history-incoming.plist','history-ack.plist'):remove_state(name)
        private_write('history-state.plist',plists.dumps(state,fmt=plists.FMT_BINARY))
    if state.get('BlockedToken')==native['Token']:return {'state':'native-change-rejected'}
    state.pop('BlockedToken',None)
    if not guard():return None
    remote=Remote(client());cloud=remote.current(cutoff);ignored=set(state.get('Ignored',[]));cloud={url:value for url,value in cloud.items() if url not in ignored};base=state.get('Base',{})
    uploads=[]
    for url,visit in local.items():
        if visit['Time']<cutoff:continue
        prior=base.get(url);existing=cloud.get(url)
        if (not prior or visit['Time']>prior.get('Time',-1)+TIME_TOLERANCE) and (not existing or visit['Time']>existing['Time']+TIME_TOLERANCE):
            uploads.append({'URL':visit['URL'],'Title':visit['Title'],'VisitTime':visit['Time'],'HTTPNonGet':visit['HTTPNonGet'],'LoadSuccessful':visit['LoadSuccessful']})
    deleted=[(url,value) for url,value in base.items() if value.get('Time',-1)>=cutoff and url not in local]
    for offset in range(0,len(uploads),50):remote.save_batch('Visits',uploads[offset:offset+50],native['DeviceID'],guard)
    tombstones=[secure_tombstone(url,max(value['Time'],now),native['DeviceID']) for url,value in deleted]
    for offset in range(0,len(tombstones),50):remote.save_batch('Tombstones',tombstones[offset:offset+50],native['DeviceID'],guard)
    # Local changes win if both sides changed the same URL after the baseline.
    merged=dict(cloud)
    for url,visit in local.items():
        prior=base.get(url);remote_visit=cloud.get(url)
        if not prior or visit['Time']>prior.get('Time',-1)+TIME_TOLERANCE:merged[url]=visit
        elif remote_visit is None:merged.pop(url,None)
    additions=[visit for url,visit in merged.items() if url not in local or visit['Time']>local[url]['Time']+TIME_TOLERANCE]
    removals=[url for url,visit in local.items() if visit['Time']>=cutoff and url not in merged and url in base]
    next_base={url:visit for url,visit in merged.items() if visit['Time']>=cutoff}
    if additions or removals:
        transaction=text_type(uuid.uuid4()).upper();plan={'Version':1,'Account':account,'Transaction':transaction,'Expected':native['Token'],'Add':additions,'Remove':removals}
        pending={'Version':1,'Account':account,'Transaction':transaction,'Model':next_base}
        private_write('history-pending.plist',plists.dumps(pending,fmt=plists.FMT_BINARY));private_write('history-incoming.plist',plists.dumps(plan,fmt=plists.FMT_BINARY));post('org.aquatransport.history.updated.%d'%os.getuid())
        state_name='applying-native-changes'
    else:
        state['Base']=next_base;private_write('history-state.plist',plists.dumps(state,fmt=plists.FMT_BINARY));state_name='ok'
    return {'state':state_name,'local':len(local),'cloud':len(cloud),'uploaded':len(uploads),'tombstones':len(tombstones),'incoming':len(additions),'removed':len(removals)}
