"""Publish only this Mac's native, non-private Safari tab snapshot."""
from __future__ import absolute_import,division,print_function,unicode_literals
import datetime,hashlib,json,struct,uuid,zlib
import plists
from compat import text_type,MissingFile,uuid5,urlsplit
from client import pb,varint,parse,sub,text,one,private_read,private_write
from pcs import zone_record_keys

DEVICE_NAMESPACE=uuid.UUID('97fd4d6e-a5c7-4c72-a990-0e80b1d796f1')

def snapshot(account):
    try:value=plists.loads(private_read('local-tabs.plist'))
    except MissingFile:return None
    if not isinstance(value,dict) or value.get('Version')!=1 or value.get('Account')!=account:return None
    identifier=value.get('DeviceID');name=value.get('DeviceName');tabs=value.get('Tabs');date=value.get('LastModified')
    if not isinstance(identifier,text_type) or len(identifier)!=36:raise ValueError('Invalid local device identifier')
    uuid.UUID(identifier)
    if not isinstance(name,text_type) or not name or len(name)>1024 or not isinstance(tabs,list) or len(tabs)>10000 or not isinstance(date,datetime.datetime):
        raise ValueError('Invalid native Safari snapshot')
    for tab in tabs:
        if not isinstance(tab,dict) or set(tab)!=set(['Title','URL']):raise ValueError('Invalid native Safari tab')
        if not isinstance(tab['Title'],text_type) or len(tab['Title'])>65536 or not isinstance(tab['URL'],text_type) or len(tab['URL'])>131072:
            raise ValueError('Invalid native Safari tab text')
        if urlsplit(tab['URL']).scheme.lower() not in ('http','https','ftp'):raise ValueError('Unsupported native Safari tab URL')
    return value

def device_id(value):return text_type(uuid5(DEVICE_NAMESPACE,value['DeviceID'].upper())).upper()

def tab_ids(value):
    namespace=uuid.UUID(device_id(value));seen={};result=[]
    for tab in value['Tabs']:
        address=tab['URL'];index=seen.get(address,0);seen[address]=index+1
        result.append(text_type(uuid5(namespace,address+'\0'+text_type(index))).upper())
    return result

def archive_string(value):
    return plists.dumps({'$archiver':'NSKeyedArchiver','$version':100000,'$objects':['$null',value],'$top':{'root':plists.UID(1)}},fmt=plists.FMT_BINARY)

def apple_date(value):
    seconds=(value-datetime.datetime(2001,1,1)).total_seconds()
    return varint(1*8+1)+struct.pack(b'<d',seconds)

def identifier(name,zone):return pb((1,pb((1,name),(2,1))),(2,zone))

def field(name,kind,value,key=None,record_name=None,zone_name=None):
    if key:
        if kind==3:value=pb((6,value))
        elif kind==2:value=pb((5,apple_date(value)))
        elif kind!=20:raise ValueError('Unsupported encrypted Safari field')
        encrypted=key.encrypt(value,(zone_name+'-'+record_name+'-'+name).encode('utf-8'))
        encoded=pb((1,kind),(2,encrypted),(13,1))
    elif kind==2:encoded=pb((1,kind),(6,apple_date(value)))
    elif kind==3:encoded=pb((1,kind),(7,value))
    elif kind==1:encoded=pb((1,kind),(2,value))
    elif kind==5:encoded=pb((1,kind),(9,pb((1,1),(2,value))))
    else:raise ValueError('Unsupported Safari field')
    return pb((1,pb((1,name))),(2,encoded))

def make_records(value,zone,key):
    zone_name=text(sub(parse(zone),1),1);owner=device_id(value);ids=tab_ids(value)
    def encrypted(record,name,kind,data):return field(name,kind,data,key,record,zone_name)
    def record(name,kind,fields):return pb((2,identifier(name,zone)),(3,pb((1,kind))),*((7,item) for item in fields))+pb((24,key.identifier()[:4]))
    device=record(owner,'CloudTabDevice',[
        encrypted(owner,'DeviceName',20,archive_string(value['DeviceName'])),
        encrypted(owner,'DeviceTypeIdentifier',3,'com.apple.mac'),
        field('LastModified',2,value['LastModified'])])
    result=[(owner,device)];change=int((value['LastModified']-datetime.datetime(2001,1,1)).total_seconds()*1000)
    for index,(name,tab) in enumerate(zip(ids,value['Tabs'])):
        position=zlib.compress(json.dumps({'sortValues':[{'sortValue':index+1,'changeID':change,'deviceIdentifier':owner}]},sort_keys=True,separators=(',',':')).encode('utf-8'))
        result.append((name,record(name,'CloudTab',[
            encrypted(name,'Title',20,archive_string(tab['Title'])),encrypted(name,'URL',20,archive_string(tab['URL'])),
            encrypted(name,'DateLastViewed',2,value['LastModified']),field('OwningDevice',5,identifier(owner,zone)),
            field('OwningSceneID',3,owner),field('Position',1,position)])))
    return result

def publish(client,raw_zone,raw_records,decoded,value,guard):
    owner=device_id(value);expected=set(tab_ids(value));zone=parse(raw_zone);zone_id=one(zone,1)
    if text(sub(parse(zone_id),1),1)!='CloudTabs':raise ValueError('Unexpected Safari write zone')
    owned=set(record['id'] for record in decoded if record['type']=='CloudTab' and record['fields'].get('OwningDevice')==owner)
    by_name={text(sub(sub(parse(raw),2),1),1):raw for raw in raw_records}
    device_present=owner in by_name
    if device_present and text(sub(parse(by_name[owner]),3),1)!='CloudTabDevice':raise ValueError('Local Safari device record collision')
    if any(name in by_name and name not in owned for name in expected):raise ValueError('Local Safari tab record collision')
    digest=hashlib.sha256(json.dumps({'name':value['DeviceName'],'tabs':value['Tabs'],'date':value['LastModified'].isoformat()},sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')).hexdigest()
    try:previous=plists.loads(private_read('publish-state.plist'))
    except MissingFile:previous={}
    receipt={'Account':value['Account'],'DeviceID':owner,'Digest':digest}
    if previous==receipt and device_present and owned==expected:return owner,False
    key=zone_record_keys(zone)[0]
    zone_tag=text(sub(zone,3),2);record_tag=text(sub(zone,6),2)
    if not zone_tag or not record_tag:raise ValueError('Missing Safari write protection tags')
    for name,record in make_records(value,zone_id,key):
        if not guard():raise RuntimeError('Safari account disabled or changed during upload')
        client.save_tab_record(record,zone_tag,record_tag,name in by_name)
    # A closed tab deletes only a record whose authenticated OwningDevice is
    # this Mac's derived native identity. Other devices never enter this set.
    for name in sorted(owned-expected):
        if not guard():raise RuntimeError('Safari account disabled or changed during upload')
        client.delete_tab_record(identifier(name,zone_id))
    if not guard():raise RuntimeError('Safari account disabled or changed during upload')
    private_write('publish-state.plist',plists.dumps(receipt,fmt=plists.FMT_BINARY))
    return owner,True
