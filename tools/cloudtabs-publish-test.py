from __future__ import print_function,unicode_literals
import os,sys,tempfile,shutil,datetime,unittest
sys.path.insert(0,os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),'build','cloudtabs-system'))
import publish,client,plists
from compat import Path,MissingFile
from client import pb,parse,one,sub,text
from pcs import PCSKey
from keychain import fields,unarchive,value
from sync import devices_from_records

class PublishTests(unittest.TestCase):
 def setUp(self):
  self.directory=tempfile.mkdtemp(prefix='aquatransport-publish-test-');self.previous=client.STATE;client.STATE=Path(self.directory)
  self.value={'Version':1,'Account':'fixture','DeviceID':'11111111-2222-4333-8444-555555555555','DeviceName':'Fixture Mac','LastModified':datetime.datetime(2026,11,25),'Tabs':[{'Title':'One','URL':'https://example.invalid/one'},{'Title':'Two','URL':'https://example.invalid/two'}]}
  self.key=PCSKey(b'0123456789abcdef');self.zone_id=pb((1,pb((1,'CloudTabs'),(2,6))),(2,pb((1,'fixture-owner'),(2,7))))
  self.zone=pb((1,self.zone_id),(3,pb((2,'zone-tag'))),(6,pb((2,'record-tag'))))
  self.previous_keys=publish.zone_record_keys;publish.zone_record_keys=lambda zone:[self.key]
  self.saved=[];self.deleted=[]
 def tearDown(self):
  client.STATE=self.previous;publish.zone_record_keys=self.previous_keys;shutil.rmtree(self.directory)
 def save_tab_record(self,record,zone_tag,record_tag,update):
  self.assertEqual((zone_tag,record_tag),('zone-tag','record-tag'));self.saved.append(record)
 def delete_tab_record(self,identifier):self.deleted.append(text(sub(parse(identifier),1),1))
 def test_encrypted_fields_archive_and_record_identity(self):
  owner=publish.device_id(self.value);records=publish.make_records(self.value,self.zone_id,self.key)
  self.assertEqual(len(records),3)
  for name,raw in records:
   r=parse(raw);decoded={}
   self.assertEqual(one(r,24),self.key.identifier()[:4])
   for fieldname,v in fields(r).items():
    kind=one(v,1)
    if one(v,13,0):
     plain=self.key.decrypt(one(v,2),('CloudTabs-'+name+'-'+fieldname).encode('utf-8'))
     if kind==20:decoded[fieldname]=unarchive(plain)
     elif kind==3:decoded[fieldname]=text(parse(plain),6)
     elif kind==2:self.assertEqual(one(sub(parse(plain),5),1),one(parse(publish.apple_date(self.value['LastModified'])),1))
     else:self.fail('Unexpected encrypted field')
     with self.assertRaises(ValueError):self.key.decrypt(one(v,2),b'wrong-record-binding')
    else:decoded[fieldname]=value(v)
   if name==owner:self.assertEqual(decoded['DeviceName'],'Fixture Mac')
   else:
    self.assertEqual(decoded['OwningDevice'],owner)
    self.assertIn(decoded['URL'],[t['URL'] for t in self.value['Tabs']])
 def test_publish_never_mutates_other_devices_and_deletes_own_closed_tabs(self):
  owner=publish.device_id(self.value);closed='AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE'
  phone='99999999-8888-4777-8666-555555555555'
  phone_raw=pb((2,publish.identifier(phone,self.zone_id)),(3,pb((1,'CloudTab'))))
  closed_raw=pb((2,publish.identifier(closed,self.zone_id)),(3,pb((1,'CloudTab'))))
  decoded=[{'id':phone,'type':'CloudTab','fields':{'OwningDevice':'phone'}},{'id':closed,'type':'CloudTab','fields':{'OwningDevice':owner}}]
  self.assertEqual(publish.publish(self,self.zone,[phone_raw,closed_raw],decoded,self.value,lambda:True),(owner,True))
  self.assertEqual(self.deleted,[closed]);self.assertEqual(len(self.saved),3)
  self.assertNotIn(phone,[text(sub(sub(parse(r),2),1),1) for r in self.saved])
  own_records=[{'id':name,'type':'CloudTab','fields':{'OwningDevice':owner}} for name in publish.tab_ids(self.value)]
  self.saved=[];self.deleted=[]
  raw=[r for _,r in publish.make_records(self.value,self.zone_id,self.key)]
  self.assertEqual(publish.publish(self,self.zone,raw,own_records,self.value,lambda:True),(owner,False))
  self.assertEqual(self.saved,[]);self.assertEqual(self.deleted,[])
 def test_account_change_stops_all_writes_and_does_not_commit_receipt(self):
  with self.assertRaises(RuntimeError):publish.publish(self,self.zone,[],[],self.value,lambda:False)
  self.assertEqual(self.saved,[])
  with self.assertRaises(MissingFile):client.private_read('publish-state.plist')
 def test_failed_save_does_not_delete_tabs_or_advance_receipt(self):
  def fail(*args):raise RuntimeError('synthetic network failure')
  self.save_tab_record=fail
  with self.assertRaises(RuntimeError):publish.publish(self,self.zone,[],[],self.value,lambda:True)
  self.assertEqual(self.deleted,[])
  with self.assertRaises(MissingFile):client.private_read('publish-state.plist')
 def test_snapshot_account_scope_and_stable_tab_identity(self):
  client.private_write('local-tabs.plist',plists.dumps(self.value,fmt=plists.FMT_BINARY))
  self.assertEqual(publish.snapshot('fixture'),self.value);self.assertIsNone(publish.snapshot('other'))
  ids=publish.tab_ids(self.value);self.value['Tabs'].reverse()
  self.assertEqual(publish.tab_ids(self.value),list(reversed(ids)))
  self.value['Tabs'].append(dict(self.value['Tabs'][0]))
  self.assertEqual(len(set(publish.tab_ids(self.value))),3)
  self.value['Tabs'][0]['URL']='file:///private/fixture'
  client.private_write('local-tabs.plist',plists.dumps(self.value,fmt=plists.FMT_BINARY))
  with self.assertRaises(ValueError):publish.snapshot('fixture')
if __name__=='__main__':unittest.main()
