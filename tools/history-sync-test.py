# -*- coding: utf-8 -*-
from __future__ import print_function,unicode_literals
import os,sys,tempfile,shutil,datetime,unittest,zlib,hashlib
sys.path.insert(0,os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),'build','cloudtabs-system'))
import history,client,plists
from compat import Path
from client import pb,parse,sub,one,text
from keychain import fields,value
from pcs import Protection
from crypto import derive_key,to_bytes

class Connection(object):
 def __init__(self):self.calls=[]
 def perform(self,kind,payload,path,flow):self.calls.append((kind,parse(payload),path,flow));return {}
class WireRemote(history.Remote):
 def __init__(self):pass

class HistoryTests(unittest.TestCase):
 def test_encrypted_visit_and_tombstone_records(self):
  remote=WireRemote();remote.connection=Connection();remote.parent_keys=[derive_key(256,to_bytes(1,32))]
  remote.zone_id=pb((1,pb((1,'History'),(2,6))),(2,pb((1,'fixture-owner'),(2,7))))
  remote.zone=parse(pb((1,remote.zone_id),(3,pb((2,'zone-tag')))))
  visit={'URL':'https://example.invalid/','Title':'Fixture','VisitTime':123.5,'HTTPNonGet':False,'LoadSuccessful':True}
  history.Remote.save_batch(remote,'Visits',[visit],'device',lambda:True)
  kind,request,path,flow=remote.connection.calls[-1];self.assertEqual((kind,path,flow),(210,'/ckdatabase/api/client/record/save','CKDModifyRecordsOperation'))
  record=sub(request,1);record_id=text(sub(sub(record,2),1),1);keys,_=Protection(one(sub(record,13),1)).unlock(remote.parent_keys)
  f=fields(record);compressed=keys[0].decrypt(one(f['EncryptedData'],2),('History-'+record_id+'-EncryptedData').encode('utf-8'))
  payload=plists.loads(zlib.decompress(compressed));self.assertEqual(payload,{'ClientVersion':3,'Visits':[visit]})
  self.assertEqual(value(f['UUID']),record_id);self.assertEqual(value(f['Version']),1)
  tombstone=history.secure_tombstone(visit['URL'],200.0,'device');remote.connection.calls=[]
  history.Remote.save_batch(remote,'Tombstones',[tombstone],'device',lambda:True)
  record=sub(remote.connection.calls[0][1],1);f=fields(record);record_id=text(sub(sub(record,2),1),1);keys,_=Protection(one(sub(record,13),1)).unlock(remote.parent_keys)
  payload=plists.loads(zlib.decompress(keys[0].decrypt(one(f['EncryptedData'],2),('History-'+record_id+'-EncryptedData').encode('utf-8'))))
  self.assertEqual(payload['Tombstones'][0],tombstone);self.assertEqual(value(f['Version']),2)
  self.assertEqual(tombstone['URLHash'],hashlib.sha512(tombstone['URLSalt']+visit['URL'].encode('utf-8')).digest())
 def test_tombstone_time_and_url_authentication(self):
  visit={'URL':'https://example.invalid/','Title':'','Time':100.0,'HTTPNonGet':False,'LoadSuccessful':True};t=history.secure_tombstone(visit['URL'],150.0,'device')
  remote=WireRemote();remote.tombstones=[{'Salt':t['URLSalt'],'Hash':t['URLHash'],'Start':t['StartTime'],'End':t['EndTime']}]
  self.assertTrue(history.Remote.tombstoned(remote,visit));visit['Time']=151;self.assertFalse(history.Remote.tombstoned(remote,visit));visit['Time']=100;visit['URL']='https://other.invalid/';self.assertFalse(history.Remote.tombstoned(remote,visit))
 def test_snapshot_validation(self):
  directory=tempfile.mkdtemp(prefix='aq-history-test-');previous=client.STATE
  try:
   client.STATE=Path(directory);history.STATE=Path(directory)
   value={'Version':1,'Account':'fixture','DeviceID':'device','Token':'a'*64,'Entries':[{'URL':'https://example.invalid/','Title':'Fixture','Time':123.0,'HTTPNonGet':False,'LoadSuccessful':True}]}
   client.private_write('local-history.plist',plists.dumps(value,fmt=plists.FMT_BINARY));raw,entries=history.snapshot('fixture');self.assertEqual(entries['https://example.invalid/']['Time'],123.0);self.assertIsNone(history.snapshot('other'))
   value['Entries'][0]['URL']='file:///private/fixture';client.private_write('local-history.plist',plists.dumps(value,fmt=plists.FMT_BINARY));self.assertIsNone(history.snapshot('fixture'))
  finally:
   client.STATE=previous;history.STATE=previous;shutil.rmtree(directory)
 def test_aged_baseline_is_not_a_deletion(self):
  directory=tempfile.mkdtemp(prefix='aq-history-state-');saved=[];now=(datetime.datetime.utcnow()-datetime.datetime(2001,1,1)).total_seconds()
  class FakeRemote(object):
   def __init__(self,c):self.saved=[]
   def current(self,cutoff):return {}
   def save_batch(self,kind,values,device,guard):self.saved.append((kind,values));saved.extend(values)
  previous=(client.STATE,history.STATE,history.Remote,history.client,history.post)
  try:
   client.STATE=Path(directory);history.STATE=Path(directory);history.Remote=FakeRemote;history.client=lambda:object();history.post=lambda name:None
   client.private_write(history.KEY_CACHE,b'key')
   local={'Version':1,'Account':'fixture','DeviceID':'device','Token':'b'*64,'Entries':[]};client.private_write('local-history.plist',plists.dumps(local,fmt=plists.FMT_BINARY))
   state={'Version':1,'Account':'fixture','Base':{'https://old.invalid/':{'URL':'https://old.invalid/','Title':'','Time':now-history.WINDOW-10,'HTTPNonGet':False,'LoadSuccessful':True}}};client.private_write('history-state.plist',plists.dumps(state,fmt=plists.FMT_BINARY))
   result=history.synchronize('fixture',lambda:True);self.assertEqual(result['tombstones'],0);self.assertEqual(saved,[])
  finally:
   client.STATE,history.STATE,history.Remote,history.client,history.post=previous;shutil.rmtree(directory)
 def test_native_tenth_second_rounding_does_not_reupload(self):
  local={'URL':'https://example.invalid/','Title':'Fixture','Time':100.05,'HTTPNonGet':False,'LoadSuccessful':True};cloud=dict(local,Time=100.0)
  self.assertFalse(local['Time']>cloud['Time']+history.TIME_TOLERANCE)
if __name__=='__main__':unittest.main()
