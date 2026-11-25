from __future__ import print_function,unicode_literals
import os,sys,tempfile,shutil,copy,unittest
sys.path.insert(0,os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),'build','cloudtabs-system'))
import bookmarks,client,plists
from compat import Path

def tree(prefix):
 result={}
 for index,role in enumerate(('Root','BookmarksBar','BookmarksMenu','ReadingList')):
  identifier=prefix+role
  result[identifier]={'Kind':'folder','Title':role,'Role':role,'Parent':'' if role=='Root' else prefix+'Root','Index':0 if role=='Root' else index-1}
 return result
def leaf(parent,title,index=0):return {'Kind':'leaf','Title':title,'URL':'https://example.invalid/'+title,'Parent':parent,'Index':index}
class RemoteFixture(object):
 def __init__(self,items):self.items=copy.deepcopy(items)
class Connection(object):account={'dsid':'fixture'}

class StateTests(unittest.TestCase):
 def setUp(self):
  self.directory=tempfile.mkdtemp(prefix='aquatransport-bookmark-state-');self.previous=[];self.uploads=[];self.notifications=[]
  self.patch(client,'STATE',Path(self.directory));self.patch(bookmarks,'STATE',Path(self.directory))
  self.local=tree('native-');self.local['local-a']=leaf('native-ReadingList','A')
  self.remote=tree('cloud-');self.remote['cloud-a']=leaf('cloud-ReadingList','A');self.remote['cloud-b']=leaf('cloud-ReadingList','B',1)
  self.patch(bookmarks,'client',lambda:Connection());self.patch(bookmarks,'Remote',lambda c:RemoteFixture(self.remote))
  self.patch(bookmarks,'upload',self.upload);self.patch(bookmarks,'post',self.notifications.append)
  client.private_write(bookmarks.KEY_CACHE,b'fixture key')
  self.snapshot(self.local,'a'*64)
 def patch(self,obj,name,value):self.previous.append((obj,name,getattr(obj,name)));setattr(obj,name,value)
 def tearDown(self):
  for obj,name,value in reversed(self.previous):setattr(obj,name,value)
  shutil.rmtree(self.directory)
 def upload(self,remote,merged,device,guard):
  self.assertTrue(guard());self.uploads.append(copy.deepcopy(merged));return 0,0
 def snapshot(self,nodes,token):
  values=[]
  for identifier,node in nodes.items():
   value=dict(node);value['ID']=identifier;values.append(value)
  client.private_write('local-bookmarks.plist',plists.dumps({'Version':1,'Account':'fixture','Token':token,'DeviceID':'fixture-device','Items':values},fmt=plists.FMT_BINARY))
 def sync(self):return bookmarks.synchronize('fixture',lambda:True)
 def test_baseline_advances_only_after_native_acknowledgement(self):
  result=self.sync();self.assertEqual(result['state'],'applying-native-changes')
  state=bookmarks.read_state('bookmarks-state.plist');self.assertEqual(state['Base'],{})
  plan=bookmarks.read_state('bookmarks-incoming.plist');self.assertEqual(plan['Expected'],'a'*64)
  nodes={}
  for value in plan['Items']:
   node=dict(value);identifier=node.pop('ID');nodes[identifier]=node
  self.snapshot(nodes,'b'*64)
  client.private_write('bookmarks-ack.plist',plists.dumps({'Account':'fixture','Transaction':plan['Transaction'],'Applied':True},fmt=plists.FMT_BINARY))
  result=self.sync();self.assertEqual(result['state'],'ok');self.assertEqual(result['readingList'],2)
  self.assertTrue(bookmarks.read_state('bookmarks-state.plist')['Base']);self.assertIsNone(bookmarks.read_state('bookmarks-pending.plist'))
 def test_local_edit_during_first_merge_is_not_overwritten(self):
  self.sync();plan=bookmarks.read_state('bookmarks-incoming.plist')
  self.local['local-a']['Title']='Edited while syncing';self.snapshot(self.local,'b'*64)
  client.private_write('bookmarks-ack.plist',plists.dumps({'Account':'fixture','Transaction':plan['Transaction'],'Applied':False,'Reason':'stale'},fmt=plists.FMT_BINARY))
  self.sync();self.assertEqual(self.uploads[-1]['cloud-a']['Title'],'Edited while syncing')
 def test_account_disabled_does_not_upload(self):
  self.assertIsNone(bookmarks.synchronize('fixture',lambda:False));self.assertEqual(self.uploads,[])
 def test_native_failure_does_not_spin(self):
  self.sync();plan=bookmarks.read_state('bookmarks-incoming.plist')
  client.private_write('bookmarks-ack.plist',plists.dumps({'Account':'fixture','Transaction':plan['Transaction'],'Applied':False,'Reason':'native-error'},fmt=plists.FMT_BINARY))
  before=len(self.uploads);self.assertEqual(self.sync()['state'],'native-change-rejected');self.assertEqual(len(self.uploads),before)
if __name__=='__main__':unittest.main()
