from __future__ import print_function,unicode_literals
import sys,os,tempfile,shutil,unittest,datetime
sys.path.insert(0,os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),'build','cloudtabs-system'))
import setup,client,plists
from compat import Path,Result,MissingFile

class SetupTests(unittest.TestCase):
 def setUp(self):
  self.directory=tempfile.mkdtemp(prefix='aquatransport-setup-fixture-')
  self.saved=[]
  self.patch(setup,'STATE',Path(self.directory));self.patch(client,'STATE',Path(self.directory))
  self.calls=[];self.authorize=0;self.cancel_recovery=False;self.failure=False;self.account='fixture'
  self.patch(setup,'current_account',lambda *args:self.account)
  self.patch(setup,'run',self.helper_run)
  self.patch(setup,'recover_identity',self.recover)
  self.patch(setup,'obtain_pcs_items',lambda:client.private_write('pcs-wrapping-keys.plist',b'fixture'))
  self.patch(setup,'synchronize',self.synchronize)
  self.patch(setup,'prepare_bookmark_keys',lambda:client.private_write('bookmarks-service-keys.plist',b'fixture-bookmark-key'))
  self.patch(setup,'prepare_history_keys',lambda:client.private_write('history-service-keys.plist',b'fixture-history-key'))
 def patch(self,obj,name,value):
  self.saved.append((obj,name,getattr(obj,name)));setattr(obj,name,value)
 def tearDown(self):
  for obj,name,value in reversed(self.saved):setattr(obj,name,value)
  shutil.rmtree(self.directory)
 def helper_run(self,arguments,**kwargs):
  self.calls.append(arguments[1])
  if arguments[1]=='--failure':return Result(3,None,None)
  self.assertEqual(arguments[1:],[u'--authorize',u'fixture'])
  if not self.authorize:
   client.private_write('session.plist',plists.dumps({'dsid':'fixture','clientInfo':'fixture','created':datetime.datetime.utcnow(),'pet':'temporary','tokens':{'mmeAuthToken':'fixture-mme','cloudKitToken':'fixture-cloud','other':'temporary'}},fmt=plists.FMT_BINARY))
  return Result(self.authorize,None,None)
 def recover(self,*arguments):
  if self.cancel_recovery:raise setup.RecoveryCancelled()
  if self.failure:raise RuntimeError('synthetic recovery failure')
  client.private_write('recovered-identity.plist',b'fixture')
 def synchronize(self,**kwargs):
  self.assertEqual(kwargs,{'preparing_account':'fixture'})
  client.private_write('safari-service-keys.plist',b'fixture-service-key')
  return object()
 def prepare(self):return setup.prepare_service('fixture',Path('/fixture/authorize'))
 def test_success_retains_only_scoped_material(self):
  self.assertEqual(self.prepare(),0)
  self.assertEqual(set(os.listdir(self.directory)),set(['session.plist','safari-service-keys.plist','bookmarks-service-keys.plist','history-service-keys.plist']))
  saved=plists.loads(client.private_read('session.plist'))
  self.assertNotIn('pet',saved);self.assertEqual(set(saved['tokens']),set(['mmeAuthToken','cloudKitToken']))
 def test_password_cancel_leaves_no_state(self):
  client.private_write('safari-service-keys.plist',b'previous-authorization')
  client.private_write('session-interrupted.new',b'interrupted-temporary-authorization')
  self.authorize=3;self.assertEqual(self.prepare(),3)
  self.assertEqual(os.listdir(self.directory),[]);self.assertEqual(self.calls,['--authorize'])
 def test_passcode_cancel_cleans_temporary_authorization(self):
  self.cancel_recovery=True;self.assertEqual(self.prepare(),3)
  self.assertEqual(os.listdir(self.directory),[]);self.assertNotIn('--failure',self.calls)
 def test_recovery_failure_uses_generic_dialog_and_cleans_state(self):
  self.failure=True;self.assertEqual(self.prepare(),3)
  self.assertEqual(os.listdir(self.directory),[]);self.assertEqual(self.calls,['--authorize','--failure'])
 def test_account_change_never_authenticates_wrong_account(self):
  self.account='different';self.assertEqual(self.prepare(),3)
  self.assertEqual(self.calls,['--failure']);self.assertEqual(os.listdir(self.directory),[])
 def test_disable_preserves_lock_inode_and_removes_authorization(self):
  client.private_write('sync.lock',b'');stamp=os.stat(str(setup.STATE/'sync.lock')).st_ino
  self.assertEqual(self.prepare(),0)
  self.patch(setup,'post',lambda name:None)
  self.assertEqual(setup.service_main(['--disable']),0)
  self.assertEqual(os.listdir(self.directory),['sync.lock'])
  self.assertEqual(os.stat(str(setup.STATE/'sync.lock')).st_ino,stamp)

if __name__=='__main__':unittest.main()
