from __future__ import print_function,unicode_literals
import os,sys,unittest,copy
sys.path.insert(0,os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),'src','mac','cloudtabs'))
import bookmark_model as m

def root(name='root'):return {name:{'Kind':'folder','Title':'Root','Role':'Root','Parent':'','Index':0}}
def leaf(title='A',url='https://example.invalid/a',parent='root',index=0):return {'Kind':'leaf','Title':title,'URL':url,'Parent':parent,'Index':index}
def folder(title='Folder',parent='root',index=0):return {'Kind':'folder','Title':title,'Parent':parent,'Index':index}

class MergeTests(unittest.TestCase):
 def test_initial_merge_keeps_both_sides_and_matches_identical_items(self):
  local=root('native-root');local['local']=leaf(parent='native-root');local['new-local']=leaf('B','https://example.invalid/b','native-root',1)
  remote=root('cloud-root');remote['remote']=leaf(parent='cloud-root');remote['new-remote']=leaf('C','https://example.invalid/c','cloud-root',1)
  canonical,mapping=m.map_native(local,remote,{},'fixture-device')
  self.assertEqual(mapping['local'],'remote')
  merged=m.merge({},canonical,remote);self.assertEqual(set(merged),set(['cloud-root','remote','new-local','new-remote']))
  native=m.to_native(merged,mapping,local,'fixture-device')
  self.assertIn('local',[item['ID'] for item in native])
 def test_initial_identity_collision_preserves_both_values(self):
  local=root();local['same-id']=leaf('Local','https://example.invalid/local')
  remote=root();remote['same-id']=leaf('Remote','https://example.invalid/remote')
  canonical,mapping=m.map_native(local,remote,{},'fixture-device');merged=m.merge({},canonical,remote)
  self.assertNotEqual(mapping['same-id'],'same-id');self.assertEqual(len(merged),3)
 def test_initial_rename_keeps_existing_identity(self):
  local=root();local['same-id']=leaf('Old title')
  remote=root();remote['same-id']=leaf('Current title')
  canonical,mapping=m.map_native(local,remote,{},'fixture-device');merged=m.merge({},canonical,remote)
  self.assertEqual(mapping['same-id'],'same-id');self.assertEqual(len(merged),2);self.assertEqual(merged['same-id']['Title'],'Current title')
 def test_native_root_identity_can_change_between_launches(self):
  local=root('new-native-root');local['a']=leaf(parent='new-native-root')
  remote=root('cloud-root');remote['cloud-a']=leaf(parent='cloud-root')
  state={'Map':{'old-native-root':'cloud-root','a':'cloud-a'}}
  canonical,mapping=m.map_native(local,remote,state,'fixture-device')
  self.assertNotIn('old-native-root',mapping);self.assertEqual(mapping['new-native-root'],'cloud-root')
  self.assertEqual(canonical['cloud-a']['Parent'],'cloud-root')
 def test_deletion_requires_common_baseline(self):
  remote=root();remote['a']=leaf()
  self.assertIn('a',m.merge({},root(),remote))
  self.assertNotIn('a',m.merge(remote,root(),remote))
  self.assertNotIn('a',m.merge(remote,remote,root()))
 def test_concurrent_edits_survive_deletion(self):
  base=root();base['a']=leaf();changed=copy.deepcopy(base);changed['a']['Title']='Changed'
  self.assertIn('a',m.merge(base,root(),changed))
  self.assertIn('a',m.merge(base,changed,root()))
 def test_independent_field_changes_and_unread_state(self):
  base=root();base['a']=leaf();base['a']['DateLastViewed']=10.0
  local=copy.deepcopy(base);local['a'].pop('DateLastViewed')
  remote=copy.deepcopy(base);remote['a']['Title']='Remote title'
  merged=m.merge(base,local,remote);self.assertEqual(merged['a']['Title'],'Remote title');self.assertNotIn('DateLastViewed',merged['a'])
 def test_preserve_path_for_new_child_in_deleted_folder(self):
  base=root();base['folder']=folder();local=copy.deepcopy(base);local['new']=leaf(parent='folder')
  merged=m.merge(base,local,root());self.assertIn('folder',merged);self.assertEqual(merged['new']['Parent'],'folder')
 def test_concurrent_insertions_and_reordering(self):
  base=root();base['a']=leaf();base['c']=leaf('C','https://example.invalid/c',index=1)
  local=copy.deepcopy(base);local['b']=leaf('B','https://example.invalid/b',index=1);local['c']['Index']=2
  remote=copy.deepcopy(base);remote['d']=leaf('D','https://example.invalid/d',index=1);remote['c']['Index']=2
  merged=m.merge(base,local,remote);self.assertEqual(m.sequence(merged,'root',set(merged)),['a','b','d','c'])
  local=copy.deepcopy(base);local['a']['Index']=1;local['c']['Index']=0
  merged=m.merge(base,local,remote);self.assertEqual(m.sequence(merged,'root',set(merged)),['c','a','d'])
 def test_reject_cycle_before_any_mutation(self):
  base=root();base['a']=folder('A');base['b']=folder('B',index=1)
  local=copy.deepcopy(base);local['a']['Parent']='b'
  remote=copy.deepcopy(base);remote['b']['Parent']='a'
  with self.assertRaises(ValueError):m.merge(base,local,remote)
 def test_user_defined_preview_is_preserved(self):
  base=root();base['a']=leaf();base['a']['PreviewText']='Original'
  local=copy.deepcopy(base);local['a']['PreviewText']='Automatic page summary'
  remote=copy.deepcopy(base);remote['a'].update(PreviewText='User summary',UserPreview=True)
  self.assertEqual(m.merge(base,local,remote)['a']['PreviewText'],'User summary')
 def test_account_and_shape_validation(self):
  with self.assertRaises(ValueError):m.from_snapshot({'Version':1,'Account':'other'},'fixture')
  nodes=root();nodes['a']=leaf(parent='missing')
  with self.assertRaises(ValueError):m.validate(nodes)
if __name__=='__main__':unittest.main()
