# -*- coding: utf-8 -*-
from __future__ import print_function,unicode_literals
import os,sys,unittest,copy,hashlib,hmac,json,zlib
sys.path.insert(0,os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),'build','cloudtabs-system'))
import bookmarks
from client import parse,pb,one,sub,text
from keychain import fields,unarchive,value
from pcs import create_record_protection,Protection
from crypto import derive_key,to_bytes

class Connection(object):
 def __init__(self):self.calls=[]
 def perform(self,kind,payload,path,flow):self.calls.append((kind,parse(payload)));return {}

class Remote(bookmarks.Remote):
 def __init__(self):
  self.items={};self.raw={};self.decoded={};self.layers={};self.cache={};self.connection=Connection()
  self.parent_keys=[derive_key(256,to_bytes(1,32))]
  self.zone_id=pb((1,pb((1,'Bookmarks'),(2,6))),(2,pb((1,'fixture-owner'),(2,7))))
  self.zone=parse(pb((1,self.zone_id),(3,pb((2,'fixture-zone-tag')))))
  self.identity_key=b'0123456789abcdef';self.identity_key_id=b'fixture-key-id'.ljust(32,b'\0')
 def identity_hash(self,title,url=''):return bookmarks.Remote.identity_hash(self,title,url)
 def record_keys(self,name):return self.cache[name]

class WireTests(unittest.TestCase):
 def setUp(self):self.remote=Remote();self.node={'Kind':'leaf','Title':'Fixture café','URL':'https://example.invalid/fixture','Parent':'Reading List','Index':0,'DateAdded':123.5,'DateLastViewed':456.0,'PreviewText':'Fixture summary'}
 def create(self):
  self.assertTrue(bookmarks.save_item(self.remote,'fixture-id',self.node,'fixture-device',lambda:True))
  kind,request=self.remote.connection.calls[-1];self.assertEqual(kind,210)
  record=sub(request,1);keys,_=Protection(one(sub(record,13),1)).unlock(self.remote.parent_keys)
  return request,record,keys[0]
 def test_native_bookmark_record_encoding(self):
  request,record,key=self.create();f=fields(record)
  self.assertEqual(one(request,6),2);self.assertIsNone(one(request,8));self.assertEqual(one(request,2),1)
  self.assertEqual(key.decrypt(one(f['Title'],2),b'Title').decode('utf-8'),self.node['Title'])
  self.assertEqual(key.decrypt(one(f['URL'],2),b'URL').decode('utf-8'),self.node['URL'])
  self.assertEqual(unarchive(key.decrypt(one(f['DateAdded'],2),b'DateAdded')),{'NS.time':123.5})
  self.assertEqual(unarchive(key.decrypt(one(f['PreviewText'],2),b'PreviewText')),'Fixture summary')
  self.assertEqual(value(f['IdentityHash']),self.remote.identity_hash(self.node['Title'],self.node['URL']))
  self.assertEqual(one(sub(f['ParentFolder'],9),1),2)
  position=json.loads(zlib.decompress(value(f['Position'])))
  self.assertEqual(position['default']['sortValues'][0]['sortValue'],1)
  self.assertEqual(value(f['TitleURLAndIdentityHash_generation']),1)
  self.assertEqual(value(f['ParentAndPosition_deviceIdentifier']),'fixture-device')
 def test_unread_update_is_a_field_delete_and_preserves_other_fields(self):
  request,record,key=self.create();record[1]=[b'fixture-etag']
  self.remote.raw['fixture-id']=record;self.remote.items['fixture-id']=dict(self.node)
  self.remote.cache['fixture-id']=[key];self.remote.decoded['fixture-id']={'fields':{'DateLastViewed_generation':1}}
  unread=dict(self.node);unread.pop('DateLastViewed')
  self.remote.connection.calls=[]
  bookmarks.save_item(self.remote,'fixture-id',unread,'fixture-device',lambda:True)
  _,request=self.remote.connection.calls[0];record=sub(request,1)
  self.assertEqual(request[3],[b'DateLastViewed']);self.assertEqual(text(record,1),'fixture-etag')
  self.assertEqual(set(fields(record)),set(['DateLastViewed_generation','DateLastViewed_deviceIdentifier']))
  self.assertEqual(value(fields(record)['DateLastViewed_generation']),2)
 def test_protected_roots_and_disabled_account_do_not_write(self):
  self.assertFalse(bookmarks.save_item(self.remote,'Reading List',{'Role':'ReadingList'},'fixture',lambda:True))
  with self.assertRaises(RuntimeError):bookmarks.save_item(self.remote,'fixture-id',self.node,'fixture',lambda:False)
  self.assertEqual(self.remote.connection.calls,[])
 def test_position_preserves_other_native_views(self):
  request,record,key=self.create();self.remote.raw['fixture-id']=record;self.remote.items['fixture-id']=dict(self.node);self.remote.cache['fixture-id']=[key]
  old={'default':{'sortValues':[{'sortValue':100,'changeID':1,'deviceIdentifier':'other'}]},'other-view':{'sortValues':[]}}
  self.remote.decoded['fixture-id']={'fields':{'ParentAndPosition_generation':4,'Position':zlib.compress(json.dumps(old).encode('utf-8'))}}
  bookmarks.save_item(self.remote,'fixture-id',self.node,'fixture',lambda:True,True)
  _,request=self.remote.connection.calls[-1];position=json.loads(zlib.decompress(value(fields(sub(request,1))['Position'])))
  self.assertEqual(position['other-view'],old['other-view']);self.assertEqual(position['default']['sortValues'][0]['changeID'],5)
if __name__=='__main__':unittest.main()
