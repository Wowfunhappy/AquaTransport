from __future__ import print_function,unicode_literals
import sys,unittest,hashlib,tempfile,os,shutil,json
from contextlib import contextmanager
sys.path.insert(0,os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),'build','cloudtabs-system'))
from compat import Path,as_bytes,from_bytes,to_bytes,unhex,byte_at,MissingFile
import plists as plistlib
class patch(object):
 @staticmethod
 @contextmanager
 def object(obj,name,value=None,**options):
  previous=getattr(obj,name)
  setattr(obj,name,(lambda *a,**k:options['return_value']) if 'return_value' in options else value)
  try:yield
  finally:setattr(obj,name,previous)
@contextmanager
def temporary_directory(prefix):
 name=tempfile.mkdtemp(prefix=prefix)
 try:yield name
 finally:shutil.rmtree(name)

from crypto import *
from client import pb,parse,one,unframe,varint
import client
from der import decode,encode
from keychain import unarchive

class CryptoTests(unittest.TestCase):
 def test_rfc5297(self):
  key=unhex('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
  aad=unhex('101112131415161718191a1b1c1d1e1f2021222324252627')
  cipher=unhex('85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c')
  self.assertEqual(siv_decrypt(key,cipher,[aad]),unhex('112233445566778899aabbccddee'))
  with self.assertRaises(ValueError): siv_decrypt(key,cipher[:-1]+as_bytes([byte_at(cipher,-1)^1]),[aad])
  with self.assertRaises(ValueError): siv_decrypt(key,cipher,[aad+b'X'])
 def test_nist_gcm(self):
  key=as_bytes(16);iv=as_bytes(12);cipher=unhex('0388dace60b6a392f328c2b971b2fe78')
  tag=unhex('ab6e47d42cec13bdf53a67b21257bddf')
  self.assertEqual(gcm_decrypt(key,iv,cipher,tag),as_bytes(16))
  self.assertEqual(gcm_decrypt(key,iv,cipher,tag[:12]),as_bytes(16))
  self.assertEqual(gcm_encrypt(key,iv,as_bytes(16),tag_length=16),(cipher,tag))
  self.assertEqual(gcm_encrypt(key,iv,as_bytes(16)),(cipher,tag[:12]))
  with self.assertRaises(Exception):gcm_decrypt(key,iv,cipher,b'X'+tag[1:])
 def test_der_bounds(self):
  self.assertEqual(decode(unhex('3003020105')).children[0].integer(),5)
  for bad in ('3080030201050000','308103020105','30030201','300302010500','02020001'):
   with self.assertRaises(ValueError):
    node=decode(unhex(bad))
    if node.tag==2:node.integer()
  nested=unhex('020101')
  for _ in range(34):nested=encode(0x30,nested)
  with self.assertRaises(ValueError):decode(nested)
 def test_archive_top_fields_and_cycles(self):
  names=('SFIESAuthenticationCode','SFCiphertext','SFEphemeralSenderPublicKeyExternaRepresentation')
  archive={'$version':100000,'$archiver':'NSKeyedArchiver','$objects':['$null',b'fixture'],'$top':{key:plistlib.UID(1) for key in names}}
  decoded=unarchive(plistlib.dumps(archive,fmt=plistlib.FMT_BINARY))
  self.assertEqual(decoded,{key:b'fixture' for key in names})
  archive['$objects'][1]={'NS.data':plistlib.UID(1)}
  with self.assertRaises(ValueError):unarchive(plistlib.dumps(archive,fmt=plistlib.FMT_BINARY))
 def test_private_state_boundaries(self):
  with temporary_directory(prefix='aquatransport-cloudtabs-test-') as directory:
   path=Path(directory)
   with patch.object(client,'STATE',path):
    client.private_write('fixture',b'synthetic')
    self.assertEqual(client.private_read('fixture'),b'synthetic')
    self.assertEqual((path/'fixture').stat().st_mode&0o777,0o600)
    os.chmod(str(path/'fixture'),0o644)
    with self.assertRaises(RuntimeError):client.private_read('fixture')
    os.symlink(str(path/'fixture'),str(path/'link'))
    with self.assertRaises((IOError,OSError)):client.private_read('link')
    for name in ('..','../outside','sub/path'):
     with self.assertRaises(ValueError):client.private_read(name)
     with self.assertRaises(ValueError):client.private_write(name,b'synthetic')
 def test_credential_refresh_is_account_scoped(self):
  with temporary_directory(prefix='aquatransport-cloudtabs-test-') as directory:
   instance=client.CloudKit.__new__(client.CloudKit)
   instance.account={'dsid':'123','clientInfo':'fixture','tokens':{'mmeAuthToken':'old','cloudKitToken':'old-cloud'}}
   response={'appleAccountInfo':{'dsPrsID':'123'},'tokens':{'mmeAuthToken':'new','cloudKitToken':'new-cloud','unrelatedToken':'not-needed'}}
   with patch.object(client,'STATE',Path(directory)),patch.object(instance,'account_settings',return_value=response):
    instance.renew_credentials()
    saved=plistlib.loads(client.private_read('session.plist'))
    self.assertEqual(saved['tokens'],{'mmeAuthToken':'new','cloudKitToken':'new-cloud'})
    response['appleAccountInfo']['dsPrsID']='different'
    with self.assertRaises(RuntimeError):instance.renew_credentials()
    self.assertEqual(plistlib.loads(client.private_read('session.plist')),saved)
 def test_native_recovery_and_key_wrap(self):
  from compat import b64decode
  from native import derive_key,load_private
  from recover import decode_bottle,peer_info
  fixture=json.load(open(os.path.join(os.path.dirname(__file__),'cloudtabs-crypto-fixtures.json')))
  peer=parse(b64decode(fixture['peer']))
  peer_info(peer)
  identity,signing,encryption=decode_bottle(parse(b64decode(fixture['bottle'])),b64decode(fixture['entropy']),fixture['account'],{fixture['peer_id']:peer})
  self.assertEqual(identity,fixture['peer_id'])
  self.assertEqual(signing.point,b64decode(fixture['signing_point']))
  self.assertEqual(encryption.point,b64decode(fixture['encryption_point']))
  self.assertEqual(load_private(encryption.private_der).point,encryption.point)
  with self.assertRaises(ValueError):decode_bottle(parse(b64decode(fixture['bottle'])),b'X'*72,fixture['account'],{fixture['peer_id']:peer})
  key=derive_key(256,to_bytes(1,32));wrapped=b64decode(fixture['rfc6637'])
  self.assertEqual(rfc6637_unwrap(key,wrapped),b64decode(fixture['unwrapped']))
  with self.assertRaises(ValueError):rfc6637_unwrap(key,wrapped[:-1]+as_bytes([byte_at(wrapped,-1)^1]))
 def test_srp_server(self):
  user=b'123456789';pin=b'fixture-passcode';salt=b'\0fixture-salt'
  a=EscrowSRP(unhex('dd'*32)); b=int('ab'*32,16)
  n=SRP_N;g=2
  x=from_bytes(sha256(salt,sha256(user,b':',pin)),'big');v=pow(g,x,n)
  k=from_bytes(sha256(raw(n),to_bytes(g,256)),'big')
  B=(k*v+pow(g,b,n))%n
  proof=a.challenge(user,pin,salt,raw(B))
  u=from_bytes(sha256(a.public,raw(B)),'big')
  key=sha256(raw(pow((from_bytes(a.public,'big')*pow(v,u,n))%n,b,n)))
  self.assertEqual(a.key,key)
  a.verify(sha256(a.public,proof,key))
  with self.assertRaises(ValueError): a.verify(as_bytes(32))
  with self.assertRaises(ValueError): a.challenge(user,pin,salt,raw(B))
  with self.assertRaises(ValueError): EscrowSRP().challenge(user,pin,salt,b'\0')
 def test_pcs_two_and_four_byte_identifiers(self):
  from pcs import PCSKey,Protection,key_x
  from compat import b64decode
  with open(os.path.join(os.path.dirname(__file__),'cloudtabs-crypto-fixtures.json')) as source:fixture=json.load(source)
  private=derive_key(256,to_bytes(1,32));wrapped=b64decode(fixture['rfc6637']);master=PCSKey(b64decode(fixture['unwrapped']))
  integer=lambda n:encode(2,as_bytes([n]))
  sequence=lambda *parts:encode(0x30,b''.join(parts))
  octets=lambda value:encode(4,value)
  # A read-only share still authenticates the complete envelope with HMAC.
  keyset=sequence(integer(0),encode(0x31,sequence(sequence(integer(3),octets(key_x(private))),octets(wrapped),integer(1))))
  meta=master.encrypt(sequence())
  signed=sequence(integer(1),integer(0),sequence(integer(1),octets(private.point)),sequence())
  mac=hmac.new(kdf(master.key,b'hmackey-of-masterkey'),keyset+meta+signed,hashlib.sha256).digest()
  def envelope(identifier,auth=mac):
   return encode(0x61,sequence(keyset,encode(0xa0,octets(meta)),encode(0xa1,sequence(integer(5),octets(signed))),octets(auth),encode(0xa2,octets(identifier))))
  for length in (2,4):
   keys,private_keys=Protection(envelope(master.identifier()[:length])).unlock([private])
   self.assertEqual(keys[0].key,master.key);self.assertEqual(private_keys,[])
   with self.assertRaises(ValueError):Protection(envelope(b'X'*length)).unlock([private])
   with self.assertRaises(ValueError):Protection(envelope(master.identifier()[:length],b'X'*32)).unlock([private])
  for length in (0,1,3,8):
   with self.assertRaises(ValueError):Protection(envelope(master.identifier()[:length])).unlock([private])
 def test_record_protection_creation_and_key_wrapping(self):
  from pcs import create_record_protection,Protection
  key=unhex('000102030405060708090a0b0c0d0e0f');plain=unhex('00112233445566778899aabbccddeeff')
  wrapped=blob('wrap',key=encoded(key),input=encoded(plain))
  self.assertEqual(wrapped,unhex('1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5'))
  parent=derive_key(256,to_bytes(1,32));other=derive_key(256,to_bytes(2,32))
  packed=rfc6637_wrap(parent,plain);self.assertEqual(rfc6637_unwrap(parent,packed),plain)
  with self.assertRaises(ValueError):rfc6637_unwrap(other,packed)
  protection,master=create_record_protection(parent)
  keys,private=Protection(protection).unlock([parent]);self.assertEqual(keys[0].key,master.key);self.assertEqual(private,[])
  cipher=master.encrypt(b'fixture bookmark value',b'Title')
  self.assertEqual(keys[0].decrypt(cipher,b'Title'),b'fixture bookmark value')
  with self.assertRaises(ValueError):keys[0].decrypt(cipher,b'URL')
  with self.assertRaises(ValueError):Protection(protection).unlock([other])
  with self.assertRaises(ValueError):Protection(protection[:-1]+as_bytes([byte_at(protection,-1)^1])).unlock([parent])
 def test_vault(self):
  header=struct.pack(b'>II16s',165,2,as_bytes(16))
  frame=vault_encode(header,[(b'fixture-id',20),(as_bytes(32),0)])
  self.assertEqual(vault_decode(frame,24,2),(header,[b'fixture-id',as_bytes(32)]))
  for i in range(len(frame)):
   with self.assertRaises(ValueError): vault_decode(frame[:i],24,2)
  with self.assertRaises(ValueError): vault_decode(frame+b'X',24,2)
 def test_protobuf(self):
  message=pb((1,'fixture'),(2,123456),(3,pb((1,b'hello'))))
  self.assertEqual(one(parse(message),2),123456)
  self.assertEqual(len(list(unframe(varint(len(message))+message))),1)
  for bad in (b'\0',b'\x0b',b'\x0a\x10short',b'\x08'+b'\xff'*10):
   with self.assertRaises(ValueError):parse(bad)

if __name__=='__main__':unittest.main()
