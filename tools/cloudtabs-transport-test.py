from __future__ import print_function,unicode_literals
import sys,os,subprocess
sys.path.insert(0,os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),'build','cloudtabs-system'))
from compat import Path,run
import plists as plistlib
from transport import NativeSession
helper=Path('build/cloudtabs-transport-fixture').resolve()
for architecture in ('x86_64','i386'):
 def invoke(value):
  return run(['/usr/bin/arch','-'+architecture,str(helper),'--transport'],input=plistlib.dumps(value,fmt=plistlib.FMT_BINARY),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
 for body in (b'',b'synthetic protobuf payload'):
  result=invoke({'url':'https://gateway.icloud.com/ckdatabase/api/client/zone/retrieve','headers':{'X-Fixture':'synthetic'},'body':body})
  assert result.returncode==0,result.stderr
  assert plistlib.loads(result.stdout)=={'status':200,'body':body}
 for url in ('http://gateway.icloud.com/ckdatabase/api/client/zone/retrieve','https://gateway.icloud.com.evil.invalid/ckdatabase/api/client/zone/retrieve','https://gateway.icloud.com:444/ckdatabase/api/client/zone/retrieve','https://user:pass@gateway.icloud.com/ckdatabase/api/client/zone/retrieve','https://gateway.icloud.com/unrelated','https://p1-escrowproxy.icloud.com/escrowproxy/api/delete'):
  assert invoke({'url':url,'headers':{},'body':b''}).returncode==2
 assert invoke({'url':'https://setup.icloud.com/setup/get_account_settings','headers':{'X-Fixture':'bad\r\nheader'},'body':b''}).returncode==2
 assert invoke({'url':'https://setup.icloud.com/setup/get_account_settings','headers':{},'body':'wrong-type'}).returncode==2
 print('PASS:',architecture,'native HTTP framing, empty bodies, payloads and authority/header validation')

# Exercise the Python/native boundary, not just hand-built native payloads.
# strftime returns bytes under the stock Python 2 interpreter. Recovery and
# account-settings requests use these headers without CloudKit's text coercion.
session=NativeSession(helper)
for url in (b'https://setup.icloud.com/setup/get_account_settings',
            b'https://p1-escrowproxy.icloud.com/escrowproxy/api/get_records',
            b'https://p1-escrowproxy.icloud.com/escrowproxy/api/srp_init',
            b'https://p1-escrowproxy.icloud.com/escrowproxy/api/recover'):
 response=session.post(url,headers={b'X-Apple-I-Client-Time':b'2026-11-25T00:00:00Z',
                                   'X-Fixture':'text header'},data=b'synthetic recovery body')
 assert response.status_code==200 and response.content==b'synthetic recovery body'
try:session.post('https://setup.icloud.com/setup/get_account_settings',headers={'X-Fixture':42})
except ValueError:pass
else:raise AssertionError('Non-string HTTP field accepted')
print('PASS: Python 2 byte-string HTTP fields cross the plist boundary as text; bodies remain binary')
