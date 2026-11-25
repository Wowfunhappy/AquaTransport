"""Native CFNetwork transport using the existing AquaTransport HTTP helper."""
from __future__ import absolute_import, division, print_function, unicode_literals
from compat import text_type, binary_type, integer_types, run, DEVNULL
import base64
import plists as plistlib
import subprocess
from compat import Path

LIMIT=4*1024*1024


def header_text(value):
    # Python 2's strftime/base64 and several system APIs return byte strings.
    # HTTP fields are text; a binary plist would otherwise encode them as NSData
    # and the native helper correctly refuses a non-string header.
    if isinstance(value,binary_type):return value.decode('utf-8')
    if isinstance(value,text_type):return value
    raise ValueError('HTTP fields must be strings')


class Response(object):
    def __init__(self,reply):
        if not isinstance(reply,dict):raise RuntimeError('Invalid native HTTP response')
        if 'error' in reply:raise RuntimeError('Native HTTP transport error %d'%reply['error'])
        self.status_code=reply.get('status')
        self.content=reply.get('body')
        if not isinstance(self.status_code,integer_types) or not isinstance(self.content,binary_type) or len(self.content)>LIMIT:
            raise RuntimeError('Invalid native HTTP response')
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def iter_content(self,size):
        for offset in range(0,len(self.content),size):yield self.content[offset:offset+size]


class NativeSession(object):
    def __init__(self,helper=None):
        self.helper=Path(helper) if helper else Path(__file__).resolve().parent/'aquatransport-cloudtabs-authorize'
    def post(self,url,headers,data=b'',auth=None,timeout=None,allow_redirects=False,stream=True):
        if allow_redirects:raise ValueError('CloudKit redirects are not allowed')
        if not isinstance(data,binary_type) or len(data)>LIMIT:raise ValueError('HTTP request exceeds size limit')
        url=header_text(url)
        headers={header_text(key):header_text(value) for key,value in headers.items()}
        if auth is not None:
            headers['Authorization']='Basic '+base64.b64encode((auth[0]+':'+auth[1]).encode('utf-8')).decode('utf-8')
        payload=plistlib.dumps({'url':url,'headers':headers,'body':data},fmt=plistlib.FMT_BINARY)
        result=run([text_type(self.helper),'--transport'],input=payload,stdout=subprocess.PIPE,
                              stderr=DEVNULL,timeout=40,check=False)
        if result.returncode or len(result.stdout)>LIMIT+65536:
            raise RuntimeError('Native HTTP helper failed (exit %d, output %d bytes)'%(result.returncode,len(result.stdout)))
        return Response(plistlib.loads(result.stdout))
