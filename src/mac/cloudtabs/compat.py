"""Small system-Python compatibility helpers; no external packages."""
from __future__ import absolute_import, division, print_function, unicode_literals
import base64
import binascii
import datetime
import errno
import gzip
import io
import os
import pwd
import re
import subprocess
import sys
import threading
import uuid

PY2=sys.version_info[0]==2
if PY2:
    text_type=unicode
    binary_type=str
    integer_types=(int,long)
else:
    text_type=str
    binary_type=bytes
    integer_types=(int,)


def as_bytes(value):
    if isinstance(value,binary_type):return value
    if isinstance(value,bytearray):return buffer(value)[:] if PY2 else bytes(value)
    return as_bytes(bytearray(value))
def byte_at(value,index):
    result=value[index]
    return ord(result) if isinstance(result,binary_type) else result

def from_bytes(value,order='big'):
    if order=='little':value=value[::-1]
    return int(binascii.hexlify(value) or b'0',16)
def to_bytes(value,length=None,order='big'):
    if value<0:raise ValueError('Negative byte integer')
    encoded=('%x'%value)
    if len(encoded)%2:encoded='0'+encoded
    data=binascii.unhexlify(encoded.encode('ascii'))
    if length is not None:
        if len(data)>length:raise ValueError('Integer exceeds byte width')
        data=data.rjust(length,b'\0')
    return data[::-1] if order=='little' else data

def unhex(value):return binascii.unhexlify(value)
def hex_bytes(value):return binascii.hexlify(value).decode('ascii')
def equal(a,b):
    from native import call,encoded
    if isinstance(a,text_type):a=a.encode('utf-8')
    if isinstance(b,text_type):b=b.encode('utf-8')
    return call('equal',a=encoded(a),b=encoded(b))['valid']
def b64decode(value):
    if isinstance(value,text_type):value=value.encode('ascii')
    if not isinstance(value,binary_type) or len(value)%4 or not fullmatch(b'[A-Za-z0-9+/]*={0,2}',value):
        raise ValueError('Invalid base64 field')
    result=base64.b64decode(value)
    if base64.b64encode(result)!=value:raise ValueError('Noncanonical base64 field')
    return result

def fullmatch(pattern,value):
    match=re.match(pattern,value)
    return match if match and match.end()==len(value) else None

def gzip_compress(value):
    output=io.BytesIO()
    writer=gzip.GzipFile(fileobj=output,mode='wb',mtime=0)
    try:writer.write(value)
    finally:writer.close()
    return output.getvalue()

def uuid5(namespace,value):
    return uuid.uuid5(namespace,value.encode('utf-8') if PY2 and isinstance(value,text_type) else value)

class _UTC(datetime.tzinfo):
    def utcoffset(self,dt):return datetime.timedelta(0)
    def dst(self,dt):return datetime.timedelta(0)
    def tzname(self,dt):return 'UTC'
UTC=_UTC()

class MissingFile(IOError):pass

def open_fd(path,flags,mode=0o777):
    try:return os.open(path,flags,mode)
    except OSError as error:
        if error.errno==errno.ENOENT:raise MissingFile(error.errno,error.strerror)
        raise

class Path(object):
    def __init__(self,path):self.path=path.path if isinstance(path,Path) else path
    def __str__(self):return self.path.encode(sys.getfilesystemencoding() or 'utf-8') if PY2 and isinstance(self.path,text_type) else self.path
    def __unicode__(self):return self.path if isinstance(self.path,text_type) else self.path.decode(sys.getfilesystemencoding() or 'utf-8')
    def __truediv__(self,part):return Path(os.path.join(self.path,part.path if isinstance(part,Path) else part))
    __div__=__truediv__
    @classmethod
    def home(cls):
        home=pwd.getpwuid(os.getuid()).pw_dir
        if PY2 and isinstance(home,binary_type):home=home.decode(sys.getfilesystemencoding() or 'utf-8')
        return cls(home)
    @property
    def parent(self):return Path(os.path.dirname(self.path))
    @property
    def name(self):return os.path.basename(self.path)
    def resolve(self):return Path(os.path.realpath(self.path))
    def is_file(self):return os.path.isfile(self.path)
    def is_dir(self):return os.path.isdir(self.path)
    def exists(self):return os.path.exists(self.path)
    def lstat(self):return os.lstat(self.path)
    def stat(self):return os.stat(self.path)
    def read_text(self):
        with io.open(self.path,'r',encoding='utf-8') as source:return source.read()
    def iterdir(self):return (self/name for name in os.listdir(self.path))
    def unlink(self):
        try:os.unlink(self.path)
        except OSError as error:
            if error.errno!=errno.ENOENT:raise
            raise MissingFile(error.errno,error.strerror)

DEVNULL=open(os.devnull,'wb')
PIPE=subprocess.PIPE
class Result(object):
    def __init__(self,code,stdout,stderr):self.returncode=code;self.stdout=stdout;self.stderr=stderr

def run(args,input=None,stdout=None,stderr=None,check=False,timeout=None,ui=False):
    inherited=ui and os.environ.get('AQ_CLOUDTABS_UI_FD')=='198'
    if inherited:
        import fcntl,stat
        if not stat.S_ISSOCK(os.fstat(198).st_mode):raise RuntimeError('Invalid authorization UI channel')
        # Python 2 has no pass_fds. Preserve only the explicitly inherited UI
        # socket; every other existing descriptor closes across the exec.
        for entry in os.listdir('/dev/fd'):
            descriptor=int(entry)
            if descriptor<3 or descriptor==198:continue
            try:fcntl.fcntl(descriptor,fcntl.F_SETFD,fcntl.fcntl(descriptor,fcntl.F_GETFD)|fcntl.FD_CLOEXEC)
            except IOError:pass
        fcntl.fcntl(198,fcntl.F_SETFD,0)
    process=subprocess.Popen([a.encode(sys.getfilesystemencoding() or 'utf-8') if PY2 and isinstance(a,text_type) else str(a) for a in args],stdin=PIPE if input is not None else None,stdout=stdout,stderr=stderr,close_fds=not inherited)
    expired=[]
    def expire():
        if process.poll() is None:
            expired.append(True)
            try:process.kill()
            except OSError:pass
    # A one-shot subprocess deadline, not a refresh trigger or retry schedule.
    timer=threading.Timer(timeout,expire) if timeout is not None else None
    if timer:timer.daemon=True;timer.start()
    try:out,err=process.communicate(input)
    except BaseException:
        if process.poll() is None:
            try:process.kill()
            except OSError:pass
        process.communicate()
        raise
    finally:
        if timer:timer.cancel()
    if expired:raise RuntimeError('Native helper timed out')
    if check and process.returncode:raise subprocess.CalledProcessError(process.returncode,args,out)
    return Result(process.returncode,out,err)

def check_output(args,stderr=None):return run(args,stdout=PIPE,stderr=stderr,check=True).stdout

try:
    from urllib.parse import urlsplit
except ImportError:
    from urlparse import urlsplit

def log(*args,**kwargs):
    message=kwargs.get('sep',' ').join(text_type(a) for a in args)+kwargs.get('end','\n')
    sys.stdout.write(message.encode('utf-8') if PY2 else message)
    sys.stdout.flush()
