"""Narrow, dependency-free binding to bundled OpenSSL and Foundation."""
from __future__ import absolute_import, division, print_function, unicode_literals
import base64
import ctypes
import json
import os

_LIBRARY=None

def library():
    global _LIBRARY
    if _LIBRARY is None:
        path=os.path.join(os.path.dirname(os.path.abspath(__file__)),'aquatransport_cloudtabs_native.dylib')
        _LIBRARY=ctypes.CDLL(path)
        _LIBRARY.AQCloudTabsNativeCall.argtypes=[ctypes.c_char_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(ctypes.c_size_t)]
        _LIBRARY.AQCloudTabsNativeCall.restype=ctypes.c_int
        _LIBRARY.AQCloudTabsNativeFree.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
        _LIBRARY.AQCloudTabsNativeFree.restype=None
    return _LIBRARY

def encoded(data):return base64.b64encode(data).decode('ascii')
def decoded(data):return base64.b64decode(data.encode('ascii'))
def call(op,**values):
    values['op']=op
    request=json.dumps(values,ensure_ascii=True,separators=(',',':')).encode('ascii')
    output=ctypes.c_void_p();length=ctypes.c_size_t();lib=library()
    if not lib.AQCloudTabsNativeCall(request,len(request),ctypes.byref(output),ctypes.byref(length)):
        raise ValueError('Native operation failed: '+op)
    try:reply=json.loads(ctypes.string_at(output,length.value).decode('utf-8'))
    finally:lib.AQCloudTabsNativeFree(output,length.value)
    if 'error' in reply:raise ValueError('Native operation failed: '+op)
    return reply

def blob(op,**values):return decoded(call(op,**values)['data'])

class ECKey(object):
    def __init__(self,info):
        self.bits=info['bits'];self.point=decoded(info['point']);self.public_der=decoded(info['public'])
        self.private_der=decoded(info['private']) if 'private' in info else None
    def verify(self,signature,data,digest):
        if not call('ec-verify',key=encoded(self.public_der),input=encoded(data),signature=encoded(signature),digest=digest)['valid']:
            raise ValueError('ECDSA signature verification failed')
    def exchange(self,peer):
        if not self.private_der:raise ValueError('Private EC key required')
        return blob('ec-exchange',key=encoded(self.private_der),peer=encoded(peer.public_der))
    def sign(self,data,digest='sha256'):
        if not self.private_der:raise ValueError('Private EC key required')
        return blob('ec-sign',key=encoded(self.private_der),input=encoded(data),digest=digest)
    def scalar(self):return blob('ec-scalar',key=encoded(self.private_der))

def derive_key(bits,scalar):return ECKey(call('ec-derive',bits=bits,input=encoded(scalar)))
def point_key(bits,point):return ECKey(call('ec-point',bits=bits,input=encoded(point)))
def load_public(data):return ECKey(call('ec-load',key=encoded(data),private=False))
def load_private(data):return ECKey(call('ec-load',key=encoded(data),private=True))
