"""Foundation plist codec, including binary NSKeyedArchiver UID values."""
from __future__ import absolute_import, division, print_function, unicode_literals
import calendar
import datetime
from compat import binary_type,text_type,integer_types,UTC
from native import call,encoded,decoded
FMT_BINARY=1
FMT_XML=2

class UID(object):
    def __init__(self,data):
        if not isinstance(data,integer_types) or not 0<=data<=0xffffffff:raise ValueError('Invalid plist UID')
        self.data=data
    def __eq__(self,other):return isinstance(other,UID) and self.data==other.data
    def __ne__(self,other):return not self==other


def _tree(value,depth=0):
    if depth>64:raise ValueError('Plist nesting limit')
    if isinstance(value,UID):return ['uid',value.data]
    if isinstance(value,binary_type):return ['data',encoded(value)]
    if isinstance(value,text_type):return ['str',value]
    if isinstance(value,bool):return ['bool',value]
    if isinstance(value,integer_types):return ['int',text_type(value)]
    if isinstance(value,float):return ['real',value]
    if isinstance(value,datetime.datetime):
        if value.tzinfo:value=value.astimezone(UTC).replace(tzinfo=None)
        return ['date',calendar.timegm(value.utctimetuple())+value.microsecond/1000000.0]
    if isinstance(value,(list,tuple)):return ['array',[_tree(item,depth+1) for item in value]]
    if isinstance(value,dict):
        items=[]
        for key,item in value.items():
            if isinstance(key,binary_type):key=key.decode('utf-8')
            if not isinstance(key,text_type):raise ValueError('Invalid plist key')
            items.append([key,_tree(item,depth+1)])
        return ['dict',items]
    raise ValueError('Unsupported plist value')


def _value(node,depth=0):
    if depth>64 or not isinstance(node,list) or len(node)!=2:raise ValueError('Invalid native plist tree')
    tag,value=node
    if tag=='str':return value
    if tag=='data':return decoded(value)
    if tag=='bool':return bool(value)
    if tag=='int':return int(value)
    if tag=='real':return float(value)
    if tag=='uid':return UID(value)
    if tag=='date':return datetime.datetime.utcfromtimestamp(value)
    if tag=='array':return [_value(item,depth+1) for item in value]
    if tag=='dict':return {key:_value(item,depth+1) for key,item in value}
    raise ValueError('Unsupported native plist type')

def loads(data):return _value(call('plist-decode',input=encoded(data))['tree'])
def dumps(value,fmt=FMT_XML,**unused):return decoded(call('plist-encode',tree=_tree(value),xml=fmt==FMT_XML)['data'])
def load(source):return loads(source.read())
def dump(value,target,**kwargs):target.write(dumps(value,**kwargs))
