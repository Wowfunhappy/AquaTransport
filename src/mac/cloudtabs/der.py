"""Small strict DER reader; no class instantiation or unbounded recursion."""
from __future__ import absolute_import, division, print_function, unicode_literals
from compat import binary_type, as_bytes, byte_at
from compat import from_bytes, to_bytes


class Node(object):
    def __init__(self,tag,data,raw,children):
        self.tag=tag;self.data=data;self.raw=raw;self.children=children

    def integer(self):
        if self.tag != 2 or not self.data or len(self.data) > 8 or byte_at(self.data,0) & 128:
            raise ValueError('Invalid unsigned DER integer')
        if len(self.data) > 1 and byte_at(self.data,0) == 0 and not byte_at(self.data,1) & 128:
            raise ValueError('Noncanonical DER integer')
        return from_bytes(self.data)

    def octets(self):
        if self.tag != 4:
            raise ValueError('Expected DER octet string')
        return self.data

    def sequence(self):
        if self.tag not in (0x30, 0x31):
            raise ValueError('Expected DER sequence or set')
        return self.children

    def explicit(self, tag):
        if self.tag != tag or len(self.children) != 1:
            raise ValueError('Invalid explicit DER field')
        return self.children[0]


def encode(tag, data):
    if not 0 <= tag < 256 or tag & 31 == 31 or len(data) > 4*1024*1024:
        raise ValueError('Invalid DER encoding input')
    if len(data) < 128:
        length = as_bytes([len(data)])
    else:
        raw = to_bytes(len(data),(len(data).bit_length()+7)//8)
        length = as_bytes([128+len(raw)]) + raw
    return as_bytes([tag]) + length + data


def decode(data):
    if not isinstance(data, binary_type) or not data or len(data) > 4*1024*1024:
        raise ValueError('Invalid DER input')
    count = [0]
    def read(start, end, depth):
        count[0] += 1
        if depth > 32 or count[0] > 65536 or start+2 > end:
            raise ValueError('DER bounds exceeded')
        tag, length = byte_at(data,start), byte_at(data,start+1)
        if tag & 31 == 31:
            raise ValueError('Unsupported DER high tag')
        offset = start+2
        if length & 128:
            size = length & 127
            if not 1 <= size <= 4 or offset+size > end or byte_at(data,offset) == 0:
                raise ValueError('Invalid DER length')
            length = from_bytes(data[offset:offset+size])
            offset += size
            if length < 128:
                raise ValueError('Noncanonical DER length')
        finish = offset + length
        if finish > end:
            raise ValueError('Truncated DER value')
        children = []
        if tag & 32:
            cursor = offset
            while cursor < finish:
                child, cursor = read(cursor, finish, depth+1)
                children.append(child)
        return Node(tag, data[offset:finish], data[start:finish], tuple(children)), finish
    node, end = read(0, len(data), 0)
    if end != len(data):
        raise ValueError('Trailing DER bytes')
    return node
