"""Cryptographic formats used by CloudKit/CKKS. Never logs keys or plaintext."""
from __future__ import absolute_import, division, print_function, unicode_literals
from compat import as_bytes, byte_at
import hashlib
import hmac
import os
import struct
from native import blob,encoded,derive_key,point_key,load_public,load_private
from compat import from_bytes, to_bytes, equal, unhex


def pbkdf2(digest,password,salt,rounds,length):
    return blob('pbkdf2',digest=digest,password=encoded(password),salt=encoded(salt),rounds=rounds,length=length)

P256 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
N256 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
N384 = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
SRP_N = int('AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73', 16)


def xor(a, b):
    if len(a) != len(b):
        raise ValueError('Mismatched cryptographic input lengths')
    return as_bytes(x ^ y for x, y in zip(bytearray(a),bytearray(b)))


def raw(n):
    return to_bytes(n,max(1,(n.bit_length()+7)//8))


def sha256(*parts):
    return hashlib.sha256(b''.join(parts)).digest()


def cbc_decrypt(key,iv,ciphertext):
    if not ciphertext or len(ciphertext)%16:raise ValueError('Invalid CBC ciphertext length')
    return blob('cbc',key=encoded(key),iv=encoded(iv),input=encoded(ciphertext))


def gcm_decrypt(key,iv,ciphertext,tag,aad=b''):
    return blob('gcm',key=encoded(key),iv=encoded(iv),input=encoded(ciphertext),tag=encoded(tag),aad=encoded(aad))


def gcm_encrypt(key,iv,plaintext,aad=b'',tag_length=12):
    data=blob('gcm-encrypt',key=encoded(key),iv=encoded(iv),input=encoded(plaintext),aad=encoded(aad),tagLength=tag_length)
    return data[tag_length:],data[:tag_length]


def cmac_aes(key,data):return blob('cmac',key=encoded(key),input=encoded(data))

def double(block):
    if len(block) != 16:
        raise ValueError('Invalid SIV block')
    n = from_bytes(block, 'big')
    n = ((n << 1) & ((1 << 128) - 1)) ^ (0x87 if n >> 127 else 0)
    return to_bytes(n,16)


def s2v(key, plaintext, aad):
    if len(aad) > 126:
        raise ValueError('Too many SIV associated-data elements')
    d = cmac_aes(key, as_bytes(16))
    for item in aad:
        d = xor(double(d), cmac_aes(key, item))
    if len(plaintext) >= 16:
        return cmac_aes(key, plaintext[:-16] + xor(plaintext[-16:], d))
    return cmac_aes(key, xor(double(d), (plaintext + b'\x80').ljust(16, b'\0')))


def siv_decrypt(key, ciphertext, aad=()):
    if len(key) not in (32, 48, 64) or len(ciphertext) < 16:
        raise ValueError('Invalid SIV input')
    tag, body = ciphertext[:16], ciphertext[16:]
    counter = bytearray(tag)
    counter[8] &= 127
    counter[12] &= 127
    plaintext=blob('ctr',key=encoded(key[len(key)//2:]),iv=encoded(as_bytes(counter)),input=encoded(body))
    expected = s2v(key[:len(key)//2], plaintext, aad)
    if not equal(tag, expected):
        raise ValueError('SIV authentication failed')
    return plaintext


def kdf(key, label, length=16, context=b''):
    if not 0 < length <= 1024:
        raise ValueError('Invalid KDF length')
    suffix = label + b'\0' + context + struct.pack(b'>I', length * 8)
    out = b''
    for i in range(1, (length + 31)//32 + 1):
        out += hmac.new(key, struct.pack(b'>I', i) + suffix, hashlib.sha256).digest()
    return out[:length]


def x963(secret, info, length):
    return b''.join(sha256(secret, struct.pack(b'>I', i), info)
                    for i in range(1, (length + 31)//32 + 1))[:length]


def hkdf384(entropy, salt, info, length):
    if not 0<length<=255*48:raise ValueError('Invalid HKDF length')
    prk=hmac.new(salt or b'\0'*48,entropy,hashlib.sha384).digest()
    out=b'';part=b''
    for index in range(1,(length+47)//48+1):
        part=hmac.new(prk,part+info+as_bytes([index]),hashlib.sha384).digest();out+=part
    return out[:length]


def escrow_ec(entropy, adsid, label):
    bits = hkdf384(entropy, adsid.encode('utf-8'), label, 56)
    scalar = from_bytes(bits, 'big') % (N384 - 1) + 1
    return derive_key(384,to_bytes(scalar,48))


def public_bytes(key):return key.point


def apple_private(data,curve):
    size=(curve+7)//8
    if len(data)!=1+3*size:raise ValueError('Invalid Apple EC private-key length')
    key=derive_key(curve,data[-size:])
    if not equal(key.point,data[:1+2*size]):raise ValueError('Apple private/public key mismatch')
    return key


def compact_public(data):
    if len(data)!=32:raise ValueError('Invalid compact public key')
    candidate=point_key(256,b'\x03'+data)
    x=from_bytes(candidate.point[1:33]);y=from_bytes(candidate.point[33:65])
    return point_key(256,b'\x04'+to_bytes(x,32)+to_bytes(min(y,P256-y),32))


def compact_private(data):
    if len(data)!=64:raise ValueError('Invalid compact private key')
    key=derive_key(256,data[32:])
    if not equal(key.point,compact_public(data[:32]).point):raise ValueError('Compact private/public key mismatch')
    return key


def rfc6637_unwrap(key, ciphertext):
    if len(ciphertext) < 35 or ciphertext[:2] != b'\x01\x00':
        raise ValueError('Invalid PCS wrapped-key header')
    size = byte_at(ciphertext,34)
    if size != len(ciphertext) - 35 or size < 24 or size % 8:
        raise ValueError('Invalid PCS wrapped-key length')
    secret = key.exchange(compact_public(ciphertext[2:34]))
    params = unhex('082a8648ce3d0301071203010807') + b'Anonymous Sender    ' + b'fingerprint'.ljust(20, b'\0')
    kek = sha256(b'\0\0\0\1', secret, params)[:16]
    plain = blob('unwrap',key=encoded(kek),input=encoded(ciphertext[35:]))
    pad = byte_at(plain,-1)
    if not 1 <= pad <= len(plain)-4 or plain[-pad:] != as_bytes([pad])*pad or byte_at(plain,0) != 1:
        raise ValueError('Invalid PCS key padding')
    secret = plain[1:-pad-2]
    if (sum(bytearray(secret)) & 65535) != from_bytes(plain[-pad-2:-pad], 'big'):
        raise ValueError('Invalid PCS key checksum')
    return secret


def rfc6637_wrap(key,secret):
    if len(secret)!=16:raise ValueError('Invalid PCS master key length')
    while True:
        scalar=from_bytes(os.urandom(32))
        if 0<scalar<N256:break
    ephemeral=derive_key(256,to_bytes(scalar,32))
    shared=ephemeral.exchange(key)
    params=unhex('082a8648ce3d0301071203010807')+b'Anonymous Sender    '+b'fingerprint'.ljust(20,b'\0')
    kek=sha256(b'\0\0\0\1',shared,params)[:16]
    plain=b'\x01'+secret+struct.pack(b'>H',sum(bytearray(secret))&65535)
    padding=40-len(plain);plain+=as_bytes([padding])*padding
    wrapped=blob('wrap',key=encoded(kek),input=encoded(plain))
    return b'\x01\x00'+ephemeral.point[1:33]+as_bytes([len(wrapped)])+wrapped


class EscrowSRP(object):
    def __init__(self, private=None):
        self.a = from_bytes(private or os.urandom(32), 'big')
        if not self.a:
            raise ValueError('Invalid SRP secret')
        self.public = raw(pow(2, self.a, SRP_N))
        self.used = False

    def challenge(self, username, password, salt, server):
        if self.used or not 1 <= len(salt) <= 1024 or not 1 <= len(server) <= 256:
            raise ValueError('Invalid or repeated SRP challenge')
        self.used = True
        b = from_bytes(server, 'big')
        if not 0 < b < SRP_N:
            raise ValueError('Invalid SRP server value')
        b_bytes = raw(b)
        n = raw(SRP_N)
        g = to_bytes(2,256)
        u = from_bytes(sha256(self.public, b_bytes), 'big')
        k = from_bytes(sha256(n, g), 'big')
        x = from_bytes(sha256(salt, sha256(username, b':', password)), 'big')
        base = (b - k * pow(2, x, SRP_N)) % SRP_N
        if not base or not u:
            raise ValueError('Degenerate SRP exchange')
        shared = pow(base, self.a + u*x, SRP_N)
        self.key = sha256(raw(shared))
        proof = sha256(xor(sha256(n), sha256(g)), sha256(username), salt, self.public, b_bytes, self.key)
        self.server_proof = sha256(self.public, proof, self.key)
        return proof

    def verify(self, proof):
        if not self.used or not equal(proof, self.server_proof):
            raise ValueError('Escrow server proof did not verify')


def vault_decode(data, header_length, section_count):
    base = 4 + header_length + 4*(section_count+1)
    if len(data) < base or len(data) > 4*1024*1024 or struct.unpack_from(b'>I', data)[0] != len(data):
        raise ValueError('Invalid recovery frame length')
    offsets = struct.unpack_from(b'>' + b'I'*(section_count+1), data, 4+header_length)
    if offsets[0] or list(offsets) != sorted(offsets) or offsets[-1] != len(data)-base:
        raise ValueError('Invalid recovery frame offsets')
    sections = []
    for left, right in zip(offsets, offsets[1:]):
        if right-left < 4:
            raise ValueError('Invalid recovery section')
        size = struct.unpack_from(b'>I', data, base+left)[0]
        if size > right-left-4:
            raise ValueError('Truncated recovery section')
        sections.append(data[base+left+4:base+left+4+size])
    return data[4:4+header_length], sections


def vault_encode(header, sections):
    offsets, body = [], bytearray()
    for value, minimum in sections:
        offsets.append(len(body))
        section = struct.pack(b'>I', len(value)) + value
        if minimum and len(section) > minimum:
            raise ValueError('Recovery section exceeds fixed size')
        body += section.ljust(minimum, b'\0')
    offsets.append(len(body))
    out = header + struct.pack(b'>' + b'I'*len(offsets), *offsets) + as_bytes(body)
    return struct.pack(b'>I', len(out)+4) + out
