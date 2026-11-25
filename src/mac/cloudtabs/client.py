"""Read-only CloudKit transport used by the AquaTransport tab-sync worker.

Wire fields follow Apple CloudKit as described in OpenBubbles/rustpush
(revision b3c96c23e1aae78d1229ebaccb12027624f1eaff). This is an independent
implementation using the protobuf wire specification.

Account material and downloaded records stay in the private per-user state
folder. Diagnostics report schema and counts, never tokens, URLs, or tab names.
"""
from __future__ import absolute_import, division, print_function, unicode_literals
from compat import text_type, binary_type, integer_types, as_bytes, byte_at, fullmatch, check_output, gzip_compress, hex_bytes, open_fd
import base64
import datetime
import ctypes
import gzip
import hashlib
import json
import os
import plists as plistlib
import re
import socket
from contextlib import closing
import stat
import struct
import subprocess
import uuid
from compat import Path

from transport import NativeSession
import resource
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

LIMIT = 4 * 1024 * 1024
STATE = Path.home() / 'Library/Application Support/AquaTransport/CloudTabs'
GATEWAY = 'https://gateway.icloud.com'


def varint(n):
    if not isinstance(n, integer_types) or not 0 <= n < 1 << 64:
        raise ValueError('Invalid protobuf integer')
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return as_bytes(out)


def read_varint(data, offset):
    n = 0
    for shift in range(0, 64, 7):
        if offset >= len(data):
            break
        b = byte_at(data,offset)
        offset += 1
        if shift == 63 and b > 1:
            break
        n |= (b & 127) << shift
        if not b & 128:
            return n, offset
    raise ValueError('Truncated or overflowing protobuf integer')


def pb(*items):
    out = bytearray()
    for tag, value in items:
        if value is None:
            continue
        if not 0 < tag < 1 << 29:
            raise ValueError('Invalid protobuf field')
        if isinstance(value, text_type):
            value = value.encode('utf-8')
        if isinstance(value, binary_type):
            out += varint(tag * 8 + 2) + varint(len(value)) + value
        elif isinstance(value, integer_types):
            out += varint(tag * 8) + varint(value & ((1 << 64) - 1))
        else:
            raise TypeError('Unsupported protobuf value')
    if len(out) > LIMIT:
        raise ValueError('Protobuf request exceeds limit')
    return as_bytes(out)


def parse(data):
    if not isinstance(data, binary_type) or len(data) > LIMIT:
        raise ValueError('Invalid protobuf input')
    result = {}
    offset = count = 0
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        field, wire = tag >> 3, tag & 7
        count += 1
        if not 0 < field < 1 << 29 or count > 65536:
            raise ValueError('Invalid protobuf field count or number')
        if wire == 0:
            value, offset = read_varint(data, offset)
        else:
            if wire == 2:
                length, offset = read_varint(data, offset)
            elif wire in (1, 5):
                length = 8 if wire == 1 else 4
            else:
                raise ValueError('Unsupported protobuf wire type')
            if length > len(data) - offset:
                raise ValueError('Truncated protobuf field')
            value = data[offset:offset + length]
            offset += length
        result.setdefault(field, []).append(value)
    return result


def one(message, field, default=None):
    values = message.get(field, [])
    if len(values) > 1:
        raise ValueError('Repeated singular protobuf field')
    return values[0] if values else default


def sub(message, field):
    return parse(one(message, field, b''))


def text(message, field, default=''):
    value = one(message, field)
    return value.decode('utf-8') if isinstance(value, binary_type) else default


def unframe(data):
    offset = 0
    while offset < len(data):
        length, offset = read_varint(data, offset)
        if not length or length > len(data) - offset:
            raise ValueError('Invalid CloudKit frame')
        yield parse(data[offset:offset + length])
        offset += length


def private_read(name):
    if not fullmatch(r'[A-Za-z0-9_.-]{1,128}',name) or name in ('.','..'):
        raise ValueError('Invalid private state file')
    fd = open_fd(text_type(STATE / name), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        info = os.fstat(f.fileno())
        if info.st_uid != os.getuid() or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode):
            raise RuntimeError('Unsafe CloudTabs state permissions')
        data = f.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise RuntimeError('CloudTabs state too large')
        return data


def private_write(name, data):
    if not fullmatch(r'[A-Za-z0-9_.-]{1,128}', name) or name in ('.','..') or len(data) > 32 * LIMIT:
        raise ValueError('Invalid private state file')
    info = STATE.lstat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077 or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError('Unsafe CloudTabs state directory')
    temp = STATE / (name + '-' + uuid.uuid4().hex + '.new')
    fd = os.open(text_type(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.rename(text_type(temp), text_type(STATE / name))
    finally:
        if temp.exists():
            temp.unlink()


def anisette():
    def read(sock, size):
        data = bytearray()
        while len(data) < size:
            part = sock.recv(size - len(data))
            if not part:
                raise RuntimeError('Anisette connection closed')
            data.extend(part)
        return as_bytes(data)
    with closing(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)) as s:
        s.settimeout(100)
        s.connect('/var/run/org.aquatransport.anisette.sock')
        libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        if libc.getpeereid(s.fileno(), ctypes.byref(uid), ctypes.byref(gid)) or uid.value != 0:
            raise RuntimeError('Unexpected device-authentication service owner')
        s.sendall(b'\x01')
        length, = struct.unpack(b'!I', read(s, 4))
        if not 0 < length <= 65536:
            raise RuntimeError('Invalid device-authentication response length')
        result = plistlib.loads(read(s, length))
        if 'error' in result or not isinstance(result.get('headers'), dict):
            raise RuntimeError('Device authentication unavailable')
        raw = result['headers']
        for key in ('device', 'X-Apple-MD-M', 'X-Apple-MD', 'X-Apple-I-MD-RINFO'):
            value = raw.get(key)
            if not isinstance(value, text_type) or not value or len(value) > 16384 or any(ord(c) < 32 for c in value):
                raise RuntimeError('Invalid device-authentication field')
        return {
            'X-Mme-Device-Id': raw['device'],
            'X-Apple-I-MD-LU': base64.b64encode(raw['device'].encode('utf-8')).decode('utf-8'),
            'X-Apple-I-MD-M': raw['X-Apple-MD-M'],
            'X-Apple-I-MD': raw['X-Apple-MD'],
            'X-Apple-I-MD-RINFO': raw['X-Apple-I-MD-RINFO'],
            'X-Apple-I-Client-Time': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'X-Apple-I-TimeZone': 'UTC', 'X-Apple-Locale': 'en_US',
        }


class CloudHTTPError(RuntimeError):
    def __init__(self,status):
        self.status=status
        super(CloudHTTPError,self).__init__('CloudKit HTTP %d'%status)


class CloudError(Exception):
    def __init__(self, result):
        self.client = one(sub(sub(result, 2), 1), 1, 0)
        self.server = one(sub(sub(result, 2), 2), 1, 0)
        self.description = text(sub(result, 2), 4)
        super(CloudError,self).__init__('CloudKit error client=%d server=%d' % (self.client, self.server))


class CloudKit(object):
    def __init__(self, container='com.apple.SafariShared.CloudTabs', bundle='com.apple.SafariBookmarksSyncAgent'):
        if not fullmatch(r'[A-Za-z0-9._-]{1,255}', container + ''):
            raise ValueError('Invalid container')
        self.container, self.bundle = container, bundle
        self.account = plistlib.loads(private_read('session.plist'))
        self.http = NativeSession()
        self.user = None
        hardware = check_output(['/usr/sbin/ioreg', '-rd1', '-c', 'IOPlatformExpertDevice']).decode('utf-8')
        match = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"\r\n]+)"', hardware)
        if not match:
            raise RuntimeError('Hardware serial unavailable')
        self.serial = match.group(1)
        self.model = check_output(['/usr/sbin/sysctl', '-n', 'hw.model']).decode('utf-8').strip()
        self.device = None

    def headers(self):
        fields = anisette()
        self.device = fields['X-Mme-Device-Id']
        result = {k: text_type(v) for k, v in fields.items() if k.lower() != 'x-mme-client-info'}
        result.update({
            'X-MMe-Client-Info': self.account['clientInfo'],
            'X-CloudKit-BundleId': self.bundle,
            'X-CloudKit-ContainerId': self.container,
            'X-CloudKit-Environment': 'Production',
            'X-CloudKit-DatabaseScope': 'Private',
            'User-Agent': 'CloudKit/1970 (19H384)',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-transform',
            'X-Apple-Request-UUID': text_type(uuid.uuid4()).upper(),
            'X-Apple-Operation-Id': hex_bytes(os.urandom(8)).upper(),
            'X-Apple-Operation-Group-Id': hex_bytes(os.urandom(8)).upper(),
        })
        return result

    def post(self, url, headers, data=b'', auth=None):
        if not url.startswith(GATEWAY + '/') and url != 'https://setup.icloud.com/setup/get_account_settings':
            raise ValueError('Unexpected CloudKit authority')
        with self.http.post(url, headers=headers, data=data, auth=auth,
                            timeout=(15, 45), allow_redirects=False, stream=True) as response:
            if response.status_code != 200:
                raise CloudHTTPError(response.status_code)
            chunks, length = [], 0
            for chunk in response.iter_content(65536):
                length += len(chunk)
                if length > LIMIT:
                    raise RuntimeError('CloudKit response exceeds limit')
                chunks.append(chunk)
            return b''.join(chunks)

    def account_settings(self):
        headers=anisette()
        headers.update({'X-MMe-Client-Info':self.account['clientInfo'],
                        'Content-Type':'text/x-xml-plist','Accept':'text/x-xml-plist'})
        data=self.post('https://setup.icloud.com/setup/get_account_settings',headers,
                       auth=(self.account['dsid'],self.account['tokens']['mmeAuthToken']))
        settings=plistlib.loads(data)
        if not isinstance(settings,dict):raise RuntimeError('Invalid account settings')
        return settings

    def renew_credentials(self):
        settings=self.account_settings()
        identifier=settings.get('appleAccountInfo',{}).get('dsPrsID')
        if text_type(identifier)!=self.account['dsid']:
            raise RuntimeError('Credential refresh returned a different account')
        tokens=settings.get('tokens',{})
        for name in ('mmeAuthToken','cloudKitToken'):
            token=tokens.get(name)
            if not isinstance(token,text_type) or not token or len(token)>16384 or any(ord(c)<32 for c in token):
                raise RuntimeError('Credential refresh omitted a usable token')
        refreshed=dict(self.account)
        refreshed['tokens']={name:tokens[name] for name in ('mmeAuthToken','cloudKitToken')}
        private_write('session.plist',plistlib.dumps(refreshed,fmt=plistlib.FMT_BINARY))
        self.account=refreshed

    def initialize(self):
        headers = self.headers()
        headers['Accept'] = 'application/json'
        body = self.post(GATEWAY + '/setup/setup/ck/v1/ckAppInit?container=' + self.container,
                         headers, auth=(self.account['dsid'], self.account['tokens']['mmeAuthToken']))
        reply = json.loads(body)
        self.user = reply.get('cloudKitUserId')
        if not isinstance(self.user, text_type) or not self.user:
            raise RuntimeError('CloudKit omitted the account identifier')

    def perform(self, operation_type, payload, path, flow=None, routing=None):
        if not self.user:
            self.initialize()
        headers = self.headers()
        operation = text_type(uuid.uuid4()).upper()
        header = pb((2, self.container), (3, self.bundle),
                    (7, pb((1, self.device), (2, 2))), (8, '13.6'), (9, self.model),
                    (10, 'com.apple.cloudkit.CloudKitDaemon'), (11, '1970'),
                    (18, '5.0'), (19, 1), (22, self.device), (23, 1), (25, 1),
                    (29, 0), (33, self.serial), (34, 0), (35, 1))
        if flow:
            header += pb((12, flow + '-Private'), (13, 0), (14, 0))
        request = pb((1, header), (2, pb((1, operation), (2, operation_type), (4, 1))), (operation_type, payload))
        body = gzip_compress(varint(len(request)) + request)
        headers.update({
            'Content-Type': 'application/x-protobuf; desc="https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc"; messageType=RequestOperation; delimited=true',
            'Accept': 'application/x-protobuf', 'Content-Encoding': 'gzip',
            'X-CloudKit-UserId': self.user,
            'X-CloudKit-AuthToken': self.account['tokens']['cloudKitToken'],
        })
        if routing:
            headers['X-CloudKit-FunctionRoutingHint'] = routing
        data = self.post(GATEWAY + path, headers, body)
        matched = []
        for response in unframe(data):
            op = sub(response, 2)
            if text(op, 1) != operation:
                raise RuntimeError('Unmatched CloudKit operation identifier')
            result = sub(response, 3)
            if one(result, 1) != 1:
                raise CloudError(result)
            if one(op, 2) != operation_type:
                raise RuntimeError('Unmatched successful CloudKit operation type')
            matched.append(one(response, operation_type,b'' if operation_type==214 else None))
        if len(matched) != 1 or not isinstance(matched[0], binary_type):
            raise RuntimeError('Missing or duplicate CloudKit response')
        return parse(matched[0])

    def zones(self):
        result = self.perform(201, b'', '/ckdatabase/api/client/zone/retrieve', 'CKDFetchRecordZonesOperation')
        return [one(parse(summary), 1) for summary in result.get(1, [])]

    def records(self, zone_identifier):
        records, token = [], None
        for page in range(1000):
            payload = pb((1, token), (2, zone_identifier), (4, 200), (5, 3), (6, pb((1, 0))), (7, 0))
            result = self.perform(213, payload, '/ckdatabase/api/client/record/sync', 'CKDFetchRecordZoneChangesOperation')
            for change in result.get(1, []):
                record = one(parse(change), 5)
                if record is not None:
                    records.append(record)
            next_token = one(result, 2)
            if one(result, 4) == 3:
                return records
            if not next_token or next_token == token:
                raise RuntimeError('CloudKit pagination did not advance')
            token = next_token
        raise RuntimeError('CloudKit pagination limit exceeded')

    def function(self, name, payload):
        if self.container != 'com.apple.security.keychain' or name not in ('fetchChanges', 'fetchViableBottles', 'fetchRecoverableTLKShares'):
            raise ValueError('Unsupported keychain read operation')
        result = self.perform(1101, pb((1, 'Cuttlefish'), (2, name), (3, payload)),
                              '/ckcoderouter/api/client/code/invoke', routing='Cuttlefish/' + name)
        return one(result, 1)

    def save_tab_record(self,record,zone_tag,record_tag,update):
        if self.container!='com.apple.SafariShared.CloudTabs':raise ValueError('Unsupported write container')
        decoded=parse(record)
        if text(sub(decoded,3),1) not in ('CloudTab','CloudTabDevice'):raise ValueError('Unsupported Safari record type')
        payload=pb((1,record),(2,1),(6,3 if update else 2),(7,zone_tag),(8,record_tag))
        result=self.perform(210,payload,'/ckdatabase/api/client/record/save','CKDModifyRecordsOperation')
        saved=one(result,4)
        if saved and one(parse(saved),2):
            actual=sub(parse(saved),2);expected=sub(decoded,2)
            if text(sub(actual,1),1)!=text(sub(expected,1),1):raise RuntimeError('Safari save acknowledgement mismatch')
        return saved or b''

    def delete_tab_record(self,identifier):
        if self.container!='com.apple.SafariShared.CloudTabs':raise ValueError('Unsupported write container')
        self.perform(214,pb((1,identifier)),'/ckdatabase/api/client/record/delete','CKDModifyRecordsOperation')


