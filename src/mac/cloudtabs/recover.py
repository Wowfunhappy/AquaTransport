"""Recover the existing trusted-device key needed for Safari's encrypted data.

Only read/recover operations are sent. This does not reset trust, enroll a new
peer, replace cloud keys, or alter the user's existing keychain records.
"""
from __future__ import absolute_import, division, print_function, unicode_literals
from compat import text_type, binary_type, fullmatch, b64decode, log
import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import plists as plistlib
import re
import struct
import subprocess
from compat import urlsplit
import uuid
from compat import Path

from native import load_public, load_private
from compat import equal, run as run_process
from crypto import pbkdf2

from client import CloudKit, LIMIT, STATE, anisette, parse, pb, one, sub, text, private_read, private_write
from crypto import EscrowSRP, vault_decode, vault_encode, cbc_decrypt, gcm_decrypt, escrow_ec, hkdf384, apple_private, public_bytes


def b64(value):
    if not isinstance(value, text_type) or len(value) > LIMIT:
        raise ValueError('Invalid encoded recovery field')
    return b64decode(value)


class RecoveryCancelled(Exception):
    pass


def prompt(helper, title, message):
    result = run_process([text_type(helper), '--prompt'], input=json.dumps({'title': title, 'message': message}).encode('utf-8'),
                            stdout=subprocess.PIPE, check=False, ui=True)
    if result.returncode==3:
        raise RecoveryCancelled('Key recovery cancelled')
    if result.returncode:
        raise RuntimeError('Key recovery prompt failed')
    if not result.stdout or len(result.stdout) > 1024:
        raise RuntimeError('Invalid recovery passcode length')
    return result.stdout


class Escrow(object):
    def __init__(self, client):
        self.client = client
        self.account = client.account
        if not all(isinstance(self.account.get(k), text_type) and self.account[k] for k in ('user', 'pet', 'adsid')):
            raise RuntimeError('Fresh Apple Account authorization required')
        created = self.account.get('created')
        if not isinstance(created, datetime.datetime) or (datetime.datetime.utcnow() - created).total_seconds() > 240:
            raise RuntimeError('Apple Account authorization expired; authorize again before recovery')
        config = self.account.get('config', {})
        service = config.get('com.apple.Dataclass.KeychainSync')
        if not isinstance(service,dict):
            settings=client.account_settings()
            service=settings['com.apple.mobileme']['com.apple.Dataclass.KeychainSync']
        host = service.get('escrowProxyUrl')
        url = urlsplit(host)
        if url.scheme != 'https' or not fullmatch(r'(p[0-9]+-)?escrowproxy\.icloud\.com', url.hostname or '') or url.port not in (None, 443) or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
            raise RuntimeError('Invalid Apple recovery endpoint')
        self.host = host.rstrip('/')

    def request(self, command, label, transaction, **values):
        paths = {'GETRECORDS': 'get_records', 'SRP_INIT': 'srp_init', 'RECOVER': 'recover'}
        if command not in paths:
            raise ValueError('Unsupported recovery operation')
        headers = anisette()
        headers.update({
            'X-MMe-Client-Info': self.account['clientInfo'].replace('com.apple.AOSKit/282', 'com.apple.AuthKit/1 (com.apple.sbd/638.100.48)'),
            'Content-Type': 'application/x-apple-plst', 'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9', 'X-Apple-I-Device-Type': '1',
            'X-Apple-I-Locale': 'en_US', 'User-Agent': 'com.apple.sbd/638.100.48',
        })
        payload = dict(command=command, label=label, transactionUUID=transaction,
                       userActionLabel='com.apple.sbd: escrow recovery', version=1)
        payload.update(values)
        with self.client.http.post(self.host + '/escrowproxy/api/' + paths[command], headers=headers,
                                   auth=(self.account['user'], self.account['pet']), data=plistlib.dumps(payload),
                                   allow_redirects=False, timeout=(15, 45), stream=True) as response:
            if response.status_code != 200:
                raise RuntimeError('Apple key recovery HTTP %d' % response.status_code)
            chunks, length = [], 0
            for chunk in response.iter_content(65536):
                length += len(chunk)
                if length > LIMIT:
                    raise RuntimeError('Recovery response exceeds limit')
                chunks.append(chunk)
            result = plistlib.loads(b''.join(chunks))
        if not isinstance(result, dict) or result.get('success') is False:
            raise RuntimeError('Apple declined the key-recovery request')
        return result

    def metadata(self):
        return self.request('GETRECORDS', 'com.apple.securebackup.record', text_type(uuid.uuid4()).upper())

    def recover(self, label, passcode):
        srp = EscrowSRP()
        transaction = text_type(uuid.uuid4()).upper()
        start = self.request('SRP_INIT', label, transaction, blob=base64.b64encode(srp.public).decode('utf-8'))
        header, sections = vault_decode(b64(start.get('respBlob')), 24, 3)
        dsid = start.get('dsid')
        if not isinstance(dsid, text_type) or not dsid.isdigit():
            raise RuntimeError('Invalid recovery account identifier')
        proof = srp.challenge(dsid.encode('utf-8'), passcode, sections[1], sections[2])
        club = start.get('clubTypeID')
        header = struct.pack(b'>II', 165, 2 if club == 1 else 0) + header[8:]
        payload = vault_encode(header, [(sections[0], 20), (proof, 0)])
        reply = self.request('RECOVER', label, transaction, blob=base64.b64encode(payload).decode('utf-8'))
        encrypted = b64(reply.get('respBlob'))
        private_write('escrow-recovery-response.bin', encrypted)
        header, sections = vault_decode(encrypted, 40 if club == 1 else 24, 3)
        srp.verify(sections[0])
        version = struct.unpack_from(b'>I', header, 4)[0]
        if version == 0:
            plain = cbc_decrypt(srp.key, sections[1], sections[2])
        elif version == 2:
            plain = gcm_decrypt(srp.key, sections[1], sections[2][:-16], sections[2][-16:])
        else:
            raise RuntimeError('Unsupported escrow encryption version %d' % version)
        header, sections = vault_decode(plain, 16, 6)
        rounds = struct.unpack_from(b'>I', header, 8)[0]
        if not 1 <= rounds <= 1000000 or not 16 <= len(sections[1]) <= 1024:
            raise RuntimeError('Invalid recovery key derivation parameters')
        key = pbkdf2('sha256', passcode, sections[1], rounds, 16)
        recovered = plistlib.loads(cbc_decrypt(key, sections[1][:16], sections[3]))
        entropy = recovered.get('BottledPeerEntropy') if isinstance(recovered, dict) else None
        if not isinstance(entropy, binary_type) or len(entropy) != 72:
            raise RuntimeError('Recovery returned no usable trusted-device entropy')
        return entropy


def peer_info(peer):
    signed = sub(peer, 2)
    info, signature = one(signed, 1), one(signed, 2)
    expected = 'SHA256:' + base64.b64encode(hashlib.sha256(info + signature).digest()).decode('utf-8')
    if not equal(expected, text(peer, 1)):
        raise ValueError('Trusted-peer identity hash mismatch')
    decoded = parse(info)
    key = load_public(one(decoded, 2))
    if key.bits != 384:
        raise ValueError('Unsupported trusted-peer signing key')
    key.verify(signature, b'TPPB.PeerPermanentInfo' + info, 'sha384')
    return decoded


def decode_bottle(outer, entropy, adsid, peers):
    blob = one(outer, 2)
    bottle = parse(blob)
    sign_key = escrow_ec(entropy, adsid, b'Escrow Signing Private Key')
    enc_key = escrow_ec(entropy, adsid, b'Escrow Encryption Private Key')
    for field, key in ((8, sign_key), (9, enc_key)):
        published = load_public(one(bottle, field))
        if not equal(public_bytes(published), public_bytes(key)):
            raise ValueError('Escrow key does not match trusted device')
    sign_key.verify(one(outer, 4), blob, 'sha384')
    peer_id = text(outer, 6)
    if peer_id != text(bottle, 1) or peer_id not in peers:
        raise ValueError('Unknown recovered trusted device')
    info = peer_info(peers[peer_id])
    published_sign = load_public(one(info, 2))
    published_enc = load_public(one(info, 3))
    published_sign.verify(one(outer, 5), blob, 'sha384')
    if not equal(public_bytes(published_sign), public_bytes(load_public(one(bottle, 10)))):
        raise ValueError('Recovered signing identity mismatch')
    if not equal(public_bytes(published_enc), public_bytes(load_public(one(bottle, 11)))):
        raise ValueError('Recovered encryption identity mismatch')
    key = hkdf384(entropy, adsid.encode('utf-8'), b'Escrow Symmetric Key', 32)
    cipher = sub(bottle, 12)
    private = parse(gcm_decrypt(key, one(cipher, 3), one(cipher, 1), one(cipher, 2)))
    signing = apple_private(one(sub(private, 3), 2), 384)
    encryption = apple_private(one(sub(private, 4), 2), 384)
    if not equal(public_bytes(signing), public_bytes(published_sign)) or not equal(public_bytes(encryption), public_bytes(published_enc)):
        raise ValueError('Recovered private identity mismatch')
    return peer_id, signing, encryption


def trust_metadata(client):
    peers, token = {}, None
    for page in range(100):
        raw = client.function('fetchChanges', pb((1, token)))
        changes = sub(parse(raw), 1)
        additions = changes.get(2, [])
        for change in additions:
            raw_peer = one(parse(change), 3)
            if raw_peer:
                peer = parse(raw_peer)
                peer_info(peer)
                peers[text(peer, 1)] = peer
        next_token = text(changes, 1)
        if not additions:
            break
        if not next_token or next_token == token:
            raise RuntimeError('Trusted-peer pagination did not advance')
        token = next_token
    else:
        raise RuntimeError('Trusted-peer pagination limit exceeded')
    raw = client.function('fetchViableBottles', pb((1, 1), (2, b'')))
    private_write('fetchViableBottles.pb', raw)
    return peers, [parse(value) for value in parse(raw).get(1, [])]


def run(helper, authorize=False):
    if authorize:
        run_process([text_type(helper), '--authorize'], check=True)
    client = CloudKit('com.apple.security.keychain', 'com.apple.security.cuttlefish')
    escrow = Escrow(client)
    metadata = escrow.metadata()
    private_write('escrow-records.plist', plistlib.dumps(metadata, fmt=plistlib.FMT_BINARY))
    peers, bottles = trust_metadata(client)
    candidates = []
    for bottle in bottles:
        label = text(bottle, 1)
        for item in metadata.get('metadataList', []):
            if item.get('label') == label:
                meta = plistlib.loads(b64(item.get('metadata')))
                candidates.append((bottle, meta))
    if len(candidates) != 1:
        raise RuntimeError('Expected one matching trusted-device recovery record, found %d' % len(candidates))
    bottle, meta = candidates[0]
    details = meta.get('ClientMetadata', {})
    name = details.get('device_name') or details.get('device_model_class') or 'your trusted Apple device'
    name = text_type(name)[:128]
    passcode = prompt(helper, 'Device Passcode', 'Enter the passcode for %s. Your passcode will not be saved.' % name)
    try:
        entropy = escrow.recover(text(bottle, 1), passcode)
    finally:
        del passcode
    peer_id, signing, encryption = decode_bottle(sub(bottle, 2), entropy, client.account['adsid'], peers)
    del entropy
    identity = {'peer': peer_id, 'signing': signing.private_der,
                'encryption': encryption.private_der}
    private_write('recovered-identity.plist', plistlib.dumps(identity, fmt=plistlib.FMT_BINARY))
    log('Trusted-device encryption identity recovered and verified.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--authorize', action='store_true')
    parser.add_argument('--helper', type=Path, default=Path('/usr/share/aquatransport/cloudtabs/aquatransport-cloudtabs-authorize'))
    args = parser.parse_args()
    run(args.helper.resolve(), args.authorize)
