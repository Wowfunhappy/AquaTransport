"""Foreground setup; retain only the credentials and PCS keys Safari needs."""
from __future__ import absolute_import, division, print_function, unicode_literals
from compat import text_type, MissingFile, run, log
import os
import sys
import stat
import errno
import fcntl
import plists as plistlib
import subprocess
from compat import Path
from client import STATE, private_read, private_write
from recover import run as recover_identity, RecoveryCancelled
from keychain import obtain_pcs_items
from sync import current_account, synchronize
from events import post
from bookmarks import prepare_keys as prepare_bookmark_keys
from history import prepare_keys as prepare_history_keys


TEMPORARY = (
    'account-settings.plist', 'escrow-records.plist', 'escrow-recovery-response.bin',
    'recovered-identity.plist', 'pcs-wrapping-keys.plist', 'recoverable-shares.pb',
    'fetchChanges.pb', 'fetchViableBottles.pb', 'keychain-ProtectedCloudStorage.plist',
    'keychain-Manatee.plist', 'zone-0.plist', 'zone-1.plist', 'zone-2.plist',
    'zone-3.plist', 'zones-index.plist', 'decrypted-tabs.plist', 'tab-zone.plist',
)


def clear_saved_state():
    # Explicit Safari disable/re-enable only. No discovery or migration of old
    # AquaTransport versions, and never remove the inode used for locking.
    names=TEMPORARY+('session.plist','safari-service-keys.plist','bookmarks-service-keys.plist','history-service-keys.plist','devices.plist','status.json','local-tabs.plist','publish-state.plist','local-bookmarks.plist','bookmarks-pending.plist','bookmarks-incoming.plist','bookmarks-ack.plist','local-history.plist','history-pending.plist','history-incoming.plist','history-ack.plist','history-native-diagnostic.plist')
    for name in names:
        try:(STATE/name).unlink()
        except MissingFile:pass
    prefixes=tuple(name+'-' for name in names)+('session-',)
    for item in STATE.iterdir():
        if item.name.endswith('.new') and item.name.startswith(prefixes):
            try:item.unlink()
            except MissingFile:pass


def prepare_service(account,helper):
    clear_saved_state()
    complete=False
    try:
        while True:
            try:
                if not account or current_account(False)!=account:
                    raise RuntimeError('The active iCloud account changed')
                result=run([text_type(helper),'--authorize',account],check=False,ui=True)
                if result.returncode==3:return 3
                if result.returncode:raise RuntimeError('Safari authorization failed')
                if current_account(False)!=account:
                    raise RuntimeError('The active iCloud account changed')
                recover_identity(helper,False)
                obtain_pcs_items()
                if synchronize(preparing_account=account) is None:
                    raise RuntimeError('Safari authorization became unavailable')
                prepare_bookmark_keys()
                prepare_history_keys()
                if current_account(False)!=account:
                    raise RuntimeError('The active iCloud account changed')
                cleanup()
                complete=True
                return 0
            except RecoveryCancelled:
                return 3
            except Exception as error:
                # Do not expose raw server errors or account material in UI.
                log('Safari authorization failed: '+type(error).__name__)
                clear_saved_state()
                if run([text_type(helper),'--failure'],check=False,ui=True).returncode:return 3
    finally:
        if not complete:clear_saved_state()


def service_main(arguments):
    if os.getuid()==0:raise RuntimeError('Safari authorization requires a user session')
    if not STATE.exists():
        if arguments==['--disable']:return 0
        try:os.makedirs(text_type(STATE),0o700)
        except OSError as error:
            if error.errno!=errno.EEXIST:raise
    info=STATE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:
        raise RuntimeError('Unsafe Safari authorization directory')
    lock=os.open(text_type(STATE/'sync.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:
            raise RuntimeError('Unsafe Safari authorization lock')
        # The coordinator unloads the worker first; wait for any final write.
        fcntl.flock(lock,fcntl.LOCK_EX)
        if arguments==['--disable']:
            clear_saved_state()
            post('org.aquatransport.cloudtabs.updated.%d'%os.getuid())
            return 0
        if len(arguments)!=2 or arguments[0]!='--prepare':raise ValueError('Invalid service action')
        helper=Path(__file__).resolve().parent/'aquatransport-cloudtabs-authorize'
        return prepare_service(arguments[1],helper)
    finally:os.close(lock)


def cleanup():
    # Keep the two scoped service credentials used by the worker. The PET,
    # account-recovery authorization and broad keychain keys are temporary.
    saved=plistlib.loads(private_read('session.plist'))
    minimal={key:saved[key] for key in ('dsid','clientInfo','created')}
    minimal['tokens']={key:saved['tokens'][key] for key in ('mmeAuthToken','cloudKitToken')}
    private_write('session.plist',plistlib.dumps(minimal,fmt=plistlib.FMT_BINARY))
    removed=0
    for name in TEMPORARY:
        try:(STATE/name).unlink();removed+=1
        except MissingFile:pass
    return removed


if __name__=='__main__':
    sys.exit(service_main(sys.argv[1:]))
