"""Maintain Safari 7's local view of authenticated, decrypted CloudKit tabs."""
from __future__ import absolute_import, division, print_function, unicode_literals
from compat import text_type, binary_type, integer_types, MissingFile, check_output, DEVNULL, uuid5, log
import argparse
import datetime
import fcntl
import errno
import hashlib
import json
import os
import plists as plistlib
import subprocess
import sys
from compat import urlsplit
import uuid
import zlib
from compat import Path

from client import CloudKit, CloudError, CloudHTTPError, STATE, private_read, private_write, parse, sub, text
from keychain import unarchive
from pcs import decrypt_zone
from events import Channel, post
from publish import snapshot as local_snapshot,publish,device_id
import bookmarks
import history


def current_account(require_safari=True):
    path=Path.home()/'Library/Preferences/MobileMeAccounts.plist'
    if not path.is_file():return None
    data=check_output(['/usr/bin/plutil','-convert','xml1','-o','-',text_type(path)],stderr=DEVNULL)
    accounts=plistlib.loads(data).get('Accounts',[])
    active=[account for account in accounts if account.get('LoggedIn') and (not require_safari or any(service.get('Name')=='BOOKMARKS' and service.get('Enabled') for service in account.get('Services',[])))]
    if len(active)!=1:return None
    return text_type(active[0]['AccountDSID'])


def string_value(value):
    if isinstance(value,binary_type):value=unarchive(value)
    if not isinstance(value,text_type):raise ValueError('Invalid tab string')
    return value


def devices_from_records(records):
    devices={};tabs=[]
    for record in records:
        fields=record['fields']
        if record['type']=='CloudTabDevice':
            name=string_value(fields['DeviceName'])
            modified=fields['LastModified']
            if not name or len(name)>1024 or not isinstance(modified,datetime.datetime):raise ValueError('Invalid cloud tab device')
            devices[record['id']]={'DeviceName':name,'LastModified':modified,'Tabs':[]}
        elif record['type']=='CloudTab':
            url=string_value(fields['URL']);title=string_value(fields['Title'])
            if len(url)>131072 or len(title)>65536:raise ValueError('Cloud tab exceeds length limit')
            if urlsplit(url).scheme.lower() not in ('http','https','ftp'):continue
            owner=fields.get('OwningDevice')
            position=fields.get('Position',b'')
            if not isinstance(position,binary_type):raise ValueError('Invalid cloud tab ordering field')
            inflater=zlib.decompressobj()
            sentinel=b'AQ-END'
            ordering=inflater.decompress(position+sentinel,65537)
            if len(ordering)>65536 or inflater.unused_data!=sentinel:raise ValueError('Invalid tab ordering data')
            sort=json.loads(ordering).get('sortValues',[])
            if not sort or len(sort)>100 or any(not isinstance(i.get('sortValue'),integer_types+(float,)) for i in sort):raise ValueError('Invalid tab ordering values')
            order=tuple(i['sortValue'] for i in sorted(sort,key=lambda item:(item.get('deviceIdentifier',''),item.get('changeID',0))))
            tabs.append((order,record['id'],owner,{'Title':title,'URL':url}))
    for _,_,owner,tab in sorted(tabs):
        if owner in devices:devices[owner]['Tabs'].append(tab)
    namespace=uuid.UUID('e6e8e378-9b29-467c-9769-7dccbe95696d')
    return {text_type(uuid5(namespace,identifier)).upper():device for identifier,device in devices.items() if device['Tabs']}


def save_devices(account,devices):
    output={'Version':1,'Account':account,'Devices':devices,'Updated':datetime.datetime.utcnow()}
    try:
        previous=plistlib.loads(private_read('devices.plist'))
        if previous.get('Account')==account and previous.get('Devices')==devices:return False
    except MissingFile:pass
    encoded=plistlib.dumps(output,fmt=plistlib.FMT_BINARY)
    if len(encoded)>4*1024*1024:raise ValueError('Safari tab cache exceeds size limit')
    private_write('devices.plist',encoded)
    post('org.aquatransport.cloudtabs.updated.%d'%os.getuid())
    return True


def status(state,**extra):
    value={'state':state,'updated':datetime.datetime.utcnow().isoformat()+'Z'}
    value.update(extra)
    private_write('status.json',json.dumps(value,sort_keys=True).encode('utf-8'))


def synchronize(client=None,cached=False,preparing_account=None):
    flags=Path('/usr/share/aquatransport/config/flags.txt')
    if flags.is_file() and 'disable-safari-cloudtabs' in flags.read_text().splitlines():
        save_devices('',{});status('disabled');return None
    account=current_account(preparing_account is None)
    saved=plistlib.loads(private_read('session.plist'))
    if preparing_account is not None and account!=preparing_account:
        raise RuntimeError('The active iCloud account changed during authorization')
    if not account or account!=saved.get('dsid'):
        save_devices('',{});status('account-unavailable');return None
    records=[]
    local=local_snapshot(account) if preparing_account is None else None
    own=device_id(local) if local else None
    if cached:
        cache=plistlib.loads(private_read('zone-0.plist'))
        records=decrypt_zone(cache)
    else:
        if client and (client.account.get('dsid')!=account or client.account.get('tokens')!=saved.get('tokens')):client=None
        client=client or CloudKit()
        zones=client.zones()
        tab_zones=0
        for raw in zones:
            zone=parse(raw)
            identifier=zone.get(1,[None])[0]
            if text(sub(parse(identifier),1),1)!='CloudTabs':continue
            try:items=client.records(identifier)
            except CloudError as error:
                if error.client==4 and error.description=='Zone blocked':continue
                raise
            if preparing_account is None and not local and not any(text(sub(parse(item),3),1) in ('CloudTab','CloudTabDevice') for item in items):continue
            cache={'zone':raw,'records':items}
            decoded=decrypt_zone(cache)
            if local and preparing_account is None:
                own,_=publish(client,raw,items,decoded,local,lambda:current_account()==account)
            records.extend(record for record in decoded if own is None or (record['id']!=own and record['fields'].get('OwningDevice')!=own));tab_zones+=1
        if not tab_zones:
            # An empty, successful container read is a valid cleared tab list.
            records=[]
    devices=devices_from_records(records)
    if preparing_account is not None:
        # Validate access and retain Safari-specific keys before the native
        # checkbox is committed. Publishing the UI cache belongs to normal sync.
        if not tab_zones:
            private_write('safari-service-keys.plist',plistlib.dumps([],fmt=plistlib.FMT_BINARY))
        return client
    changed=save_devices(account,devices)
    count=sum(len(device['Tabs']) for device in devices.values())
    bookmark_state=None
    try:bookmark_state=bookmarks.synchronize(account,lambda:current_account()==account)
    except Exception as error:
        bookmark_state={'state':'waiting-for-native-event','error':type(error).__name__}
        log('Safari bookmark sync stopped: '+type(error).__name__,flush=True)
    history_state=None
    try:history_state=history.synchronize(account,lambda:current_account()==account)
    except Exception as error:
        history_state={'state':'waiting-for-native-event','error':type(error).__name__}
        log('Safari History sync stopped: '+type(error).__name__,flush=True)
    status('ok',devices=len(devices),tabs=count,publishedTabs=len(local['Tabs']) if local else 0,bookmarks=bookmark_state,history=history_state)
    log('Safari cloud tabs synchronized: devices=%d tabs=%d changed=%s'%(len(devices),count,changed),flush=True)
    return client


def synchronize_with_refresh(client=None,cached=False):
    try:return synchronize(client,cached)
    except (CloudError,CloudHTTPError) as error:
        authentication=(isinstance(error,CloudHTTPError) and error.status==401) or (isinstance(error,CloudError) and error.client in (11,12))
        if not authentication:raise
        fresh=CloudKit()
        if current_account()!=fresh.account['dsid']:raise
        # Refresh only in response to an authentication failure during a native
        # sync event. There is no independent credential or refresh timer.
        fresh.renew_credentials()
        return synchronize(fresh,cached)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--listen',action='store_true')
    parser.add_argument('--cached',action='store_true')
    args=parser.parse_args()
    if not STATE.is_dir():return
    lock=os.open(text_type(STATE/'sync.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except (IOError,OSError) as error:
        os.close(lock)
        if error.errno in (errno.EACCES,errno.EAGAIN):return
        raise
    channel=Channel('org.aquatransport.cloudtabs.refresh.%d'%os.getuid()) if args.listen else None
    client=None
    try:
        while True:
            try:client=synchronize_with_refresh(client,args.cached)
            except Exception as error:
                client=None
                status('waiting-for-sync-event',error=type(error).__name__)
                if not args.listen:raise
            if not args.listen:return
            # Block on Safari's existing save/show/change events. Drain queued
            # notifications to coalesce them; no refresh timer or polling loop.
            channel.wait()
    finally:
        if channel:channel.close()
        os.close(lock)


if __name__=='__main__':main()
