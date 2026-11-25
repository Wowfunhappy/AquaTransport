"""Account-scoped, three-way merge of native Safari bookmark trees."""
from __future__ import absolute_import,division,print_function,unicode_literals
import copy,uuid,math
from compat import text_type,integer_types,uuid5

FIELDS=('Kind','Title','URL','DateAdded','DateLastViewed','PreviewText','Parent')
NAMESPACE=uuid.UUID('c8582fa5-8565-408a-87aa-5cfb7a4e0289')

def validate(items):
    if not isinstance(items,dict) or not items or len(items)>20000:raise ValueError('Invalid bookmark tree size')
    roles={}
    for identifier,node in items.items():
        if not isinstance(identifier,text_type) or not identifier or len(identifier)>256 or not isinstance(node,dict):raise ValueError('Invalid bookmark identifier')
        if node.get('Kind') not in ('folder','leaf'):raise ValueError('Invalid bookmark kind')
        if not isinstance(node.get('Title'),text_type) or len(node['Title'])>65536:raise ValueError('Invalid bookmark title')
        if not isinstance(node.get('Index'),integer_types) or not 0<=node['Index']<=20000:raise ValueError('Invalid bookmark index')
        parent=node.get('Parent')
        if not isinstance(parent,text_type):raise ValueError('Invalid bookmark parent')
        if parent and (parent not in items or items[parent].get('Kind')!='folder'):raise ValueError('Missing bookmark parent')
        if node['Kind']=='leaf' and (not isinstance(node.get('URL'),text_type) or len(node['URL'])>131072):raise ValueError('Invalid bookmark URL')
        for name in ('DateAdded','DateLastViewed'):
            if name in node and (not isinstance(node[name],integer_types+(float,)) or not -1e12<node[name]<1e12):raise ValueError('Invalid Reading List date')
        if 'PreviewText' in node and (not isinstance(node['PreviewText'],text_type) or len(node['PreviewText'])>262144):raise ValueError('Invalid Reading List preview')
        role=node.get('Role')
        if role:
            if role not in ('Root','BookmarksBar','BookmarksMenu','ReadingList') or role in roles or node['Kind']!='folder':raise ValueError('Invalid standard bookmark folder')
            roles[role]=identifier
        if not parent and role!='Root':raise ValueError('Unrooted bookmark')
        seen=set();cursor=identifier
        while cursor:
            if cursor in seen or len(seen)>32:raise ValueError('Bookmark hierarchy cycle or depth limit')
            seen.add(cursor);cursor=items[cursor]['Parent']
    if 'Root' not in roles:raise ValueError('Missing bookmark root')
    for role,identifier in roles.items():
        if items[identifier]['Title']!=role or (role!='Root' and items[identifier]['Parent']!=roles['Root']):raise ValueError('Invalid standard bookmark folder location')
    return roles

def from_snapshot(snapshot,account):
    if not isinstance(snapshot,dict) or snapshot.get('Version')!=1 or snapshot.get('Account')!=account:raise ValueError('Bookmark snapshot account mismatch')
    if not isinstance(snapshot.get('Token'),text_type) or len(snapshot['Token'])!=64:raise ValueError('Invalid bookmark snapshot token')
    if not isinstance(snapshot.get('DeviceID'),text_type) or not snapshot['DeviceID']:raise ValueError('Invalid bookmark source identity')
    nodes=snapshot.get('Items')
    if not isinstance(nodes,list):raise ValueError('Invalid native bookmarks')
    result={}
    for value in nodes:
        if not isinstance(value,dict):raise ValueError('Invalid native bookmark')
        node=dict(value);identifier=node.pop('ID',None)
        if identifier in result:raise ValueError('Duplicate native bookmark')
        result[identifier]=node
    validate(result);normalize_root_order(result);return result

def normalize_root_order(items):
    root=next(name for name,node in items.items() if node.get('Role')=='Root')
    ranks={'BookmarksBar':0,'BookmarksMenu':1,'ReadingList':2}
    children=sorted((name for name,node in items.items() if node['Parent']==root),key=lambda name:(ranks.get(items[name].get('Role'),3),items[name]['Index'],name))
    for index,name in enumerate(children):items[name]['Index']=index

def depth(items,identifier):
    result=0
    while items[identifier]['Parent']:
        result+=1;identifier=items[identifier]['Parent']
    return result

def identity(node):return node['Kind'],node['Title'],node.get('URL','')

def map_native(local,remote,state,device):
    mapping=dict(state.get('Map',{}));claimed=set(mapping.values());roles=validate(remote)
    for name,node in local.items():
        if node.get('Role'):
            role=node['Role']
            if role not in roles:raise ValueError('Cloud bookmark standard folder is missing')
            # Safari can recreate its in-memory root identity on launch. Bind
            # standard roles to the current native objects, not stale aliases.
            for previous,target in list(mapping.items()):
                if target==roles[role] and previous!=name:
                    if previous in local:raise ValueError('Conflicting native standard folder identity')
                    del mapping[previous]
            mapping[name]=roles[role];claimed.add(roles[role])
    for name in sorted(local,key=lambda key:(depth(local,key),local[key]['Index'],key)):
        node=local[name]
        if name in mapping:continue
        parent=mapping.get(node['Parent'],'')
        reading=parent==roles.get('ReadingList') and node['Kind']=='leaf'
        candidates=[key for key,value in remote.items() if key not in claimed and not value.get('Role') and value['Parent']==parent and
                    (identity(value)==identity(node) or (reading and value['Kind']=='leaf' and value.get('URL')==node.get('URL')))]
        same_identity=name in remote and remote[name]['Kind']==node['Kind'] and (node['Kind']=='folder' or remote[name].get('URL')==node.get('URL'))
        if same_identity and name not in claimed:target=name
        elif candidates:target=min(candidates,key=lambda key:(remote[key]['Index'],key))
        elif name not in remote and name not in claimed:target=name
        else:target=text_type(uuid5(NAMESPACE,device+'\0'+name)).upper()
        if target in claimed:raise ValueError('Bookmark mapping collision')
        mapping[name]=target;claimed.add(target)
    if len(set(mapping.values()))!=len(mapping):raise ValueError('Ambiguous bookmark mapping')
    canonical={}
    for name,value in local.items():
        node=dict(value);node['Parent']=mapping[value['Parent']] if value['Parent'] else ''
        canonical[mapping[name]]=node
    validate(canonical);return canonical,mapping

def changed(node,base):return any(node.get(name)!=base.get(name) for name in FIELDS)

def sequence(items,parent,allowed):
    return sorted((key for key,node in items.items() if node['Parent']==parent and key in allowed),key=lambda key:(items[key]['Index'],key))

def add_missing(primary,secondary):
    result=list(primary)
    for index,name in enumerate(secondary):
        if name in result:continue
        before=next((candidate for candidate in reversed(secondary[:index]) if candidate in result),None)
        after=next((candidate for candidate in secondary[index+1:] if candidate in result),None)
        position=result.index(before)+1 if before is not None else result.index(after) if after is not None else len(result)
        result.insert(position,name)
    return result

def merge(base,local,remote):
    validate(local);validate(remote)
    if base:validate(base)
    result={}
    for name in set(local)|set(remote):
        l=local.get(name);r=remote.get(name);b=base.get(name)
        if l and r:
            if l['Kind']!=r['Kind']:raise ValueError('Bookmark type changed without a new identity')
            node=dict(r)
            if b:
                for field in FIELDS:
                    if l.get(field)!=b.get(field):
                        if field=='PreviewText' and r.get('UserPreview'):continue
                        if field in l:node[field]=l[field]
                        else:node.pop(field,None)
            result[name]=node
        elif l:
            if not b or l.get('Role') or changed(l,b):result[name]=dict(l)
        elif r:
            if not b or r.get('Role') or changed(r,b):result[name]=dict(r)
    # A concurrent addition/edit inside a deleted folder preserves its path.
    for name in list(result):
        cursor=result[name]['Parent'];seen=set()
        while cursor and cursor not in result:
            if cursor in seen or len(seen)>32:raise ValueError('Invalid preserved bookmark hierarchy')
            seen.add(cursor);parent=local.get(cursor) or remote.get(cursor) or base.get(cursor)
            if not parent or parent['Kind']!='folder':raise ValueError('Missing preserved bookmark folder')
            result[cursor]=dict(parent);cursor=parent['Parent']
    parents=set(node['Parent'] for node in result.values())
    for parent in parents:
        allowed=set(key for key,node in result.items() if node['Parent']==parent)
        ls=sequence(local,parent,allowed);rs=sequence(remote,parent,allowed);bs=sequence(base,parent,allowed)
        common=set(ls)&set(bs)
        reordered=[i for i in ls if i in common]!=[i for i in bs if i in common]
        ordered=add_missing(ls,rs) if reordered else add_missing(rs,ls)
        ordered=add_missing(ordered,sorted(allowed))
        for index,name in enumerate(ordered):result[name]['Index']=index
    validate(result);normalize_root_order(result);return result

def to_native(merged,mapping,local,device):
    reverse={v:k for k,v in mapping.items()};used=set(local)|set(mapping)
    for name in merged:
        if name in reverse:continue
        try:uuid.UUID(name);candidate=name
        except (ValueError,AttributeError):candidate=text_type(uuid5(NAMESPACE,device+'\0native\0'+name)).upper()
        if candidate in used:candidate=text_type(uuid5(NAMESPACE,device+'\0native\0'+name)).upper()
        if candidate in used:raise ValueError('Native bookmark identity collision')
        mapping[candidate]=name;reverse[name]=candidate;used.add(candidate)
    result=[]
    for name in sorted(merged,key=lambda key:(depth(merged,key),merged[key]['Index'],key)):
        node={key:value for key,value in merged[name].items() if key in FIELDS+('Index','Role')}
        node['ID']=reverse[name];node['Parent']=reverse[node['Parent']] if node['Parent'] else ''
        result.append(node)
    return result
