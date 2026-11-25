/* Reading List and bookmarks stay in Safari's native model and file locker. */
#include <CommonCrypto/CommonDigest.h>
static BOOL AQBookmarksStarted,AQBookmarksApplying,AQBookmarksCapturing,AQBookmarksReceiving,AQBookmarksQueued,AQBookmarksNeedRefresh;
static id AQBookGet(id object,const char *name) {SEL selector=sel_registerName(name);return [object respondsToSelector:selector]?((id(*)(id,SEL))objc_msgSend)(object,selector):nil;}
static id AQBookController(void) {return AQBookGet(NSClassFromString(@"BookmarksController"),"sharedController");}
static BOOL AQBookPrivateFile(NSString *path) {struct stat s;return !lstat(path.fileSystemRepresentation,&s) && S_ISREG(s.st_mode) && s.st_uid==getuid() && !(s.st_mode&077) && s.st_size>0 && s.st_size<=4*1024*1024;}
static NSString *AQBookAccount(void) {
    if(tf_flag("disable-safari-cloudtabs"))return nil;
    NSString *account=AQCurrentAccount(),*directory=AQCloudTabsStateDirectory();
    if(!account || !AQBookPrivateFile([directory stringByAppendingPathComponent:@"bookmarks-service-keys.plist"]))return nil;
    NSString *session=[directory stringByAppendingPathComponent:@"session.plist"];
    return AQBookPrivateFile(session) && [[[[NSDictionary dictionaryWithContentsOfFile:session] objectForKey:@"dsid"] description] isEqual:account]?account:nil;
}
static BOOL AQBookWriteData(NSString *name,NSData *data) {
    NSString *directory=AQCloudTabsStateDirectory();struct stat info;
    if(lstat(directory.fileSystemRepresentation,&info) || !S_ISDIR(info.st_mode) || info.st_uid!=getuid() || (info.st_mode&077))return NO;
    if(!data.length || data.length>4*1024*1024)return NO;
    NSString *temporary=[directory stringByAppendingPathComponent:[NSString stringWithFormat:@"%@-%@.new",name,[[NSUUID UUID] UUIDString]]];
    int fd=open(temporary.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(fd<0)return NO;
    const char *p=data.bytes;size_t left=data.length;BOOL ok=YES;
    while(left) {ssize_t n=write(fd,p,left);if(n<0 && errno==EINTR)continue;if(n<=0){ok=NO;break;}p+=n;left-=n;}
    if(fsync(fd))ok=NO;close(fd);
    if(ok)ok=!rename(temporary.fileSystemRepresentation,[[directory stringByAppendingPathComponent:name] fileSystemRepresentation]);
    if(!ok)unlink(temporary.fileSystemRepresentation);return ok;
}
static BOOL AQBookWrite(NSString *name,NSDictionary *value) {
    return AQBookWriteData(name,[NSPropertyListSerialization dataWithPropertyList:value format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL]);
}
static NSDictionary *AQBookRead(NSString *name) {
    NSString *path=[AQCloudTabsStateDirectory() stringByAppendingPathComponent:name];
    if(!AQBookPrivateFile(path))return nil;
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW);if(fd<0)return nil;
    struct stat s;BOOL valid=!fstat(fd,&s)&&S_ISREG(s.st_mode)&&s.st_uid==getuid()&&!(s.st_mode&077)&&s.st_size>0&&s.st_size<=4*1024*1024;
    NSMutableData *data=valid?[NSMutableData dataWithLength:s.st_size]:nil;char *p=data.mutableBytes;size_t left=data.length;
    while(valid && left) {ssize_t n=read(fd,p,left);if(n<0&&errno==EINTR)continue;if(n<=0){valid=NO;break;}p+=n;left-=n;}
    close(fd);id value=valid?[NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL]:nil;
    return [value isKindOfClass:[NSDictionary class]]?value:nil;
}
static NSString *AQBookDigest(NSString *account,NSArray *items) {
    NSMutableArray *ordered=[NSMutableArray array];NSArray *keys=@[@"ID",@"Parent",@"Kind",@"Role",@"Index",@"Title",@"URL",@"DateAdded",@"DateLastViewed",@"PreviewText"];
    NSString *root=nil;for(NSDictionary *item in items)if([[item objectForKey:@"Role"] isEqual:@"Root"]){root=[item objectForKey:@"ID"];break;}
    NSArray *sorted=[items sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a,NSDictionary *b){NSString *x=[[a objectForKey:@"ID"] isEqual:root]?@"@Root":[a objectForKey:@"ID"],*y=[[b objectForKey:@"ID"] isEqual:root]?@"@Root":[b objectForKey:@"ID"];return [x compare:y];}];
    for(NSDictionary *item in sorted) {NSMutableArray *row=[NSMutableArray array];for(NSString *key in keys){id value=[item objectForKey:key];if(root && [value isEqual:root] && [@[@"ID",@"Parent"] containsObject:key])value=@"@Root";[row addObject:value?:[NSNull null]];}[ordered addObject:row];}
    NSData *data=[NSJSONSerialization dataWithJSONObject:@[account,ordered] options:0 error:NULL];if(!data)return nil;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256(data.bytes,(CC_LONG)data.length,digest);
    NSMutableString *result=[NSMutableString string];for(unsigned i=0;i<sizeof digest;i++)[result appendFormat:@"%02x",digest[i]];return result;
}
static BOOL AQBookFlatten(NSDictionary *node,NSString *parent,NSUInteger index,NSDictionary *roles,NSMutableArray *items,NSMutableSet *seen,unsigned depth) {
    if(depth>32 || items.count>=20000 || ![node isKindOfClass:[NSDictionary class]])return NO;
    NSString *type=[node objectForKey:@"WebBookmarkType"];
    if(![@[@"WebBookmarkTypeList",@"WebBookmarkTypeLeaf"] containsObject:type?:@""])return YES;
    NSString *identifier=[node objectForKey:@"WebBookmarkUUID"];if(![identifier isKindOfClass:[NSString class]] || !identifier.length || identifier.length>128 || [seen containsObject:identifier])return NO;
    [seen addObject:identifier];BOOL folder=[type isEqual:@"WebBookmarkTypeList"];
    NSString *role=[roles objectForKey:identifier];
    if(depth==1 && [[node objectForKey:@"Title"] isEqual:@"com.apple.ReadingList"])role=@"ReadingList";
    id uri=[node objectForKey:@"URIDictionary"];if(uri && ![uri isKindOfClass:[NSDictionary class]])return NO;
    id title=folder?[node objectForKey:@"Title"]:[uri objectForKey:@"title"];
    if(!title)title=@"";if(role)title=role;
    if(![title isKindOfClass:[NSString class]] || [title length]>65536)return NO;
    NSMutableDictionary *item=[NSMutableDictionary dictionaryWithDictionary:@{@"ID":identifier,@"Parent":parent,@"Kind":folder?@"folder":@"leaf",@"Title":title,@"Index":@(index)}];
    if(role)[item setObject:role forKey:@"Role"];
    if(!folder) {
        id url=[node objectForKey:@"URLString"];if(![url isKindOfClass:[NSString class]] || [url length]>131072)return NO;[item setObject:url forKey:@"URL"];
        id reading=[node objectForKey:@"ReadingList"];
        if(reading && ![reading isKindOfClass:[NSDictionary class]])return NO;
        for(NSString *key in @[@"DateAdded",@"DateLastViewed"]) {
            id date=[reading objectForKey:key];if(!date)continue;
            if(![date isKindOfClass:[NSDate class]] || !isfinite([date timeIntervalSinceReferenceDate]))return NO;
            [item setObject:@([date timeIntervalSinceReferenceDate]) forKey:key];
        }
        id preview=[reading objectForKey:@"PreviewText"];if(preview) {if(![preview isKindOfClass:[NSString class]] || [preview length]>262144)return NO;[item setObject:preview forKey:@"PreviewText"];}
    }
    [items addObject:item];id children=[node objectForKey:@"Children"];
    if(children && (![children isKindOfClass:[NSArray class]] || !folder))return NO;
    NSUInteger order=0;
    for(NSDictionary *child in children) {
        if(![child isKindOfClass:[NSDictionary class]])return NO;
        BOOL supported=[@[@"WebBookmarkTypeList",@"WebBookmarkTypeLeaf"] containsObject:[child objectForKey:@"WebBookmarkType"]?:@""];
        if(!AQBookFlatten(child,identifier,order,roles,items,seen,depth+1))return NO;
        if(supported)order++;
    }
    return YES;
}
static NSDictionary *AQBookSnapshot(void) {
    NSString *account=AQBookAccount();if(!account)return nil;
    id controller=AQBookController(),group=AQBookGet(controller,"allBookmarks"),root=AQBookGet(group,"topBookmark");
    id dictionary=AQBookGet(root,"dictionaryRepresentation");if(![dictionary isKindOfClass:[NSDictionary class]])return nil;
    NSMutableDictionary *roles=[NSMutableDictionary dictionary];
    for(NSArray *entry in @[@[@"Root",root?:[NSNull null]],@[@"BookmarksBar",AQBookGet(controller,"bookmarksBarCollection")?:[NSNull null]],@[@"BookmarksMenu",AQBookGet(controller,"bookmarksMenuCollection")?:[NSNull null]]]) {
        id identifier=AQBookGet([entry objectAtIndex:1],"UUID");if(identifier)[roles setObject:[entry objectAtIndex:0] forKey:identifier];
    }
    NSMutableArray *items=[NSMutableArray array];
    if(!AQBookFlatten(dictionary,@"",0,roles,items,[NSMutableSet set],0) || !items.count)return nil;
    NSString *rootID=AQBookGet(root,"UUID");NSMutableArray *rootChildren=[NSMutableArray array];NSDictionary *ranks=@{@"BookmarksBar":@0,@"BookmarksMenu":@1,@"ReadingList":@2};
    for(NSDictionary *item in items)if([[item objectForKey:@"Parent"] isEqual:rootID])[rootChildren addObject:item];
    [rootChildren sortUsingComparator:^NSComparisonResult(NSDictionary *a,NSDictionary *b){
        NSNumber *xValue=[ranks objectForKey:[a objectForKey:@"Role"]?:@""]?:@3,*yValue=[ranks objectForKey:[b objectForKey:@"Role"]?:@""]?:@3;
        NSInteger x=xValue.integerValue,y=yValue.integerValue;
        if(x!=y)return x<y?NSOrderedAscending:NSOrderedDescending;
        return [[a objectForKey:@"Index"] compare:[b objectForKey:@"Index"]];
    }];
    for(NSUInteger i=0;i<rootChildren.count;i++)[[rootChildren objectAtIndex:i] setObject:@(i) forKey:@"Index"];
    CFPropertyListRef device=CFPreferencesCopyValue(CFSTR("SyncedTabsDeviceUUID"),CFSTR("com.apple.Safari"),kCFPreferencesCurrentUser,kCFPreferencesCurrentHost);
    NSString *deviceID=device&&CFGetTypeID(device)==CFStringGetTypeID()?[[(NSString *)device copy] autorelease]:nil;
    if(device)CFRelease(device);if(!deviceID.length)return nil;
    NSString *token=AQBookDigest(account,items);if(!token)return nil;
    return @{@"Version":@1,@"Account":account,@"DeviceID":deviceID,@"Token":token,@"Items":items};
}
static NSDictionary *AQBookIndex(NSArray *items) {
    if(![items isKindOfClass:[NSArray class]] || !items.count || items.count>20000)return nil;
    NSMutableDictionary *index=[NSMutableDictionary dictionary],*roles=[NSMutableDictionary dictionary];
    for(id item in items) {
        if(![item isKindOfClass:[NSDictionary class]])return nil;
        id identifier=[item objectForKey:@"ID"],parent=[item objectForKey:@"Parent"],kind=[item objectForKey:@"Kind"],title=[item objectForKey:@"Title"],position=[item objectForKey:@"Index"],role=[item objectForKey:@"Role"];
        if(![identifier isKindOfClass:[NSString class]] || ![identifier length] || [identifier length]>128 || [index objectForKey:identifier] || ![parent isKindOfClass:[NSString class]] ||
           ![@[@"folder",@"leaf"] containsObject:kind?:@""] || ![title isKindOfClass:[NSString class]] || [title length]>65536 || ![position isKindOfClass:[NSNumber class]] ||
           [position doubleValue]!=[position integerValue] || [position integerValue]<0 || [position integerValue]>20000)return nil;
        if([kind isEqual:@"leaf"]) {id url=[item objectForKey:@"URL"];if(![url isKindOfClass:[NSString class]] || [url length]>131072)return nil;}
        for(NSString *key in @[@"DateAdded",@"DateLastViewed"]) {id value=[item objectForKey:key];if(value && (![value isKindOfClass:[NSNumber class]] || !isfinite([value doubleValue]) || fabs([value doubleValue])>=1e12))return nil;}
        id preview=[item objectForKey:@"PreviewText"];if(preview && (![preview isKindOfClass:[NSString class]] || [preview length]>262144))return nil;
        if(role) {if(![@[@"Root",@"BookmarksBar",@"BookmarksMenu",@"ReadingList"] containsObject:role] || [roles objectForKey:role] || ![kind isEqual:@"folder"])return nil;[roles setObject:identifier forKey:role];}
        [index setObject:item forKey:identifier];
    }
    if(![roles objectForKey:@"Root"])return nil;
    for(NSString *role in roles) {NSDictionary *item=[index objectForKey:[roles objectForKey:role]];if(![[item objectForKey:@"Title"] isEqual:role] || (![role isEqual:@"Root"] && ![[item objectForKey:@"Parent"] isEqual:[roles objectForKey:@"Root"]]))return nil;}
    for(NSString *identifier in index) {
        NSMutableSet *seen=[NSMutableSet set];NSString *cursor=identifier;
        while(cursor.length) {
            NSDictionary *item=[index objectForKey:cursor];if(!item || [seen containsObject:cursor] || seen.count>32)return nil;[seen addObject:cursor];
            NSString *parent=[item objectForKey:@"Parent"];
            if(parent.length && ![[[index objectForKey:parent] objectForKey:@"Kind"] isEqual:@"folder"])return nil;
            if(!parent.length && ![[item objectForKey:@"Role"] isEqual:@"Root"])return nil;
            cursor=parent;
        }
    }
    return index;
}
static NSArray *AQBookItemsByAliasingRoot(NSArray *items,NSString *target) {
    NSString *source=nil;for(NSDictionary *item in items)if([[item objectForKey:@"Role"] isEqual:@"Root"]){source=[item objectForKey:@"ID"];break;}
    if(!source || !target.length)return nil;if([source isEqual:target])return items;
    for(NSDictionary *item in items)if([[item objectForKey:@"ID"] isEqual:target])return nil;
    NSMutableArray *result=[NSMutableArray arrayWithCapacity:items.count];
    for(NSDictionary *item in items) {NSMutableDictionary *copy=[[item mutableCopy] autorelease];if([[copy objectForKey:@"ID"] isEqual:source])[copy setObject:target forKey:@"ID"];if([[copy objectForKey:@"Parent"] isEqual:source])[copy setObject:target forKey:@"Parent"];[result addObject:copy];}
    return result;
}
static NSDictionary *AQBookNativeDictionary(NSDictionary *item) {
    BOOL folder=[[item objectForKey:@"Kind"] isEqual:@"folder"];
    NSMutableDictionary *result=[NSMutableDictionary dictionaryWithDictionary:@{@"WebBookmarkType":folder?@"WebBookmarkTypeList":@"WebBookmarkTypeLeaf",@"WebBookmarkUUID":[item objectForKey:@"ID"]}];
    if(folder) {
        [result setObject:[[item objectForKey:@"Role"] isEqual:@"ReadingList"]?@"com.apple.ReadingList":[item objectForKey:@"Title"] forKey:@"Title"];
        [result setObject:@[] forKey:@"Children"];
        if([[item objectForKey:@"Role"] isEqual:@"ReadingList"])[result setObject:@YES forKey:@"ShouldOmitFromUI"];
    } else {
        [result setObject:@{@"title":[item objectForKey:@"Title"]} forKey:@"URIDictionary"];[result setObject:[item objectForKey:@"URL"] forKey:@"URLString"];
        NSMutableDictionary *reading=[NSMutableDictionary dictionary];
        for(NSString *key in @[@"DateAdded",@"DateLastViewed"])if([item objectForKey:key])[reading setObject:[NSDate dateWithTimeIntervalSinceReferenceDate:[[item objectForKey:key] doubleValue]] forKey:key];
        if([item objectForKey:@"PreviewText"])[reading setObject:[item objectForKey:@"PreviewText"] forKey:@"PreviewText"];
        if(reading.count)[result setObject:reading forKey:@"ReadingList"];
    }
    return result;
}
static BOOL AQBookSupportedDictionary(id node) {
    id type=[node isKindOfClass:[NSDictionary class]]?[node objectForKey:@"WebBookmarkType"]:nil;
    return [@[@"WebBookmarkTypeList",@"WebBookmarkTypeLeaf"] containsObject:type?:@""];
}
static BOOL AQBookCollectDictionaries(NSDictionary *node,NSMutableDictionary *index,NSMutableSet *active,unsigned depth) {
    if(depth>32 || ![node isKindOfClass:[NSDictionary class]])return NO;
    if(AQBookSupportedDictionary(node)) {
        id identifier=[node objectForKey:@"WebBookmarkUUID"];
        if(![identifier isKindOfClass:[NSString class]] || ![identifier length] || [identifier length]>128 || [index objectForKey:identifier] || [active containsObject:identifier])return NO;
        [index setObject:node forKey:identifier];[active addObject:identifier];
    }
    id children=[node objectForKey:@"Children"];
    if(children && ![children isKindOfClass:[NSArray class]])return NO;
    for(id child in children)if(!AQBookCollectDictionaries(child,index,active,depth+1))return NO;
    id identifier=[node objectForKey:@"WebBookmarkUUID"];if(identifier)[active removeObject:identifier];return YES;
}
static NSDictionary *AQBookBuildDictionary(NSString *identifier,NSDictionary *desired,NSDictionary *existing,unsigned depth) {
    if(depth>32)return nil;NSDictionary *item=[desired objectForKey:identifier];if(!item)return nil;
    BOOL folder=[[item objectForKey:@"Kind"] isEqual:@"folder"];
    NSString *expectedType=folder?@"WebBookmarkTypeList":@"WebBookmarkTypeLeaf";
    NSDictionary *old=[existing objectForKey:identifier];
    if(old && ![[old objectForKey:@"WebBookmarkType"] isEqual:expectedType])return nil;
    NSMutableDictionary *result=[[(old?:AQBookNativeDictionary(item)) mutableCopy] autorelease];
    [result setObject:expectedType forKey:@"WebBookmarkType"];[result setObject:identifier forKey:@"WebBookmarkUUID"];
    if(folder) {
        // Keep localized/storage titles for the four standard folders.
        if(![item objectForKey:@"Role"])[result setObject:[item objectForKey:@"Title"] forKey:@"Title"];
        NSMutableArray *wanted=[NSMutableArray array];
        for(NSString *name in desired)if([[[desired objectForKey:name] objectForKey:@"Parent"] isEqual:identifier])[wanted addObject:[desired objectForKey:name]];
        [wanted sortUsingDescriptors:@[[NSSortDescriptor sortDescriptorWithKey:@"Index" ascending:YES],[NSSortDescriptor sortDescriptorWithKey:@"ID" ascending:YES]]];
        NSMutableArray *children=[NSMutableArray array];
        for(NSDictionary *child in wanted) {
            NSDictionary *built=AQBookBuildDictionary([child objectForKey:@"ID"],desired,existing,depth+1);if(!built)return nil;[children addObject:built];
        }
        // Preserve Safari's proxy/virtual collections at their prior position.
        NSUInteger supportedBefore=0,extra=0;
        for(id child in [old objectForKey:@"Children"]) {
            if(AQBookSupportedDictionary(child)){supportedBefore++;continue;}
            if(![child isKindOfClass:[NSDictionary class]])return nil;
            NSUInteger insertion=MIN(supportedBefore+extra,children.count);[children insertObject:child atIndex:insertion];extra++;
        }
        [result setObject:children forKey:@"Children"];
    } else {
        NSMutableDictionary *uri=[[[result objectForKey:@"URIDictionary"] mutableCopy] autorelease]?:[NSMutableDictionary dictionary];
        [uri setObject:[item objectForKey:@"Title"] forKey:@"title"];[result setObject:uri forKey:@"URIDictionary"];
        [result setObject:[item objectForKey:@"URL"] forKey:@"URLString"];
        NSMutableDictionary *reading=[[[result objectForKey:@"ReadingList"] mutableCopy] autorelease]?:[NSMutableDictionary dictionary];
        for(NSString *key in @[@"DateAdded",@"DateLastViewed"]) {
            id value=[item objectForKey:key];if(value)[reading setObject:[NSDate dateWithTimeIntervalSinceReferenceDate:[value doubleValue]] forKey:key];else[reading removeObjectForKey:key];
        }
        id preview=[item objectForKey:@"PreviewText"];if(preview)[reading setObject:preview forKey:@"PreviewText"];else[reading removeObjectForKey:@"PreviewText"];
        if(reading.count)[result setObject:reading forKey:@"ReadingList"];else[result removeObjectForKey:@"ReadingList"];
    }
    return result;
}
static NSData *AQBookBuildFile(NSData *current,NSArray *items) {
    id root=[NSPropertyListSerialization propertyListWithData:current options:0 format:NULL error:NULL];
    if(![root isKindOfClass:[NSDictionary class]])return nil;
    items=AQBookItemsByAliasingRoot(items,[root objectForKey:@"WebBookmarkUUID"]);NSDictionary *desired=AQBookIndex(items);if(!desired)return nil;
    NSMutableDictionary *existing=[NSMutableDictionary dictionary];
    if(!AQBookCollectDictionaries(root,existing,[NSMutableSet set],0))return nil;
    NSString *rootID=nil;for(NSString *identifier in desired)if([[[desired objectForKey:identifier] objectForKey:@"Role"] isEqual:@"Root"]){rootID=identifier;break;}
    if(!rootID || ![[root objectForKey:@"WebBookmarkUUID"] isEqual:rootID])return nil;
    NSDictionary *built=AQBookBuildDictionary(rootID,desired,existing,0);if(!built)return nil;
    NSMutableArray *flattened=[NSMutableArray array];NSMutableDictionary *roles=[NSMutableDictionary dictionary];
    for(NSString *identifier in desired)if([[desired objectForKey:identifier] objectForKey:@"Role"])[roles setObject:[[desired objectForKey:identifier] objectForKey:@"Role"] forKey:identifier];
    if(!AQBookFlatten(built,@"",0,roles,flattened,[NSMutableSet set],0) || !AQBookIndex(flattened))return nil;
    return [NSPropertyListSerialization dataWithPropertyList:built format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
}
static BOOL AQBookAtomicWrite(NSString *path,NSData *data) {
    if(!data.length || data.length>4*1024*1024)return NO;NSString *directory=[path stringByDeletingLastPathComponent];struct stat info;
    if(lstat(directory.fileSystemRepresentation,&info) || !S_ISDIR(info.st_mode) || info.st_uid!=getuid() || (info.st_mode&022))return NO;
    NSString *temporary=[directory stringByAppendingPathComponent:[NSString stringWithFormat:@".Bookmarks-%@.new",[[NSUUID UUID] UUIDString]]];
    int fd=open(temporary.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(fd<0)return NO;
    const char *p=data.bytes;size_t left=data.length;BOOL ok=YES;
    while(left){ssize_t n=write(fd,p,left);if(n<0&&errno==EINTR)continue;if(n<=0){ok=NO;break;}p+=n;left-=n;}
    if(fsync(fd))ok=NO;close(fd);if(ok)ok=!rename(temporary.fileSystemRepresentation,path.fileSystemRepresentation);if(!ok)unlink(temporary.fileSystemRepresentation);return ok;
}
static void AQBookVoid(id object,const char *selector) {((void(*)(id,SEL))objc_msgSend)(object,sel_registerName(selector));}
static BOOL AQBookBool(id object,const char *selector) {return ((BOOL(*)(id,SEL))objc_msgSend)(object,sel_registerName(selector));}
static BOOL AQBookSame(id a,id b) {return a==b || [a isEqual:b];}
static NSString *AQBookPlanMismatch(NSDictionary *actual,NSDictionary *desired,NSDictionary *before) {
    if(!actual)return @"invalid-native-tree";
    NSString *actualRoot=nil;for(NSString *identifier in actual)if([[[actual objectForKey:identifier] objectForKey:@"Role"] isEqual:@"Root"]){actualRoot=identifier;break;}
    NSArray *desiredItems=[desired allValues],*beforeItems=[before allValues];
    desired=AQBookIndex(AQBookItemsByAliasingRoot(desiredItems,actualRoot));
    if(before.count)before=AQBookIndex(AQBookItemsByAliasingRoot(beforeItems,actualRoot));
    if(!desired || (beforeItems.count && !before))return @"root-alias";
    if(![[NSSet setWithArray:[actual allKeys]] isEqual:[NSSet setWithArray:[desired allKeys]]])return @"item-identities";
    for(NSString *identifier in desired) {
        NSDictionary *wanted=[desired objectForKey:identifier],*got=[actual objectForKey:identifier],*old=[before objectForKey:identifier];
        for(NSString *key in @[@"Parent",@"Kind",@"Role",@"Title",@"URL",@"Index",@"DateAdded",@"DateLastViewed",@"PreviewText"]) {
            if(![wanted objectForKey:key] && ![old objectForKey:key] && [@[@"DateAdded",@"PreviewText"] containsObject:key])continue;
            if(!AQBookSame([wanted objectForKey:key],[got objectForKey:key]))return [NSString stringWithFormat:@"%@:%@",key,[wanted objectForKey:@"Role"]?:[wanted objectForKey:@"Kind"]];
        }
    }
    return nil;
}
@interface AQSafariBookmarksAdapter : NSObject
+ (void)startEvents;
+ (void)startOnMain;
+ (void)queueStart:(BOOL)refresh;
+ (void)capture;
+ (void)nativeDidSave:(id)controller;
+ (void)applyIncoming;
+ (void)applyIncomingPlan;
+ (BOOL)nativeSyncRequested;
+ (void)nativeReloaded:(id)controller;
@end
static void AQBookDeliver(void *unused) {(void)unused;[AQSafariBookmarksAdapter applyIncoming];}
static void AQBookUpdated(CFNotificationCenterRef center,void *observer,CFStringRef name,const void *object,CFDictionaryRef info) {
    (void)center;(void)observer;(void)name;(void)object;(void)info;dispatch_async_f(dispatch_get_main_queue(),NULL,AQBookDeliver);
}
@implementation AQSafariBookmarksAdapter
+ (BOOL)nativeSyncRequested {
    if(!AQBookAccount())return NO;
    if(![NSThread isMainThread]) {[self performSelectorOnMainThread:@selector(nativeReloaded:) withObject:nil waitUntilDone:NO];return YES;}
    if(!AQBookmarksApplying && !AQBookmarksCapturing && !AQBookmarksReceiving)[self queueStart:YES];
    return YES;
}
+ (void)nativeReloaded:(id)controller {
    (void)controller;
    if(![NSThread isMainThread]) {[self performSelectorOnMainThread:@selector(nativeReloaded:) withObject:nil waitUntilDone:NO];return;}
    if(!AQBookmarksApplying && !AQBookmarksCapturing && !AQBookmarksReceiving && AQBookAccount())[self queueStart:YES];
}
+ (void)startEvents {
    if(![NSThread isMainThread]){[self performSelectorOnMainThread:@selector(startEvents) withObject:nil waitUntilDone:NO];return;}
    if(!AQBookmarksApplying && !AQBookmarksCapturing && !AQBookmarksReceiving)[self queueStart:NO];
}
+ (void)queueStart:(BOOL)refresh {
    AQBookmarksNeedRefresh|=refresh;if(AQBookmarksQueued)return;AQBookmarksQueued=YES;
    // Native save/reload callbacks can occur during controller construction.
    // Read the shared model on the next main-queue turn, after that operation.
    dispatch_async(dispatch_get_main_queue(),^{
        AQBookmarksQueued=NO;BOOL requested=AQBookmarksNeedRefresh;AQBookmarksNeedRefresh=NO;
        [self startOnMain];if(requested && AQBookAccount())[AQSafariTabsAdapter requestRefresh];
    });
}
+ (void)startOnMain {
    if(![NSThread isMainThread] || !AQBookAccount())return;
    if(!AQBookmarksStarted) {
        AQBookmarksStarted=YES;
        NSString *name=[NSString stringWithFormat:@"org.aquatransport.bookmarks.updated.%u",getuid()];
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),NULL,AQBookUpdated,(CFStringRef)name,NULL,CFNotificationSuspensionBehaviorDeliverImmediately);
    }
    [self capture];
    [self applyIncoming];
}
+ (void)nativeDidSave:(id)controller {
    (void)controller;
    if(![NSThread isMainThread]) {[self performSelectorOnMainThread:@selector(nativeDidSave:) withObject:nil waitUntilDone:NO];return;}
    if(!AQBookmarksApplying && !AQBookmarksCapturing && !AQBookmarksReceiving)[self queueStart:NO];
}
+ (void)capture {
    if(![NSThread isMainThread] || AQBookmarksApplying || AQBookmarksCapturing)return;
    AQBookmarksCapturing=YES;
    @try {
        NSDictionary *snapshot=AQBookSnapshot();if(!snapshot)return;
        NSDictionary *old=AQBookRead(@"local-bookmarks.plist");
        if([[old objectForKey:@"Token"] isEqual:[snapshot objectForKey:@"Token"]])return;
        if(AQBookWrite(@"local-bookmarks.plist",snapshot))[AQSafariTabsAdapter requestRefresh];
    } @finally {AQBookmarksCapturing=NO;}
}
+ (void)applyIncoming {
    if(AQBookmarksReceiving)return;AQBookmarksReceiving=YES;
    @try {[self applyIncomingPlan];} @finally {AQBookmarksReceiving=NO;}
}
+ (void)applyIncomingPlan {
    if(![NSThread isMainThread] || AQBookmarksApplying)return;
    NSString *account=AQBookAccount();NSDictionary *plan=AQBookRead(@"bookmarks-incoming.plist");
    if(!account || ![[plan objectForKey:@"Version"] isEqual:@1] || ![[plan objectForKey:@"Account"] isEqual:account])return;
    NSString *transaction=[plan objectForKey:@"Transaction"],*expected=[plan objectForKey:@"Expected"];
    if(![transaction isKindOfClass:[NSString class]] || transaction.length!=36 || ![expected isKindOfClass:[NSString class]] || expected.length!=64)return;
    if([[AQBookRead(@"bookmarks-ack.plist") objectForKey:@"Transaction"] isEqual:transaction])return;
    NSDictionary *snapshot=AQBookSnapshot(),*before=AQBookIndex([snapshot objectForKey:@"Items"]),*desired=AQBookIndex([plan objectForKey:@"Items"]);
    if(!before || !desired)return;
    BOOL applied=NO;NSString *reason=@"stale";id controller=AQBookController();NSData *backup=nil;NSString *path=nil;
    if([[snapshot objectForKey:@"Token"] isEqual:expected]) {
        AQBookmarksApplying=YES;
        @try {
            reason=@"native-error";
            AQBookVoid(controller,"savePendingChanges");AQBookVoid(controller,"lockFileLocker");AQBookVoid(controller,"reloadBookmarksFromFileIfChanged");
            snapshot=AQBookSnapshot();before=AQBookIndex([snapshot objectForKey:@"Items"]);
            if(before && [[snapshot objectForKey:@"Token"] isEqual:expected] && [AQBookAccount() isEqual:account]) {
                path=AQBookGet(NSClassFromString(@"BookmarksController"),"standardBookmarksFilePath");
                backup=[NSData dataWithContentsOfFile:path];
                if(!backup.length || backup.length>4*1024*1024)[NSException raise:@"AQBookmarkModel" format:@"Native backup unavailable"];
                NSData *replacement=AQBookBuildFile(backup,[plan objectForKey:@"Items"]);
                if(!replacement || !AQBookAtomicWrite(path,replacement))[NSException raise:@"AQBookmarkModel" format:@"Complete bookmark file could not be written"];
                AQBookVoid(controller,"unlockFileLocker");AQBookVoid(controller,"reloadBookmarksFromFileIfChanged");
                NSDictionary *actual=AQBookIndex([AQBookSnapshot() objectForKey:@"Items"]);NSString *mismatch=AQBookPlanMismatch(actual,desired,before);
                if(mismatch) {
                    AQBookWrite(@"bookmarks-native-diagnostic.plist",@{@"Transaction":transaction,@"Mismatch":mismatch,@"ExpectedCount":@(desired.count),@"ActualCount":@(actual.count)});
                    [NSException raise:@"AQBookmarkModel" format:@"Native model did not accept the complete plan"];
                }
                applied=YES;reason=@"";
            } else reason=@"stale";
        } @catch(NSException *exception) {
            NSMutableDictionary *diagnostic=[[AQBookRead(@"bookmarks-native-diagnostic.plist") mutableCopy] autorelease];
            if(![[diagnostic objectForKey:@"Transaction"] isEqual:transaction])diagnostic=[NSMutableDictionary dictionaryWithObject:transaction forKey:@"Transaction"];
            [diagnostic setObject:[exception name]?:@"native-exception" forKey:@"Exception"];
            if([[exception name] isEqual:@"AQBookmarkModel"])[diagnostic setObject:[exception reason]?:@"" forKey:@"Reason"];
            AQBookWrite(@"bookmarks-native-diagnostic.plist",diagnostic);
            if(backup && path) {
                ((void(*)(id,SEL,BOOL))objc_msgSend)(controller,sel_registerName("setSavePending:"),NO);
                if(!AQBookBool(controller,"fileLockerIsLocked"))AQBookVoid(controller,"lockFileLocker");
                if(AQBookAtomicWrite(path,backup)){AQBookVoid(controller,"unlockFileLocker");AQBookVoid(controller,"reloadBookmarksFromFileIfChanged");}
            }
            applied=NO;
        } @finally {
            if(AQBookBool(controller,"fileLockerIsLocked"))AQBookVoid(controller,"unlockFileLocker");
            AQBookmarksApplying=NO;
        }
    }
    [self capture];NSDictionary *after=AQBookSnapshot();
    AQBookWrite(@"bookmarks-ack.plist",@{@"Version":@1,@"Account":account,@"Transaction":transaction,@"Applied":@(applied),@"Reason":reason,@"Token":[after objectForKey:@"Token"]?:@""});
    [AQSafariTabsAdapter requestRefresh];
}
@end
