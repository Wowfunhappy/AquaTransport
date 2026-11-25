/* Safari 7 Global History bridge. Private C++ entry points are resolved from
 * the loaded, trusted Safari image by exact symbol name and validated through
 * their Objective-C wrapper before use. */
static BOOL AQHistoryStarted,AQHistoryApplying,AQHistoryQueued;
static void *AQSafariLocalSymbol(const char *wanted) {
    for(uint32_t image=0;image<_dyld_image_count();image++) {
        const char *path=_dyld_get_image_name(image);if(!path || !strstr(path,"/Safari.framework/Versions/A/Safari"))continue;
        const struct mach_header *header=_dyld_get_image_header(image);intptr_t slide=_dyld_get_image_vmaddr_slide(image);
        const struct symtab_command *symbols=NULL;uintptr_t linkAddress=0;uint64_t linkFile=0;
        const uint8_t *cursor=(const uint8_t *)header+
#ifdef __LP64__
            sizeof(struct mach_header_64);
#else
            sizeof(struct mach_header);
#endif
        for(uint32_t command=0;command<header->ncmds;command++) {
            const struct load_command *load=(const struct load_command *)cursor;
            if(load->cmd==LC_SYMTAB)symbols=(const struct symtab_command *)load;
#ifdef __LP64__
            if(load->cmd==LC_SEGMENT_64) {const struct segment_command_64 *segment=(const struct segment_command_64 *)load;if(!strcmp(segment->segname,"__LINKEDIT")){linkAddress=(uintptr_t)segment->vmaddr;linkFile=segment->fileoff;}}
#else
            if(load->cmd==LC_SEGMENT) {const struct segment_command *segment=(const struct segment_command *)load;if(!strcmp(segment->segname,"__LINKEDIT")){linkAddress=(uintptr_t)segment->vmaddr;linkFile=segment->fileoff;}}
#endif
            if(!load->cmdsize)return NULL;cursor+=load->cmdsize;
        }
        if(!symbols || !linkAddress)return NULL;uintptr_t base=(uintptr_t)slide+linkAddress-(uintptr_t)linkFile;
        const char *strings=(const char *)(base+symbols->stroff);
#ifdef __LP64__
        const struct nlist_64 *table=(const struct nlist_64 *)(base+symbols->symoff);
#else
        const struct nlist *table=(const struct nlist *)(base+symbols->symoff);
#endif
        for(uint32_t index=0;index<symbols->nsyms;index++)if(table[index].n_un.n_strx<symbols->strsize && !strcmp(strings+table[index].n_un.n_strx,wanted))return (void *)((uintptr_t)slide+(uintptr_t)table[index].n_value);
    }
    return NULL;
}
static void *AQGlobalHistory(void) {
    static void *(*shared)(void);static BOOL tried;
    if(!tried){tried=YES;shared=AQSafariLocalSymbol("__ZN6Safari13GlobalHistory6sharedEv");}
    void *history=shared?shared():NULL;Class wrapper=NSClassFromString(@"GlobalHistoryObjC");
    return history && wrapper?history:NULL;
}
static NSDictionary *AQHistoryRead(NSString *name) {
    NSString *path=[AQCloudTabsStateDirectory() stringByAppendingPathComponent:name];struct stat s;
    if(lstat(path.fileSystemRepresentation,&s) || !S_ISREG(s.st_mode) || s.st_uid!=getuid() || (s.st_mode&077) || s.st_size<=0 || s.st_size>32*1024*1024)return nil;
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW);if(fd<0)return nil;NSMutableData *data=[NSMutableData dataWithLength:s.st_size];char *p=data.mutableBytes;size_t left=data.length;BOOL ok=YES;
    while(left){ssize_t n=read(fd,p,left);if(n<0&&errno==EINTR)continue;if(n<=0){ok=NO;break;}p+=n;left-=n;}close(fd);
    id value=ok?[NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL]:nil;return [value isKindOfClass:[NSDictionary class]]?value:nil;
}
static BOOL AQHistoryWrite(NSString *name,NSDictionary *value) {
    NSData *data=[NSPropertyListSerialization dataWithPropertyList:value format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    if(!data.length || data.length>32*1024*1024)return NO;
    NSString *directory=AQCloudTabsStateDirectory();struct stat info;if(lstat(directory.fileSystemRepresentation,&info)||!S_ISDIR(info.st_mode)||info.st_uid!=getuid()||(info.st_mode&077))return NO;
    NSString *temporary=[directory stringByAppendingPathComponent:[NSString stringWithFormat:@"%@-%@.new",name,[[NSUUID UUID] UUIDString]]];int fd=open(temporary.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(fd<0)return NO;
    const char *p=data.bytes;size_t left=data.length;BOOL ok=YES;while(left){ssize_t n=write(fd,p,left);if(n<0&&errno==EINTR)continue;if(n<=0){ok=NO;break;}p+=n;left-=n;}if(fsync(fd))ok=NO;close(fd);
    if(ok)ok=!rename(temporary.fileSystemRepresentation,[[directory stringByAppendingPathComponent:name] fileSystemRepresentation]);if(!ok)unlink(temporary.fileSystemRepresentation);return ok;
}
static NSString *AQHistoryAccount(void) {
    NSString *account=AQBookAccount();if(!account)return nil;
    return AQBookPrivateFile([AQCloudTabsStateDirectory() stringByAppendingPathComponent:@"history-service-keys.plist"])?account:nil;
}
static NSDictionary *AQHistorySnapshot(void) {
    NSString *account=AQHistoryAccount();void *history=AQGlobalHistory();if(!account || !history)return nil;
    static void (*enumerate)(void *,void (^)(void *));static BOOL tried;
    if(!tried){tried=YES;enumerate=AQSafariLocalSymbol("__ZNK6Safari13GlobalHistory50enumerateItemsByDescendingLastVisitedDateWithBlockEU13block_pointerFvPNS_17GlobalHistoryItemEE");}
    if(!enumerate)return nil;Class wrapper=NSClassFromString(@"GlobalHistoryItemObjC");if(!wrapper)return nil;
    NSMutableDictionary *entries=[NSMutableDictionary dictionary];NSTimeInterval cutoff=[[NSDate date] timeIntervalSinceReferenceDate]-30*24*60*60;
    enumerate(history,^(void *raw){
        if(entries.count>=10000 || !raw)return;id item=((id(*)(id,SEL,void*))objc_msgSend)([wrapper alloc],sel_registerName("initWithGlobalHistoryItem:"),raw);if(!item)return;
        NSString *url=AQBookGet(item,"URLString"),*title=AQBookGet(item,"title");NSTimeInterval time=((double(*)(id,SEL))objc_msgSend)(item,sel_registerName("lastVisitedTimeInterval"));
        if(![title isKindOfClass:[NSString class]])title=@"";
        NSURL *parsed=[url isKindOfClass:[NSString class]]?[NSURL URLWithString:url]:nil;NSString *scheme=[[parsed scheme] lowercaseString];
        if(time>=cutoff && isfinite(time) && [url length]<=131072 && [title length]<=65536 && [@[@"http",@"https",@"ftp"] containsObject:scheme?:@""]) {
            NSDictionary *old=[entries objectForKey:url];if(!old || time>[[old objectForKey:@"Time"] doubleValue])[entries setObject:@{@"URL":url,@"Title":title?:@"",@"Time":@(time),@"HTTPNonGet":@NO,@"LoadSuccessful":@YES} forKey:url];
        }
        [item release];
    });
    NSArray *values=[[entries allValues] sortedArrayUsingDescriptors:@[[NSSortDescriptor sortDescriptorWithKey:@"Time" ascending:NO],[NSSortDescriptor sortDescriptorWithKey:@"URL" ascending:YES]]];
    NSMutableArray *digestRows=[NSMutableArray array];for(NSDictionary *entry in values)[digestRows addObject:@[[entry objectForKey:@"URL"],[entry objectForKey:@"Title"],[entry objectForKey:@"Time"]]];
    NSData *digestData=[NSJSONSerialization dataWithJSONObject:digestRows options:0 error:NULL];unsigned char digest[CC_SHA256_DIGEST_LENGTH];if(!digestData)return nil;CC_SHA256(digestData.bytes,(CC_LONG)digestData.length,digest);
    NSMutableString *token=[NSMutableString string];for(unsigned i=0;i<sizeof digest;i++)[token appendFormat:@"%02x",digest[i]];
    CFPropertyListRef device=CFPreferencesCopyValue(CFSTR("SyncedTabsDeviceUUID"),CFSTR("com.apple.Safari"),kCFPreferencesCurrentUser,kCFPreferencesCurrentHost);NSString *deviceID=device&&CFGetTypeID(device)==CFStringGetTypeID()?[[(NSString *)device copy] autorelease]:nil;if(device)CFRelease(device);
    return deviceID?@{@"Version":@1,@"Account":account,@"DeviceID":deviceID,@"Token":token,@"Entries":values}:nil;
}
static NSArray *AQHistoryRawItemsForURLs(NSSet *wanted) {
    void *history=AQGlobalHistory();if(!history||!wanted.count)return @[];static void (*enumerate)(void *,void (^)(void *));static BOOL tried;
    if(!tried){tried=YES;enumerate=AQSafariLocalSymbol("__ZNK6Safari13GlobalHistory50enumerateItemsByDescendingLastVisitedDateWithBlockEU13block_pointerFvPNS_17GlobalHistoryItemEE");}
    Class wrapper=NSClassFromString(@"GlobalHistoryItemObjC");if(!enumerate||!wrapper)return nil;NSMutableArray *result=[NSMutableArray array];
    enumerate(history,^(void *raw){if(!raw)return;id item=((id(*)(id,SEL,void*))objc_msgSend)([wrapper alloc],sel_registerName("initWithGlobalHistoryItem:"),raw);NSString *url=AQBookGet(item,"URLString");if([wanted containsObject:url])[result addObject:[NSValue valueWithPointer:raw]];[item release];});
    return result;
}
static BOOL AQHistoryApplyOperations(NSArray *additions,NSArray *removals) {
    void *history=AQGlobalHistory();if(!history)return NO;
    static void (*create)(void **,void *);static void (*add)(void *,void *);static void (*remove)(void *,void *);static void (*deref)(void *);static id (*sharedObjC)(void);static BOOL tried;
    if(!tried){tried=YES;create=AQSafariLocalSymbol("__ZN6Safari17GlobalHistoryItem6createERKNS_2CF10DictionaryE");add=AQSafariLocalSymbol("__ZN6Safari13GlobalHistory8addItemsERKN3WTF6VectorIPNS_17GlobalHistoryItemELm0ENS1_15CrashOnOverflowEEE");remove=AQSafariLocalSymbol("__ZN6Safari13GlobalHistory11removeItemsERKN3WTF6VectorIPNS_17GlobalHistoryItemELm0ENS1_15CrashOnOverflowEEE");deref=AQSafariLocalSymbol("__ZN3WTF20ThreadSafeRefCountedIN6Safari17GlobalHistoryItemEE5derefEv");sharedObjC=AQSafariLocalSymbol("__ZN6Safari13GlobalHistory10sharedObjCEv");}
    if(!create||!add||!remove||!deref||!sharedObjC)return NO;
    NSSet *removeURLs=[NSSet setWithArray:removals];NSArray *rawRemovals=AQHistoryRawItemsForURLs(removeURLs);if(!rawRemovals)return NO;
    if(rawRemovals.count){void **buffer=calloc(rawRemovals.count,sizeof(void*));if(!buffer)return NO;for(NSUInteger i=0;i<rawRemovals.count;i++)buffer[i]=[[rawRemovals objectAtIndex:i] pointerValue];struct{void **buffer;unsigned capacity,size;}vector={buffer,(unsigned)rawRemovals.count,(unsigned)rawRemovals.count};remove(history,&vector);free(buffer);}
    NSMutableArray *owned=[NSMutableArray array];
    for(NSDictionary *entry in additions) {
        NSString *url=[entry objectForKey:@"URL"],*title=[entry objectForKey:@"Title"];NSNumber *time=[entry objectForKey:@"Time"];
        if(![url isKindOfClass:[NSString class]]||![title isKindOfClass:[NSString class]]||![time isKindOfClass:[NSNumber class]])return NO;
        NSMutableDictionary *dictionary=[NSMutableDictionary dictionaryWithObjectsAndKeys:url,@"",title,@"title",title,@"displayTitle",[NSString stringWithFormat:@"%.6f",[time doubleValue]],@"lastVisitedDate",@1,@"visitCount",@[@1],@"D",nil];
        if([[entry objectForKey:@"HTTPNonGet"] boolValue])[dictionary setObject:@YES forKey:@"lastVisitWasHTTPNonGet"];
        if(![[entry objectForKey:@"LoadSuccessful"] boolValue])[dictionary setObject:@YES forKey:@"lastVisitWasFailure"];
        CFDictionaryRef wrapper=(CFDictionaryRef)dictionary;void *item=NULL;create(&item,&wrapper);if(!item){for(NSValue *value in owned)deref([value pointerValue]);return NO;}[owned addObject:[NSValue valueWithPointer:item]];
    }
    if(owned.count){void **buffer=calloc(owned.count,sizeof(void*));if(!buffer){for(NSValue *value in owned)deref([value pointerValue]);return NO;}for(NSUInteger i=0;i<owned.count;i++)buffer[i]=[[owned objectAtIndex:i] pointerValue];struct{void **buffer;unsigned capacity,size;}vector={buffer,(unsigned)owned.count,(unsigned)owned.count};add(history,&vector);free(buffer);for(NSValue *value in owned)deref([value pointerValue]);}
    id wrapper=sharedObjC();if(wrapper&&[wrapper respondsToSelector:sel_registerName("savePendingChangesBeforeTermination")])AQBookVoid(wrapper,"savePendingChangesBeforeTermination");return YES;
}
@interface AQSafariHistoryAdapter : NSObject
+ (void)startEvents;
+ (void)nativeChanged;
+ (void)capture;
+ (void)applyIncoming;
@end
static void AQHistoryDeliver(void *unused){(void)unused;[AQSafariHistoryAdapter applyIncoming];}
static void AQHistoryUpdated(CFNotificationCenterRef center,void *observer,CFStringRef name,const void *object,CFDictionaryRef info){(void)center;(void)observer;(void)name;(void)object;(void)info;dispatch_async_f(dispatch_get_main_queue(),NULL,AQHistoryDeliver);}
@implementation AQSafariHistoryAdapter
+ (void)startEvents {
    if(![NSThread isMainThread]){[self performSelectorOnMainThread:@selector(startEvents) withObject:nil waitUntilDone:NO];return;}
    if(!AQHistoryAccount())return;if(!AQHistoryStarted){AQHistoryStarted=YES;NSString *name=[NSString stringWithFormat:@"org.aquatransport.history.updated.%u",getuid()];CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),NULL,AQHistoryUpdated,(CFStringRef)name,NULL,CFNotificationSuspensionBehaviorDeliverImmediately);}
    [self nativeChanged];[self applyIncoming];
}
+ (void)nativeChanged {
    if(AQHistoryApplying||AQHistoryQueued||!AQHistoryAccount())return;AQHistoryQueued=YES;
    dispatch_async(dispatch_get_main_queue(),^{AQHistoryQueued=NO;[self capture];});
}
+ (void)capture {
    if(AQHistoryApplying)return;NSDictionary *snapshot=AQHistorySnapshot();if(!snapshot)return;NSDictionary *old=AQHistoryRead(@"local-history.plist");
    if([[old objectForKey:@"Token"] isEqual:[snapshot objectForKey:@"Token"]])return;
    if(AQHistoryWrite(@"local-history.plist",snapshot))[AQSafariTabsAdapter requestRefresh];
}
+ (void)applyIncoming {
    if(![NSThread isMainThread]||AQHistoryApplying)return;NSString *account=AQHistoryAccount();NSDictionary *plan=AQHistoryRead(@"history-incoming.plist");
    if(!account||![[plan objectForKey:@"Version"] isEqual:@1]||![[plan objectForKey:@"Account"] isEqual:account])return;
    NSString *transaction=[plan objectForKey:@"Transaction"],*expected=[plan objectForKey:@"Expected"];NSArray *requestedAdd=[plan objectForKey:@"Add"],*remove=[plan objectForKey:@"Remove"];
    if(transaction.length!=36||expected.length!=64||![requestedAdd isKindOfClass:[NSArray class]]||![remove isKindOfClass:[NSArray class]]||requestedAdd.count>5000||remove.count>5000)return;
    NSMutableArray *add=[NSMutableArray arrayWithArray:requestedAdd],*ignored=[NSMutableArray array];for(NSDictionary *entry in requestedAdd)if(![entry isKindOfClass:[NSDictionary class]]||![[entry objectForKey:@"URL"] isKindOfClass:[NSString class]])return;
    if([[[AQHistoryRead(@"history-ack.plist") objectForKey:@"Transaction"] description] isEqual:transaction])return;
    NSDictionary *snapshot=AQHistorySnapshot();BOOL applied=NO;NSString *reason=@"stale";NSString *path=[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Safari/History.plist"];NSData *backup=nil;
    if([[snapshot objectForKey:@"Token"] isEqual:expected]){
        AQHistoryApplying=YES;@try {
            struct stat info;if(lstat(path.fileSystemRepresentation,&info)||!S_ISREG(info.st_mode)||info.st_uid!=getuid()||info.st_size<=0||info.st_size>64*1024*1024)[NSException raise:@"AQHistoryModel" format:@"Native History file unavailable"];
            backup=[NSData dataWithContentsOfFile:path];if(!backup.length)[NSException raise:@"AQHistoryModel" format:@"Native History backup unavailable"];
            if(!AQHistoryApplyOperations(add,remove))[NSException raise:@"AQHistoryModel" format:@"Native History import failed"];
            NSDictionary *after=AQHistorySnapshot();NSMutableDictionary *afterByURL=[NSMutableDictionary dictionary];for(NSDictionary *entry in [after objectForKey:@"Entries"])[afterByURL setObject:entry forKey:[entry objectForKey:@"URL"]];
            for(NSDictionary *entry in add){NSDictionary *actual=[afterByURL objectForKey:[entry objectForKey:@"URL"]];if(!actual){[ignored addObject:[entry objectForKey:@"URL"]];continue;}if([[actual objectForKey:@"Time"] doubleValue]+0.11<[[entry objectForKey:@"Time"] doubleValue]){AQHistoryWrite(@"history-native-diagnostic.plist",@{@"Transaction":transaction,@"Mismatch":@"addition-time",@"ExpectedCount":@(add.count),@"ActualCount":@(afterByURL.count)});[NSException raise:@"AQHistoryModel" format:@"Native History imported an older visit time"];}}
            for(NSString *url in remove)if([afterByURL objectForKey:url]){AQHistoryWrite(@"history-native-diagnostic.plist",@{@"Transaction":transaction,@"Mismatch":@"removal",@"ExpectedCount":@(remove.count),@"ActualCount":@(afterByURL.count)});[NSException raise:@"AQHistoryModel" format:@"Native History retained a removed visit"];}
            applied=YES;reason=@"";
        }@catch(NSException *exception){NSMutableDictionary *diagnostic=[[AQHistoryRead(@"history-native-diagnostic.plist") mutableCopy] autorelease];if(!diagnostic)diagnostic=[NSMutableDictionary dictionary];[diagnostic setObject:transaction forKey:@"Transaction"];[diagnostic setObject:[exception name]?:@"native-exception" forKey:@"Exception"];if([[exception name] isEqual:@"AQHistoryModel"])[diagnostic setObject:[exception reason]?:@"" forKey:@"Reason"];AQHistoryWrite(@"history-native-diagnostic.plist",diagnostic);NSMutableArray *addedURLs=[NSMutableArray array],*restore=[NSMutableArray array];for(NSDictionary *entry in add)if([entry objectForKey:@"URL"])[addedURLs addObject:[entry objectForKey:@"URL"]];for(NSDictionary *entry in [snapshot objectForKey:@"Entries"])if([remove containsObject:[entry objectForKey:@"URL"]])[restore addObject:entry];AQHistoryApplyOperations(restore,addedURLs);applied=NO;reason=@"native-error";}@finally{AQHistoryApplying=NO;}
    }
    [self capture];NSString *token=[AQHistorySnapshot() objectForKey:@"Token"]?:@"";AQHistoryWrite(@"history-ack.plist",@{@"Version":@1,@"Account":account,@"Transaction":transaction,@"Applied":@(applied),@"Reason":reason,@"Token":token,@"Ignored":ignored});[AQSafariTabsAdapter requestRefresh];
}
@end
