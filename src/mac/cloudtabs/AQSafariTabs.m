/* Safari's native tab UI consumes these objects. The adapter never writes to
 * NSUbiquitousKeyValueStore; CloudKit transport runs in the per-user worker. */
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <fcntl.h>
#include <notify.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <spawn.h>
#include <sys/wait.h>
#include <crt_externs.h>
#include <math.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../aquatransport_config.h"
#include "state.h"

static NSArray *AQDevices;
static NSString *AQAccount;
static struct stat AQStamp;
static BOOL AQHaveStamp, AQEventsStarted;
static IMP AQNativeGetter, AQNativeShow, AQNativeChange, AQNativeSave, AQNativeAccount,AQNativeOtherDevice;
static IMP AQNativeHistoryChanged,AQNativeHistoryTitle;
static int AQBootstrapPending;

static BOOL AQEnabled(id value) {return [value isKindOfClass:[NSNumber class]] && [value boolValue];}

static NSString *AQCurrentAccount(void) {
    NSDictionary *prefs=[NSDictionary dictionaryWithContentsOfFile:[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Preferences/MobileMeAccounts.plist"]];
    NSArray *accounts=[prefs objectForKey:@"Accounts"];
    if(![accounts isKindOfClass:[NSArray class]]) return nil;
    NSString *found=nil;
    for(id account in accounts) {
        if(![account isKindOfClass:[NSDictionary class]] || !AQEnabled([account objectForKey:@"LoggedIn"])) continue;
        id services=[account objectForKey:@"Services"];BOOL enabled=NO;
        if(![services isKindOfClass:[NSArray class]]) continue;
        for(id service in services) if([service isKindOfClass:[NSDictionary class]] && [[service objectForKey:@"Name"] isEqual:@"BOOKMARKS"] && AQEnabled([service objectForKey:@"Enabled"])) enabled=YES;
        id dsid=[account objectForKey:@"AccountDSID"];
        if(!enabled || (![dsid isKindOfClass:[NSString class]] && ![dsid isKindOfClass:[NSNumber class]])) continue;
        if(found) return nil;
        found=[dsid description];
    }
    return found;
}

static NSArray *AQDecodeDevices(id cache, NSString *account) {
    if(![cache isKindOfClass:[NSDictionary class]] || !account.length ||
       ![[cache objectForKey:@"Account"] isEqual:account] || ![[cache objectForKey:@"Version"] isEqual:@1]) return nil;
    id devices=[cache objectForKey:@"Devices"];
    if(![devices isKindOfClass:[NSDictionary class]] || [devices count]>100) return nil;
    Class native=NSClassFromString(@"CloudTabDevice");
    if(!native || ![native instancesRespondToSelector:NSSelectorFromString(@"initWithDictionary:uuid:")]) return nil;
    NSMutableArray *result=[NSMutableArray array];NSUInteger count=0;
    for(id identifier in devices) {
        id device=[devices objectForKey:identifier];
        if(![identifier isKindOfClass:[NSString class]] || ![identifier length] || [identifier length]>256 || ![device isKindOfClass:[NSDictionary class]]) return nil;
        id name=[device objectForKey:@"DeviceName"],modified=[device objectForKey:@"LastModified"],tabs=[device objectForKey:@"Tabs"];
        if(![name isKindOfClass:[NSString class]] || ![name length] || [name length]>1024 || ![modified isKindOfClass:[NSDate class]] || ![tabs isKindOfClass:[NSArray class]]) return nil;
        if(!isfinite([modified timeIntervalSinceReferenceDate])) return nil;
        count+=[tabs count];if(count>10000) return nil;
        NSMutableArray *clean=[NSMutableArray array];
        for(id tab in tabs) {
            if(![tab isKindOfClass:[NSDictionary class]]) return nil;
            id title=[tab objectForKey:@"Title"],address=[tab objectForKey:@"URL"];
            if(![title isKindOfClass:[NSString class]] || [title length]>65536 || ![address isKindOfClass:[NSString class]] || [address length]>131072) return nil;
            NSURL *url=[NSURL URLWithString:address];NSString *scheme=[[url scheme] lowercaseString];
            if(![@[@"http",@"https",@"ftp"] containsObject:scheme?:@""]) return nil;
            [clean addObject:@{@"Title":title,@"URL":address}];
        }
        if(!clean.count) continue;
        NSDictionary *dictionary=@{@"DeviceName":name,@"LastModified":modified,@"Tabs":clean};
        id object=((id(*)(id,SEL,id,id))objc_msgSend)([native alloc],NSSelectorFromString(@"initWithDictionary:uuid:"),dictionary,identifier);
        if(!object) return nil;
        [result addObject:object];[object release];
    }
    return result;
}

static BOOL AQRefresh(void) {
    NSString *account=AQCurrentAccount();
    if(tf_flag("disable-safari-cloudtabs")) account=nil;
    NSString *path=[AQCloudTabsStateDirectory() stringByAppendingPathComponent:@"devices.plist"];
    int fd=account?open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW):-1;
    struct stat stamp;memset(&stamp,0,sizeof stamp);
    BOOL valid=fd>=0 && !fstat(fd,&stamp) && S_ISREG(stamp.st_mode) && stamp.st_uid==getuid() && !(stamp.st_mode&077) && stamp.st_size>0 && stamp.st_size<=4*1024*1024;
    BOOL sameAccount=(account==AQAccount || [account isEqual:AQAccount]);
    if(valid && AQHaveStamp && sameAccount && stamp.st_ino==AQStamp.st_ino && stamp.st_size==AQStamp.st_size &&
       stamp.st_mtimespec.tv_sec==AQStamp.st_mtimespec.tv_sec && stamp.st_mtimespec.tv_nsec==AQStamp.st_mtimespec.tv_nsec) {close(fd);return NO;}
    NSArray *fresh=nil;
    if(valid) {
        NSMutableData *data=[NSMutableData dataWithLength:(NSUInteger)stamp.st_size];
        char *p=data.mutableBytes;size_t left=data.length;
        while(left) {ssize_t n=read(fd,p,left);if(n<0 && errno==EINTR) continue;if(n<=0) {valid=NO;break;}p+=n;left-=n;}
        if(valid) {
            id cache=[NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL];
            @try {fresh=AQDecodeDevices(cache,account);}
            @catch(NSException *exception) {fresh=nil;}
        }
    }
    if(fd>=0) close(fd);
    BOOL changed=(!sameAccount || AQDevices.count || fresh.count);
    [AQDevices release];AQDevices=[fresh copy];[AQAccount release];AQAccount=[account copy];
    AQHaveStamp=valid;AQStamp=stamp;
    return changed;
}

@interface AQSafariTabsAdapter : NSObject
+ (id)devicesForStore:(id)store native:(id)native;
+ (BOOL)installForCurrentProcess;
+ (void)startEvents;
+ (void)cacheChanged;
+ (void)requestRefresh;
+ (void)startForCurrentProcess;
+ (void)applicationDidLaunch:(NSNotification *)notification;
+ (void)savedDictionary:(id)dictionary forKey:(id)key;
+ (void)removedDictionaryForKey:(id)key;
@end


static id AQGetter(id self,SEL command) {
    id native=((id(*)(id,SEL))AQNativeGetter)(self,command);
    return [AQSafariTabsAdapter devicesForStore:self native:native];
}

static void AQShown(id self,SEL cmd,id notification) {
    ((void(*)(id,SEL,id))AQNativeShow)(self,cmd,notification);[AQSafariTabsAdapter requestRefresh];
}
static void AQChanged(id self,SEL cmd,id notification) {
    ((void(*)(id,SEL,id))AQNativeChange)(self,cmd,notification);[AQSafariTabsAdapter requestRefresh];
}
static void AQSaved(id self,SEL cmd) {
    ((void(*)(id,SEL))AQNativeSave)(self,cmd);[AQSafariTabsAdapter requestRefresh];
}
static void AQAccountChanged(id self,SEL cmd,id notification) {
    ((void(*)(id,SEL,id))AQNativeAccount)(self,cmd,notification);[AQSafariTabsAdapter cacheChanged];[AQSafariTabsAdapter requestRefresh];
    Class bookmarks=NSClassFromString(@"AQSafariBookmarksAdapter");if(bookmarks)((void(*)(id,SEL))objc_msgSend)(bookmarks,NSSelectorFromString(@"startEvents"));
}
static void AQHistoryChanged(id self,SEL cmd,BOOL removals) {
    ((void(*)(id,SEL,BOOL))AQNativeHistoryChanged)(self,cmd,removals);
    Class adapter=NSClassFromString(@"AQSafariHistoryAdapter");if(adapter)((void(*)(id,SEL))objc_msgSend)(adapter,NSSelectorFromString(@"nativeChanged"));
}
static void AQHistoryTitleChanged(id self,SEL cmd,void *item) {
    ((void(*)(id,SEL,void *))AQNativeHistoryTitle)(self,cmd,item);
    Class adapter=NSClassFromString(@"AQSafariHistoryAdapter");if(adapter)((void(*)(id,SEL))objc_msgSend)(adapter,NSSelectorFromString(@"nativeChanged"));
}
static BOOL AQOtherDevice(id self,SEL selector) {
    BOOL native=((BOOL(*)(id,SEL))AQNativeOtherDevice)(self,selector);
    if(native || tf_flag("disable-safari-cloudtabs"))return native;
    @synchronized([AQSafariTabsAdapter class]) {AQRefresh();return AQDevices.count>0;}
}
static void AQBridgeDeviceRegistration(void) {
    Class cls=NSClassFromString(@"CloudTabStore");SEL selector=NSSelectorFromString(@"_atLeastOneOtherActiveDeviceIsRegistered");
    Method method=class_getInstanceMethod(cls,selector);char type[8]={0};Dl_info owner;
    if(!method || method_getNumberOfArguments(method)!=2)return;
    method_getReturnType(method,type,sizeof type);if(strcmp(type,"c") && strcmp(type,"B"))return;
    IMP implementation=method_getImplementation(method);
    if(!dladdr((void *)implementation,&owner) || !owner.dli_fname || !strstr(owner.dli_fname,"/Safari.framework/"))return;
    AQNativeOtherDevice=method_setImplementation(method,(IMP)AQOtherDevice);
}
static void AQScheduleForModernDevices(void) {
    if(!AQNativeOtherDevice || !AQDevices.count)return;
    id store=((id(*)(id,SEL))objc_msgSend)(NSClassFromString(@"CloudTabStore"),NSSelectorFromString(@"sharedCloudTabStore"));
    SEL active=NSSelectorFromString(@"_atLeastOneOtherActiveDeviceIsRegistered");
    // Bring the existing native scheduler up to date when only modern devices
    // are registered. Its ordinary timer and coalescing behavior remain intact.
    if(!((BOOL(*)(id,SEL))AQNativeOtherDevice)(store,active) && [store respondsToSelector:NSSelectorFromString(@"saveTabsForCurrentDeviceSoon")])
        ((void(*)(id,SEL))objc_msgSend)(store,NSSelectorFromString(@"saveTabsForCurrentDeviceSoon"));
}
static void AQHook(const char *className,const char *selector,unsigned arguments,IMP replacement,IMP *original) {
    Class cls=objc_getClass(className);Method m=cls?class_getInstanceMethod(cls,sel_registerName(selector)):NULL;
    if(!m || method_getNumberOfArguments(m)!=arguments) return;
    char type[8]={0};method_getReturnType(m,type,sizeof type);if(strcmp(type,"v")) return;
    Dl_info owner;IMP implementation=method_getImplementation(m);
    if(!dladdr((void *)implementation,&owner) || !owner.dli_fname || !strstr(owner.dli_fname,"/Safari.framework/")) return;
    *original=method_setImplementation(m,replacement);
}
static void AQEnsureWorker(void *unused) {
    (void)unused;
    char *arguments[]={"aquatransport-bootstrap","--user-features",NULL};
    pid_t child=0;
    int error=posix_spawn(&child,"/usr/share/aquatransport/aquatransport-bootstrap",NULL,NULL,arguments,*_NSGetEnviron());
    if(!error) {int status;while(waitpid(child,&status,0)<0 && errno==EINTR) {}}
    __sync_lock_test_and_set(&AQBootstrapPending,0);
}
static void AQDeliver(void *unused) {(void)unused;[AQSafariTabsAdapter cacheChanged];}
static void AQUpdated(CFNotificationCenterRef center,void *observer,CFStringRef name,const void *object,CFDictionaryRef info) {
    (void)center;(void)observer;(void)name;(void)object;(void)info;
    dispatch_async_f(dispatch_get_main_queue(),NULL,AQDeliver);
}

@implementation AQSafariTabsAdapter
+ (void)startForCurrentProcess {
    if(![[[NSBundle mainBundle] bundleIdentifier] isEqual:@"com.apple.Safari"] || ![NSThread isMainThread])return;
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(applicationDidLaunch:) name:NSApplicationDidFinishLaunchingNotification object:nil];
    if([[NSRunningApplication currentApplication] isFinishedLaunching])[self applicationDidLaunch:nil];
}
+ (void)applicationDidLaunch:(NSNotification *)notification {
    (void)notification;
    [[NSNotificationCenter defaultCenter] removeObserver:self name:NSApplicationDidFinishLaunchingNotification object:nil];
    [self startEvents];
}
+ (void)savedDictionary:(id)dictionary forKey:(id)key {
    if(![NSThread isMainThread] || tf_flag("disable-safari-cloudtabs") || ![dictionary isKindOfClass:[NSDictionary class]] || ![key isKindOfClass:[NSString class]])return;
    CFPropertyListRef identifier=CFPreferencesCopyValue(CFSTR("SyncedTabsDeviceUUID"),CFSTR("com.apple.Safari"),kCFPreferencesCurrentUser,kCFPreferencesCurrentHost);
    BOOL own=identifier && CFGetTypeID(identifier)==CFStringGetTypeID() && [key isEqual:(NSString *)identifier];
    if(identifier)CFRelease(identifier);if(!own)return;
    NSString *account=AQCurrentAccount();if(!account.length)return;
    id name=[dictionary objectForKey:@"DeviceName"];
    id tabs=[dictionary objectForKey:@"Tabs"],modified=[dictionary objectForKey:@"LastModified"];
    if(![name isKindOfClass:[NSString class]] || ![name length] || [name length]>1024 || ![tabs isKindOfClass:[NSArray class]] || [tabs count]>10000 || ![modified isKindOfClass:[NSDate class]])return;
    NSMutableArray *clean=[NSMutableArray array];
    for(id tab in tabs) {
        if(![tab isKindOfClass:[NSDictionary class]])return;
        id title=[tab objectForKey:@"Title"],url=[tab objectForKey:@"URL"];
        if(![title isKindOfClass:[NSString class]] || [title length]>65536 || ![url isKindOfClass:[NSString class]] || [url length]>131072)return;
        if(![@[@"http",@"https",@"ftp"] containsObject:[[[NSURL URLWithString:url] scheme] lowercaseString]?:@""])continue;
        [clean addObject:@{@"Title":title,@"URL":url}];
    }
    NSString *directory=AQCloudTabsStateDirectory();struct stat info;
    if(lstat(directory.fileSystemRepresentation,&info) || !S_ISDIR(info.st_mode) || info.st_uid!=getuid() || (info.st_mode&077))return;
    NSDictionary *snapshot=@{@"Version":@1,@"Account":account,@"DeviceID":key,@"DeviceName":name,@"Tabs":clean,@"LastModified":modified};
    NSData *data=[NSPropertyListSerialization dataWithPropertyList:snapshot format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    if(!data.length || data.length>4*1024*1024)return;
    NSString *temporary=[directory stringByAppendingPathComponent:[NSString stringWithFormat:@"local-tabs-%@.new",[[NSUUID UUID] UUIDString]]];
    int fd=open(temporary.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(fd<0)return;
    const char *bytes=data.bytes;size_t left=data.length;BOOL ok=YES;
    while(left) {ssize_t count=write(fd,bytes,left);if(count<0 && errno==EINTR)continue;if(count<=0){ok=NO;break;}bytes+=count;left-=count;}
    if(fsync(fd))ok=NO;close(fd);
    if(ok)ok=!rename(temporary.fileSystemRepresentation,[[directory stringByAppendingPathComponent:@"local-tabs.plist"] fileSystemRepresentation]);
    if(!ok)unlink(temporary.fileSystemRepresentation);
    if(ok){[self startEvents];[self requestRefresh];}
}
+ (void)removedDictionaryForKey:(id)key {
    id store=((id(*)(id,SEL))objc_msgSend)(NSClassFromString(@"CloudTabStore"),NSSelectorFromString(@"sharedCloudTabStore"));
    if(![store respondsToSelector:NSSelectorFromString(@"_currentDeviceName")])return;
    id name=((id(*)(id,SEL))objc_msgSend)(store,NSSelectorFromString(@"_currentDeviceName"));
    if(name)[self savedDictionary:@{@"DeviceName":name,@"LastModified":[NSDate date],@"Tabs":@[]} forKey:key];
}
+ (id)devicesForStore:(id)store native:(id)native {
    if(tf_flag("disable-safari-cloudtabs") || ![store respondsToSelector:NSSelectorFromString(@"cloudTabsSupported")] || !((BOOL(*)(id,SEL))objc_msgSend)(store,NSSelectorFromString(@"cloudTabsSupported"))) return native;
    if([NSThread isMainThread]) [self startEvents];
    else [self performSelectorOnMainThread:@selector(startEvents) withObject:nil waitUntilDone:NO];
    @synchronized(self) {
        AQRefresh();
        if(!AQDevices.count) return native;
        NSMutableArray *result=[NSMutableArray array];NSMutableSet *identifiers=[NSMutableSet set];
        if([native isKindOfClass:[NSArray class]]) for(id device in native) {
            [result addObject:device];id identifier=[device valueForKey:@"uuid"];if(identifier) [identifiers addObject:identifier];
        }
        for(id device in AQDevices) if(![identifiers containsObject:[device valueForKey:@"uuid"]]) [result addObject:device];
        return result;
    }
}
+ (void)startEvents {
    if(AQEventsStarted || ![NSThread isMainThread]) return;
    AQEventsStarted=YES;
    NSString *name=[NSString stringWithFormat:@"org.aquatransport.cloudtabs.updated.%u",getuid()];
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),NULL,AQUpdated,(CFStringRef)name,NULL,CFNotificationSuspensionBehaviorDeliverImmediately);
    AQHook("CloudTabsPopoverViewController","popoverWillShow:",3,(IMP)AQShown,&AQNativeShow);
    AQHook("CloudTabStore","_keyValueStoreDidChangeExternally:",3,(IMP)AQChanged,&AQNativeChange);
    AQHook("CloudTabStore","saveTabsForCurrentDevice",2,(IMP)AQSaved,&AQNativeSave);
    AQHook("CloudTabStore","_iCloudLoggedInStateDidChange:",3,(IMP)AQAccountChanged,&AQNativeAccount);
    AQHook("GlobalHistoryObjC","entriesChangedIncludingRemovals:",3,(IMP)AQHistoryChanged,&AQNativeHistoryChanged);
    AQHook("GlobalHistoryObjC","titleDidChangeForItem:",3,(IMP)AQHistoryTitleChanged,&AQNativeHistoryTitle);
    AQBridgeDeviceRegistration();
    @synchronized(self) {AQRefresh();AQScheduleForModernDevices();}
    Class bookmarks=NSClassFromString(@"AQSafariBookmarksAdapter");
    if(bookmarks)((void(*)(id,SEL))objc_msgSend)(bookmarks,NSSelectorFromString(@"startEvents"));
    Class history=NSClassFromString(@"AQSafariHistoryAdapter");
    if(history)((void(*)(id,SEL))objc_msgSend)(history,NSSelectorFromString(@"startEvents"));
    // The first getter may already be inside popoverWillShow when the lazy
    // module loads. Bridge that first access once; later reads use the cache.
    [self requestRefresh];
}
+ (void)requestRefresh {
    if(tf_flag("disable-safari-cloudtabs") || !AQCurrentAccount().length) return;
    NSString *name=[NSString stringWithFormat:@"org.aquatransport.cloudtabs.refresh.%u",getuid()];
    notify_post(name.UTF8String);
    // Register through the existing coordinator in this GUI session. Calls
    // are coalesced while it runs; there is no login watcher or refresh timer.
    if(__sync_bool_compare_and_swap(&AQBootstrapPending,0,1))
        dispatch_async_f(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),NULL,AQEnsureWorker);
}
+ (void)cacheChanged {
    @synchronized(self) {AQRefresh();AQScheduleForModernDevices();}
    // A getter may already have read the new file before this completion
    // notification reaches the main queue. Still forward the change to views.
    id store=((id(*)(id,SEL))objc_msgSend)(NSClassFromString(@"CloudTabStore"),NSSelectorFromString(@"sharedCloudTabStore"));
    [[NSNotificationCenter defaultCenter] postNotificationName:@"SyncedCloudTabDevicesDidChangeNotification" object:store];
    Class bookmarks=NSClassFromString(@"AQSafariBookmarksAdapter");if(bookmarks)((void(*)(id,SEL))objc_msgSend)(bookmarks,NSSelectorFromString(@"startEvents"));
}
+ (BOOL)installForCurrentProcess {
    if(![[[NSBundle mainBundle] bundleIdentifier] isEqual:@"com.apple.Safari"]) return NO;
    @synchronized(self) {
        if(AQNativeGetter) return YES;
        Class store=NSClassFromString(@"CloudTabStore");
        Method method=class_getInstanceMethod(store,NSSelectorFromString(@"syncedCloudTabDevices"));
        if(!method || method_getNumberOfArguments(method)!=2) return NO;
        char type[8]={0};method_getReturnType(method,type,sizeof type);if(strcmp(type,"@")) return NO;
        AQNativeGetter=method_setImplementation(method,(IMP)AQGetter);
    }
    [self startEvents];[self cacheChanged];return YES;
}
@end

#include "preferences.inc"
#include "bookmarks.inc"
#include "history.inc"
