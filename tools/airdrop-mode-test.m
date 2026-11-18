#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <assert.h>
static BOOL native_mode;
static NSUInteger active_transfers;
static NSHashTable *active_browsers,*active_servers;
static NSHashTable *pending_browsers,*pending_servers;
static NSMutableArray *events;
@interface CachedBrowser : NSObject
@property(copy) NSArray *services;
@property(copy) NSArray *published;
- (void)clearCacheAndNotify;
@end
@implementation CachedBrowser
- (void)clearCacheAndNotify {
    [events addObject:@"browser notify"];
    dispatch_async(dispatch_get_main_queue(),^{ self.published=self.services; });
}
@end
@interface AQTransferLease : NSObject @end
@implementation AQTransferLease @end
static void stop_browser(id browser,SEL selector) { (void)selector; [events addObject:@"browser stop"]; [(CachedBrowser *)browser setServices:@[]]; [active_browsers removeObject:browser]; }
static void stop_server(id server,SEL selector) { (void)selector; [events addObject:@"server stop"]; [active_servers removeObject:server]; }
static void start_browser(id browser,SEL selector) { (void)selector; [events addObject:@"browser start"]; [active_browsers addObject:browser]; }
static void start_server(id server,SEL selector) { (void)selector; [events addObject:@"server start"]; [active_servers addObject:server]; }
static void restart_server(id server) { start_server(server,@selector(start)); }
static void force_stop_radio(void) { [events addObject:@"radio stop"]; }
#include "../src/mac/airdrop/AQMode.inc"
#include "../src/mac/airdrop/AQPendingRetry.inc"
static NSUInteger mode_notifications;
static BOOL notified_native;
static void mode_notification(id center,SEL selector,NSString *name,id object,NSDictionary *info,BOOL immediate) {
    (void)center; (void)selector; (void)object; (void)immediate;
    assert([name isEqual:AQModeChanged]);
    ++mode_notifications; notified_native=[info[@"native"] boolValue];
}
static void drain(void) { [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]]; }
int main(void) { @autoreleasepool {
    // Keep fixture requests/acknowledgments inside this process, so the test
    // cannot switch a running sharingd or change Finder's displayed mode.
    Method post=class_getInstanceMethod([NSDistributedNotificationCenter class],
        @selector(postNotificationName:object:userInfo:deliverImmediately:));
    assert(post); method_setImplementation(post,(IMP)mode_notification);
    events=[NSMutableArray array]; active_browsers=[NSHashTable weakObjectsHashTable]; active_servers=[NSHashTable weakObjectsHashTable];
    pending_browsers=[NSHashTable weakObjectsHashTable]; pending_servers=[NSHashTable weakObjectsHashTable];
    CachedBrowser *browser=[CachedBrowser new]; browser.services=@[@"Test iPhone"]; browser.published=browser.services;
    NSObject *server=[NSObject new]; [active_browsers addObject:browser]; [active_servers addObject:server];
    mode_observer=[AQModeObserver new];
    active_transfers=1;
    [mode_observer modeRequested:[NSNotification notificationWithName:AQModeRequest
        object:nil userInfo:@{@"native":@YES}]];
    drain(); assert(!native_mode && !events.count && !mode_notifications);
    active_transfers=0; apply_pending_mode(); drain();
    assert(native_mode);
    assert(mode_notifications==1 && notified_native);
    assert(browser.published.count==0);
    assert(([events isEqual:@[@"browser stop",@"server stop",@"browser notify",@"radio stop",@"server start",@"browser start"]]));
    [events removeAllObjects];
    [mode_observer modeRequested:[NSNotification notificationWithName:AQModeRequest
        object:nil userInfo:@{@"native":@NO}]];
    drain(); assert(!native_mode);
    assert(mode_notifications==2 && !notified_native);
    assert(([events isEqual:@[@"browser stop",@"server stop",@"browser notify",@"server start",@"browser start"]]));
    [mode_observer modeRequested:[NSNotification notificationWithName:AQModeRequest
        object:nil userInfo:@{@"native":@YES}]];
    drain(); assert(native_mode);
    mode_heartbeat_at=0; expire_mode_owner(); drain(); assert(!native_mode);
    assert(mode_notifications==4 && !notified_native);
    [events removeAllObjects];
    [pending_servers addObject:server];
    retry_pending_radio(YES);
    assert(([events isEqual:@[@"server start"]]));
    [events removeAllObjects];
    [active_browsers removeObject:browser]; // Finder closed while the receiver was still pending.
    retry_pending_radio(YES);
    assert(!events.count);
    [active_browsers addObject:browser];
    retry_pending_radio(NO);
    assert(!events.count);
    puts("PASS: mode changes defer during transfers, clear Finder's stale peers, restart native owners, and restore modern discovery on request or expired Finder session");
    puts("PASS: pending receiver retries stop when Finder closes or Bluetooth or Wi-Fi is off");
    return 0;
} }
