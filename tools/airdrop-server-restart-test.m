#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <assert.h>

static NSHashTable *active_servers;
static unsigned drains;
static void drain_after_stop(id server) { (void)server; ++drains; }
#include "../src/mac/airdrop/AQServerRestart.inc"

// Model the native lifecycle verified in Mavericks sharingd: stop clears the
// listener immediately, but gCurrentServer and the publisher survive until the
// terminal callback. startHTTPServer refuses while gCurrentServer is occupied;
// only full start restores the timestamp used by publishedInfoChanged:.
static id current;
@interface Receiver : NSObject {
@public id _publisher;
}
@property BOOL listening, started, published;
@property unsigned starts;
- (void)startHTTPServer;
- (void)stop;
- (void)finishClosing;
@end
@implementation Receiver
- (void)start {
    ++_starts;
    _started=YES;
    [self startHTTPServer];
}
- (void)startHTTPServer {
    if(current) return;
    current=self; _listening=YES; _publisher=[NSObject new];
    if(_started) _published=YES;
}
- (void)stop { _started=NO; _listening=NO; }
- (void)finishClosing {
    assert(current==self && !_listening);
    current=nil; _publisher=nil; _published=NO;
    // Native airDropUnpublished: ignores this object's own notification.
    [[NSNotificationCenter defaultCenter] postNotificationName:@"com.apple.sharingd.AirDropUnpublished" object:self];
}
@end
static void close_receiver(Receiver *receiver) {
    cancel_server_restart(receiver);
    [active_servers removeObject:receiver];
    [receiver stop];
}
int main(void) { @autoreleasepool {
    active_servers=[NSHashTable weakObjectsHashTable];
    server_publisher_offset=ivar_getOffset(class_getInstanceVariable([Receiver class],"_publisher"));
    install_server_restart_observer();
    Receiver *receiver=[Receiver new];
    [receiver start]; assert(receiver.listening && receiver.published);
    // Reproduce the old handoff: an immediate low-level restart is refused,
    // and the same receiver's shutdown notification does not restart it.
    [receiver stop]; [receiver startHTTPServer]; [receiver finishClosing];
    assert(!receiver.listening && !receiver.published);
    // Even after shutdown, a low-level start alone does not restore publication.
    [receiver startHTTPServer]; assert(receiver.listening && !receiver.published);
    [receiver stop]; [receiver finishClosing];

    // Both directions use the same path; repeated transitions must republish.
    for(int i=0;i<4;i++) {
        [receiver start]; unsigned starts=receiver.starts;
        close_receiver(receiver); restart_server(receiver);
        assert(receiver.starts==starts && !receiver.listening);
        assert([restarting_servers containsObject:receiver]);
        [receiver finishClosing];
        assert(receiver.starts==starts+1 && receiver.listening && receiver.started && receiver.published);
        assert(!restarting_servers.count);
        close_receiver(receiver); [receiver finishClosing];
        assert(!receiver.listening && !receiver.published);
    }
    assert(drains==4);
    // Finder leaving while the old listener closes cancels its queued restart.
    [receiver start]; close_receiver(receiver); restart_server(receiver);
    close_receiver(receiver); unsigned starts=receiver.starts;
    [receiver finishClosing]; assert(receiver.starts==starts && !receiver.listening);
    // A receiver that never started has no publisher or terminal callback.
    restart_server(receiver); assert(receiver.listening && receiver.published);
    close_receiver(receiver); [receiver finishClosing];
    // Completed synchronous shutdown before restart is also handled.
    [receiver start]; close_receiver(receiver); [receiver finishClosing];
    restart_server(receiver); assert(receiver.listening && receiver.published);
    close_receiver(receiver); [receiver finishClosing];
    // An unrelated receiver's notification must not wake the pending receiver.
    [receiver start]; close_receiver(receiver); restart_server(receiver);
    starts=receiver.starts;
    [[NSNotificationCenter defaultCenter] postNotificationName:@"com.apple.sharingd.AirDropUnpublished" object:[NSObject new]];
    assert(receiver.starts==starts && !receiver.listening);
    [receiver finishClosing]; assert(receiver.starts==starts+1 && receiver.published);
    close_receiver(receiver); [receiver finishClosing];
    puts("PASS: reproduces refused native restart and missing publication; waits for same-receiver shutdown, restores full start, cancels on close, handles repeated transitions and unrelated notifications");
} return 0; }
