/* Legacy AirDrop uses native TLS on the sending side. Track only local Bonjour
 * hosts named by live SDWormholeClient requests, never arbitrary sharingd HTTPS.
 * The lease is attached to the client so parallel transfers and cleanup compose. */
#include "AQModeScope.h"
static NSCountedSet *legacy_peer_hosts;
static char legacy_peer_key;
static NSString *legacy_host(NSString *host) {
    host=host.lowercaseString;
    if([host hasSuffix:@"."]) host=[host substringToIndex:host.length-1];
    return host.length<=255 && [host hasSuffix:@".local"] ? host : nil;
}
@interface AQLegacyPeer : NSObject
@property(copy) NSString *host;
@end
@implementation AQLegacyPeer
- (void)dealloc {
    @synchronized([AQLegacyPeer class]) { [legacy_peer_hosts removeObject:_host]; }
}
@end
static void remember_legacy_peer(id client,CFURLRef url) {
    if(!url || ![[(__bridge NSURL *)url scheme] isEqualToString:@"https"]) return;
    NSString *host=legacy_host(CFBridgingRelease(CFURLCopyHostName(url)));
    if(!host) return;
    AQLegacyPeer *peer=objc_getAssociatedObject(client,&legacy_peer_key);
    if([peer.host isEqualToString:host]) return;
    peer=[AQLegacyPeer new]; peer.host=host;
    @synchronized([AQLegacyPeer class]) {
        if(!legacy_peer_hosts) legacy_peer_hosts=[NSCountedSet new];
        [legacy_peer_hosts addObject:host];
    }
    objc_setAssociatedObject(client,&legacy_peer_key,peer,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}
__attribute__((visibility("default"))) int AQAirDropNativePeer(const char *host) {
    if(!AQ_NATIVE_MODE || !host || !*host) return 0;
    NSString *name=legacy_host([NSString stringWithUTF8String:host]);
    if(!name) return 0;
    @synchronized([AQLegacyPeer class]) { return [legacy_peer_hosts countForObject:name]!=0; }
}
