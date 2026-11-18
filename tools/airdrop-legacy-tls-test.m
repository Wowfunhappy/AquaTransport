#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <assert.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
static BOOL native_mode;
#define AQ_NATIVE_MODE native_mode
#include "../src/mac/airdrop/AQLegacyTLS.inc"
#include "../src/mac/airdrop/AQLegacyDH.h"
static void remember(id client,NSString *url) { remember_legacy_peer(client,(__bridge CFURLRef)[NSURL URLWithString:url]); }
int main(void) { @autoreleasepool {
    native_mode=YES;
    assert(!AQAirDropNativePeer("test.local"));
    NSObject *one=[NSObject new],*two=[NSObject new];
    remember(one,@"https://Test.local.:1234/Ask");
    assert(AQAirDropNativePeer("test.local") && AQAirDropNativePeer("TEST.LOCAL."));
    assert(!AQAirDropNativePeer(NULL) && !AQAirDropNativePeer("other.local"));
    remember(two,@"https://test.local:1234/Upload");
    remember(two,@"https://test.local:1234/Upload"); // Same client does not leak a reference.
    native_mode=NO; assert(!AQAirDropNativePeer("test.local")); native_mode=YES;
    one=nil; assert(AQAirDropNativePeer("test.local"));
    two=nil; assert(!AQAirDropNativePeer("test.local"));
    @autoreleasepool {
        NSObject *client=[NSObject new];
        remember(client,@"https://first.local/Ask");
        remember(client,@"https://second.local/Ask");
        assert(!AQAirDropNativePeer("first.local") && AQAirDropNativePeer("second.local"));
    }
    assert(!AQAirDropNativePeer("second.local"));
    NSObject *client=[NSObject new];
    remember(client,@"https://example.com/Ask"); assert(!AQAirDropNativePeer("example.com"));
    remember(client,@"https://test.local.example.com/Ask"); assert(!AQAirDropNativePeer("test.local.example.com"));
    remember(client,@"http://test.local/Ask"); assert(!AQAirDropNativePeer("test.local"));
    assert(!legacy_peer_hosts.count);
    const unsigned char *cursor=legacy_dh_params;
    DH *dh=d2i_DHparams(NULL,&cursor,sizeof(legacy_dh_params));
    assert(dh && cursor==legacy_dh_params+sizeof(legacy_dh_params));
    const BIGNUM *p=NULL,*g=NULL; DH_get0_pqg(dh,&p,NULL,&g);
    BIGNUM *expected=BN_get_rfc3526_prime_2048(NULL);
    assert(BN_num_bits(p)==2048 && BN_cmp(p,expected)==0 && BN_is_word(g,2));
    BN_free(expected); DH_free(dh);
    puts("PASS: native TLS limited to active local AirDrop peers, parallel-client lifetime and mode boundaries; server DH parameters are RFC 3526 group 14");
} return 0; }
