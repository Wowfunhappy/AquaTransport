/* Native backend diagnostic. Never reads credentials or signs in. The normal
 * adapter uses IPC; this diagnostic directly checks the helper's shared backend. */
#define AQ_NATIVE_DIAGNOSTIC 1
#include "../src/mac/aquatransport_gsa.m"
#include "local-anisette-fixture.h"

static int scenario, calls;
static id localOTP(id self, SEL selector, id owner, NSError **error) {
    calls++;
    switch (scenario) {
        case 14: return @{@"X-Apple-MD":@"otp", @"X-Apple-MD-M":@"machine", @"X-Apple-I-MD-RINFO":@"12345"};
        case 11: return @{@"X-Apple-MD":@"otp", @"X-Apple-MD-M":@"machine", @"X-Apple-I-MD-RINFO":@"12345", @"device":@"00000000-0000-4000-8000-000000000001"};
        case 12: return @{@"X-Apple-MD":@"otp", @"X-Apple-MD-M":@"machine", @"X-Apple-I-MD-RINFO":@"12345", @"device":@42};
        case 13: return @{@"X-Apple-MD":@"otp", @"X-Apple-MD-M":@"machine", @"X-Apple-I-MD-RINFO":@"12345", @"device":@"bad\nidentity"};
        case 1: return nil;
        case 2: return @[];
        case 3: return @{};
        case 4: return @{@"X-Apple-MD": @"otp", @"X-Apple-I-MD-RINFO": @"12345"};
        case 5: return @{@"X-Apple-MD": @42, @"X-Apple-MD-M": @"machine", @"X-Apple-I-MD-RINFO": @"12345"};
        case 6: return @{@"X-Apple-MD": @"", @"X-Apple-MD-M": @"machine", @"X-Apple-I-MD-RINFO": @"12345"};
        case 7: return @{@"X-Apple-MD": @"otp\r\ninjected", @"X-Apple-MD-M": @"machine", @"X-Apple-I-MD-RINFO": @"12345"};
        case 8: return @{@"X-Apple-MD": [@"x" stringByPaddingToLength:16385 withString:@"x" startingAtIndex:0], @"X-Apple-MD-M": @"machine", @"X-Apple-I-MD-RINFO": @"12345"};
        case 9: [NSException raise:@"FixtureException" format:@"must not escape or be logged"]; return nil;
        case 10: return @{@"X-Apple-MD": @"otp", @"X-Apple-MD-M": @"bad\nmachine", @"X-Apple-I-MD-RINFO": @"12345"};
    }
    return @{@"X-Apple-MD": @"otp", @"X-Apple-MD-M": @"machine", @"X-Apple-I-MD-RINFO": @"12345",
        @"device": AQTestDevice, @"Authorization": @"must-not-forward", @"X-MMe-Client-Info": @"must-not-forward"};
}

@interface AQNoNetwork : NSURLProtocol @end
@implementation AQNoNetwork
+ (BOOL)canInitWithRequest:(NSURLRequest *)r { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)stopLoading {}
- (void)startLoading { assert(!"Local Anisette must not make HTTP requests"); }
@end

static int validationScenario, validationRequests;
@interface AQValidationFixture : NSURLProtocol @end
@implementation AQValidationFixture
+ (BOOL)canInitWithRequest:(NSURLRequest *)r { return [[[r URL] path] isEqual:@"/grandslam/GsService2/validate"]; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)stopLoading {}
- (void)startLoading {
    validationRequests++;
    NSDictionary *body = @{@"ec":@0};
    NSDictionary *headers = @{@"X-Apple-PE-Token":@"Y29tLmFwcGxlLmdzLmlkbXMucGV0OmZha2UtcGV0"};
    int status = 200;
    switch (validationScenario) {
        case 1: body = @{@"Status":@{@"ec":@0}}; break;
        case 2: headers = nil; break;
        case 3: body = @{@"ec":@-21669}; break;
        case 4: body = @{@"Status":@{@"ec":@-21669}}; break;
        case 5: body = @{@"ec":@"0"}; break;
        case 6: body = @{}; break;
        case 7: headers = @{@"X-Apple-PE-Token":@"malformed"}; break;
        case 8: status = 503; break;
        case 9: body = @{@"ec":@0.5}; break;
    }
    NSHTTPURLResponse *r = [[[NSHTTPURLResponse alloc] initWithURL:[[self request] URL] statusCode:status HTTPVersion:@"HTTP/1.1" headerFields:headers] autorelease];
    [[self client] URLProtocol:self didReceiveResponse:r cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [[self client] URLProtocol:self didLoadData:aq_encode(body)];
    [[self client] URLProtocolDidFinishLoading:self];
}
@end

#include "anisette-provision-fixture.h"

int main(int argc, char **argv) {
    NSAutoreleasePool *pool = [NSAutoreleasePool new];
    [NSURLProtocol registerClass:[AQNoNetwork class]];
    if (argc == 2 && !strcmp(argv[1], "--selftest")) {
        NSMutableURLRequest *ids = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:
            @"https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateUser"]];
        [ids setHTTPMethod:@"POST"];
        [ids setValue:@"client-a" forHTTPHeaderField:@"x-ds-client-id"];
        [ids setValue:@"7" forHTTPHeaderField:@"x-protocol-version"];
        NSDictionary *input = @{@"username":@"test@example.invalid", @"password":@"synthetic123456"};
        NSDictionary *completed = @{@"test":@"completed-delegate"};
        aq_ids_retry_remember(ids, input, completed, 100);
        assert([aq_ids_retry_lookup(ids,input,104) isEqual:completed]);
        assert([aq_ids_retry_lookup(ids,input,159) isEqual:completed]);
        assert(!aq_ids_retry_lookup(ids,input,160));
        assert(!AQIDSRetryResult);
        for (NSString *field in @[@"username", @"password", @"other-field"]) {
            NSMutableDictionary *different = [[input mutableCopy] autorelease];
            [different setObject:@"different" forKey:field];
            aq_ids_retry_remember(ids,input,completed,100);
            assert(!aq_ids_retry_lookup(ids,different,104));
            assert(!aq_ids_retry_lookup(ids,input,105));
        }
        for (NSString *field in @[@"x-ds-client-id", @"x-protocol-version"]) {
            NSMutableURLRequest *different = [[ids mutableCopy] autorelease];
            [different setValue:@"different" forHTTPHeaderField:field];
            aq_ids_retry_remember(ids,input,completed,100);
            assert(!aq_ids_retry_lookup(different,input,104));
        }
        NSMutableURLRequest *otherEndpoint = [[ids mutableCopy] autorelease];
        [otherEndpoint setURL:[NSURL URLWithString:@"https://setup.icloud.com/setup/login_or_create_account"]];
        aq_ids_retry_remember(ids,input,completed,100);
        assert(!aq_ids_retry_lookup(otherEndpoint,input,104));
        puts("PASS: IDS retry cache exact match, expiration, changed account/input/client and endpoint isolation");
        assert([aq_pet_from_header(aq_base64([@"com.apple.gs.idms.pet:synthetic:token" dataUsingEncoding:NSUTF8StringEncoding])) isEqual:@"synthetic:token"]);
        assert(!aq_pet_from_header(nil));
        assert(!aq_pet_from_header(@"fake-pet"));
        assert(!aq_pet_from_header(@"!!!!"));
        for (NSString *invalid in @[@"com.apple.gs.xcode.auth:token", @"com.apple.gs.idms.pet:", @"com.apple.gs.idms.pet:bad\nvalue", @"token-without-label"])
            assert(!aq_pet_from_header(aq_base64([invalid dataUsingEncoding:NSUTF8StringEncoding])));
        assert(fabs(aq_otp_boundary_delay(26.8) - 3.7) < .001);
        assert(fabs(aq_otp_boundary_delay(29.9) - .6) < .001);
        assert(fabs(aq_otp_boundary_delay(30.1) - 30.4) < .001);
        IMP original = aq_test_install_otp((IMP)localOTP);
        for (scenario = 0; scenario <= 10; scenario++) {
            NSError *error = nil;
            NSDictionary *headers = aq_anisette(nil, &error);
            assert(calls == scenario+1);
            if (scenario) {
                assert(!headers && [[error domain] isEqual:AQErrorDomain]);
                assert([error code] == (scenario == 9 ? 11 : 12));
            } else {
                assert(!error && [headers count] == 9);
                assert([[headers objectForKey:@"X-Apple-I-MD"] isEqual:@"otp"]);
                assert([[headers objectForKey:@"X-Apple-I-MD-M"] isEqual:@"machine"]);
                assert([[headers objectForKey:@"X-Apple-I-MD-RINFO"] isEqual:@"12345"]);
                NSString *device = AQTestDevice;
                assert([device length] && [[headers objectForKey:@"X-Mme-Device-Id"] isEqual:device]);
                assert([[headers objectForKey:@"X-Apple-I-MD-LU"] isEqual:aq_base64([device dataUsingEncoding:NSUTF8StringEncoding])]);
                assert([[headers objectForKey:@"X-MMe-Client-Info"] isEqual:AQTestClient]);
                assert(![headers objectForKey:@"Authorization"]);
            }
        }
        scenario = 11;
        NSError *identityError = nil;
        NSDictionary *providerHeaders = aq_anisette(nil, &identityError);
        assert(providerHeaders && !identityError);
        assert([[providerHeaders objectForKey:@"X-Mme-Device-Id"] isEqual:@"00000000-0000-4000-8000-000000000001"]);
        assert([[providerHeaders objectForKey:@"X-Apple-I-MD-LU"] isEqual:@"MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAx"]);
        for (scenario = 12; scenario <= 14; scenario++) {
            identityError = nil;
            assert(!aq_anisette(nil, &identityError) && [identityError code] == 13);
        }
        scenario = 11;
        [NSURLProtocol registerClass:[AQValidationFixture class]];
        for (validationScenario = 0; validationScenario <= 9; validationScenario++) {
            NSError *error = nil; NSString *pet = nil;
            BOOL accepted = aq_second_factor(nil, @"synthetic-identity", @"00000000-0000-4000-8000-000000000001", @"123456", &pet, &error);
            assert(accepted == (validationScenario <= 1));
            if (accepted) assert(!error && [pet isEqual:@"fake-pet"]);
            else assert(error && !pet);
        }
        int before = validationRequests;
        NSError *changedError = nil; NSString *pet = nil;
        assert(!aq_second_factor(nil, @"synthetic-identity", @"different-device", @"123456", &pet, &changedError));
        assert([changedError code] == 49 && validationRequests == before);
        changedError = nil;
        assert(!aq_anisette_after_sync(nil, @{@"X-Mme-Device-Id":@"different-device", @"X-Apple-I-MD":@"otp"}, &changedError));
        assert([changedError code] == 49);
        [NSURLProtocol unregisterClass:[AQValidationFixture class]];
        puts("PASS: provider identity propagation, malformed identities, validation status layouts, rejected/malformed codes and tokens, identity changes");
        aq_test_install_otp(original);
        puts("PASS: local Anisette mapping, validation, exceptions and no HTTP (11 cases)");
        testProvisioning();
        testRoutingRecovery();
        [pool drain]; return 0;
    }
    if (argc != 1) { fprintf(stderr, "Usage: gsa-diagnose [--selftest]\n"); [pool drain]; return 2; }
    if (!aq_adi_load() || AQADI.state((uint64_t)-2)) {
        fprintf(stderr, "Native device state is not ready; offline diagnostic will not provision.\n");
        [pool drain]; return 1;
    }
    void *machine = NULL, *otp = NULL; uint32_t ml = 0, ol = 0;
    int status = AQADI.otp((uint64_t)-2, &machine, &ml, &otp, &ol);
    BOOL valid = !status && machine && otp && ml && ol && ml <= 12288 && ol <= 12288;
    if (machine) AQADI.dispose(machine);
    if (otp) AQADI.dispose(otp);
    printf("Native proof generation: status=%d, usable=%d; values withheld. No metadata writes or HTTP.\n", status, valid);
    [pool drain]; return valid ? 0 : 1;
}
