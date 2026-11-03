/* Offline coverage of the production provisioning/state machine. Only native
 * cryptographic calls and HTTPS responses are replaced; metadata uses scratch
 * files. No Apple framework, account, keychain or real device state is touched. */
static int adiMode, adiRequests, adiStarts, adiFinishes, adiDestroys, adiOTPs, adiSyncs, adiState;
static int fakeState(uint64_t dsid) { assert(dsid == UINT64_MAX-1); return adiState; }
static int fakeDispose(void *p) { free(p); return 0; }
static int fakeStart(uint64_t dsid, const void *p, uint32_t n, void **out, uint32_t *size, uint32_t *session) {
    assert(dsid == UINT64_MAX-1 && n == 4 && !memcmp(p, "spim", 4)); adiStarts++;
    if (adiMode == 3) return -1;
    *out = strdup("cpim"); *size = 4; *session = 7; return 0;
}
static int fakeFinish(uint32_t session, const void *p, uint32_t n, const void *key, uint32_t length) {
    assert(session == 7 && n == 3 && !memcmp(p, "ptm", 3) && length == 2 && !memcmp(key, "tk", 2)); adiFinishes++;
    if (adiMode == 6) return -1;
    adiState = 0; return 0;
}
static int fakeDestroy(uint32_t session) { assert(session == 7); adiDestroys++; return 0; }
static int fakeOTP(uint64_t dsid, void **machine, uint32_t *ml, void **otp, uint32_t *ol) {
    assert(dsid == UINT64_MAX-1); adiOTPs++;
    *machine = strdup("machine"); *ml = 7; *otp = strdup("otp"); *ol = 3; return 0;
}
static int fakeSync(uint64_t dsid, const void *server, uint32_t length, void **mid, uint32_t *ml, void **srm, uint32_t *sl) {
    assert(dsid == UINT64_MAX-1 && length == 11 && !memcmp(server, "server-sync", 11)); adiSyncs++;
    if (adiMode == 1) return -1;
    *mid = strdup("mid"); *ml = adiMode == 2 ? 20000 : 3;
    *srm = strdup("client-sync"); *sl = 11; return 0;
}
@interface AQProvisionFixture : NSURLProtocol @end
@implementation AQProvisionFixture
+ (BOOL)canInitWithRequest:(NSURLRequest *)req { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)req { return req; }
- (void)stopLoading {}
- (void)startLoading {
    NSURLRequest *req = [self request]; adiRequests++;
    assert(adiRequests <= 3 && aq_adi_url([[req URL] absoluteString]));
    assert(![req valueForHTTPHeaderField:@"Authorization"] && ![req valueForHTTPHeaderField:@"X-Apple-I-MD"]);
    assert([[req valueForHTTPHeaderField:@"X-Mme-Client-Info"] isEqual:aq_client_info()]);
    NSDictionary *result = nil; NSInteger status = 200;
    switch (adiRequests) {
        case 1:
            assert([[req HTTPMethod] isEqual:@"GET"]);
            result = adiMode == 1 ? @{} : @{@"urls": @{
                @"midStartProvisioning": @"https://gsa.apple.com/grandslam/start",
                @"midFinishProvisioning": adiMode == 7 ? @"https://other.invalid/grandslam/finish" : @"https://gsa.apple.com/grandslam/finish"}};
            break;
        case 2:
            assert([[req HTTPMethod] isEqual:@"POST"] && [[aq_plist([req HTTPBody]) objectForKey:@"Request"] count] == 0);
            status = adiMode == 2 ? 503 : 200;
            result = @{@"Response": @{@"spim": @"c3BpbQ=="}};
            break;
        case 3:
            assert([[req HTTPMethod] isEqual:@"POST"] && [[[[aq_plist([req HTTPBody]) objectForKey:@"Request"] objectForKey:@"cpim"] description] isEqual:@"Y3BpbQ=="]);
            status = adiMode == 4 ? 503 : 200;
            result = @{@"Response": @{@"ptm": @"cHRt", @"tk": @"dGs=", @"X-Apple-I-MD-RINFO": adiMode == 5 ? @"bad\r\nroute" : @"12345"}};
            break;
    }
    NSHTTPURLResponse *response = [[[NSHTTPURLResponse alloc] initWithURL:[req URL] statusCode:status HTTPVersion:@"HTTP/1.1" headerFields:nil] autorelease];
    [[self client] URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [[self client] URLProtocol:self didLoadData:aq_encode(result)];
    [[self client] URLProtocolDidFinishLoading:self];
}
@end
static void testProvisioning(void) {
    AQADI.state = fakeState; AQADI.otp = fakeOTP; AQADI.start = fakeStart;
    AQADI.finish = fakeFinish; AQADI.destroy = fakeDestroy; AQADI.dispose = fakeDispose;
    [NSURLProtocol registerClass:[AQProvisionFixture class]];
    for (adiMode = 0; adiMode <= 9; adiMode++) {
        adiRequests = adiStarts = adiFinishes = adiDestroys = adiOTPs = 0;
        adiState = adiMode == 8 ? -1 : adiMode == 9 ? 0 : -45061;
        char path[] = "/tmp/aquatransport-adi.XXXXXX"; int fd = mkstemp(path); assert(fd >= 0); unlink(path);
        NSError *error = nil;
        NSDictionary *headers = aq_adi_headers(nil, @"fixture-device", fd, &error);
        if (!adiMode) {
            assert(headers && !error && adiRequests == 3 && adiStarts == 1 && adiFinishes == 1 && !adiDestroys && adiOTPs == 1);
            assert([[headers objectForKey:@"X-Apple-I-MD-RINFO"] isEqual:@"12345"]);
            assert([[aq_adi_read(fd) objectForKey:@"routing"] isEqual:@"12345"]);
            assert(aq_adi_headers(nil, @"fixture-device", fd, &error) && adiRequests == 3 && adiOTPs == 2);
            assert(!aq_adi_headers(nil, @"different-device", fd, &error) && [error code] == 18 && adiRequests == 3);
        } else {
            const int expected[] = {3,1,2,2,3,3,3,1,0,0};
            assert(!headers && error && adiRequests == expected[adiMode] && !adiOTPs);
            assert(adiDestroys == (adiMode >= 4 && adiMode <= 6 ? 1 : 0));
            error = nil;
            assert(!aq_adi_headers(nil, @"fixture-device", fd, &error));
            assert([error code] == (adiMode == 8 ? 12 : adiMode == 9 ? 18 : 17) && adiRequests == expected[adiMode]);
        }
        close(fd);
    }
    adiState = -45061; adiRequests = 0;
    int readonly = open("/dev/null", O_RDONLY); assert(readonly >= 0);
    NSError *error = nil;
    assert(!aq_adi_headers(nil, @"fixture-device", readonly, &error) && [error code] == 14 && !adiRequests); close(readonly);
    for (NSString *route in @[@"0", @"-1", @"123\r\n", @"18446744073709551616", @"１２３", @""])
        assert(!aq_adi_routing(route));
    [NSURLProtocol unregisterClass:[AQProvisionFixture class]];
    memset(&AQADI, 0, sizeof AQADI);
    puts("PASS: native provisioning, 64-bit DSID, routing persistence, failed-session cleanup, cooldown and request bounds (11 cases)");
}

static void testSynchronization(void) {
    memset(&AQADI, 0, sizeof AQADI); AQADI.state = fakeState; AQADI.sync = fakeSync; AQADI.dispose = fakeDispose;
    char path[] = "/tmp/aquatransport-sync.XXXXXX"; int fd = mkstemp(path); assert(fd >= 0); unlink(path);
    NSMutableDictionary *record = [NSMutableDictionary dictionaryWithObjectsAndKeys:@"fixture-device", @"device", @"12345", @"routing", nil];
    assert(aq_adi_save(fd, record)); NSData *server = [@"server-sync" dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error = nil; adiMode = 0; adiState = 0; adiSyncs = 0;
    NSDictionary *result = aq_adi_synchronize(server, @"fixture-device", fd, &error);
    assert(result && !error && adiSyncs == 1 && [[result objectForKey:@"mid"] isEqual:[@"mid" dataUsingEncoding:NSUTF8StringEncoding]] &&
        [[result objectForKey:@"srm"] isEqual:[@"client-sync" dataUsingEncoding:NSUTF8StringEncoding]]);
    assert(aq_adi_store_routing(@"67890", @"fixture-device", fd, &error));
    assert([[aq_adi_read(fd) objectForKey:@"routing"] isEqual:@"67890"]);
    error = nil; assert(!aq_adi_store_routing(@"bad\r\nroute", @"fixture-device", fd, &error) && [error code] == 28);
    error = nil; adiMode = 1; assert(!aq_adi_synchronize(server, @"fixture-device", fd, &error) && [error code] == 29);
    error = nil; adiMode = 2; assert(!aq_adi_synchronize(server, @"fixture-device", fd, &error) && [error code] == 29);
    error = nil; adiMode = 0; adiState = -1; assert(!aq_adi_synchronize(server, @"fixture-device", fd, &error) && [error code] == 12);
    error = nil; adiState = 0; assert(!aq_adi_synchronize([NSData data], @"fixture-device", fd, &error) && [error code] == 28);
    [record removeObjectForKey:@"routing"]; assert(aq_adi_save(fd, record));
    error = nil; assert(!aq_adi_synchronize(server, @"fixture-device", fd, &error) && [error code] == 18);
    close(fd); memset(&AQADI, 0, sizeof AQADI);
    puts("PASS: native device synchronization, output bounds and routing persistence (8 cases)");
}
