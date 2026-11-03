/* IPC fixtures use synthetic headers. --live talks only to the installed local
 * service; it neither reads credentials nor submits account requests. */
#include "../src/mac/aquatransport_gsa.m"
#include <assert.h>
#include <pthread.h>
struct IPCFixture {
    int socket; const void *bytes; size_t length; uint32_t advertised;
    unsigned char operation; const void *request; size_t requestLength;
};
static void receiveFixture(int fd, void *bytes, size_t length) {
    while (length) { ssize_t n = recv(fd, bytes, length, 0); assert(n > 0); bytes = (char *)bytes+n; length -= n; }
}
static void *serveFixture(void *context) {
    struct IPCFixture *f = context;
    int client = accept(f->socket, NULL, NULL); assert(client >= 0);
    int one = 1; setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    unsigned char op; ssize_t n = recv(client, &op, 1, 0);
    if (n == 1) {
        assert(op == f->operation);
        if (op != 1) {
            uint32_t requestLength = 0; receiveFixture(client, &requestLength, sizeof requestLength);
            requestLength = ntohl(requestLength); assert(requestLength == f->requestLength);
            void *request = malloc(requestLength); assert(request);
            receiveFixture(client, request, requestLength);
            assert(!memcmp(request, f->request, requestLength)); free(request);
        }
        uint32_t size = htonl(f->advertised);
        send(client, &size, sizeof size, 0);
        if (f->length) send(client, f->bytes, f->length, 0);
    }
    close(client); return NULL;
}
@interface AQIPCCancelled : AQGSAProtocol @end
@implementation AQIPCCancelled
- (BOOL)isStopped { return YES; }
@end
@interface AQIPCNoHTTP : NSURLProtocol @end
@implementation AQIPCNoHTTP
+ (BOOL)canInitWithRequest:(NSURLRequest *)r { return YES; }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)stopLoading {}
- (void)startLoading { assert(!"Anisette client must never make HTTP requests"); }
@end
int main(int argc, char **argv) {
    NSAutoreleasePool *pool = [NSAutoreleasePool new];
    [NSURLProtocol registerClass:[AQIPCNoHTTP class]];
    if (argc == 2 && !strcmp(argv[1], "--live")) {
        NSError *error = nil; NSDictionary *headers = aq_anisette(nil, &error);
        if (!headers) { fprintf(stderr, "Local service failed: code=%ld (%s)\n", (long)[error code], [[error localizedDescription] UTF8String]); return 1; }
        puts("PASS: production local IPC returned native Anisette; values withheld");
        [pool drain]; return 0;
    }
    assert(argc == 1);
    char directory[] = "/tmp/aq-ipc.XXXXXX"; assert(mkdtemp(directory));
    struct sockaddr_un address; memset(&address, 0, sizeof address); address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof address.sun_path, "%s/socket", directory);
    for (int mode = 0; mode < 8; mode++) {
        NSData *data = aq_encode(mode == 1 ? @{@"error":@17, @"message":@"fixture cooldown"} : @{@"headers":@{@"X-Apple-MD":@"otp"}});
        if (mode == 2) data = [@"malformed" dataUsingEncoding:NSUTF8StringEncoding];
        struct IPCFixture f = { socket(AF_UNIX, SOCK_STREAM, 0), [data bytes], [data length], (uint32_t)[data length], 1, NULL, 0 };
        if (mode == 3) f.advertised = 65537;
        if (mode == 4) f.length = 2;
        assert(f.socket >= 0);
        if (bind(f.socket, (struct sockaddr *)&address, sizeof address)) { perror("bind fixture"); abort(); }
        if (listen(f.socket, 1)) { perror("listen fixture"); abort(); }
        pthread_t thread;
        if (mode == 6) close(f.socket);
        else assert(!pthread_create(&thread, NULL, serveFixture, &f));
        NSError *error = nil;
        AQIPCCancelled *cancelled = mode == 5 ? [[[AQIPCCancelled alloc] init] autorelease] : nil;
        NSDictionary *reply = aq_adi_client(cancelled, &error, address.sun_path, mode == 7 ? geteuid()+1 : geteuid(), 1, nil);
        NSDictionary *headers = aq_dict([reply objectForKey:@"headers"]);
        if (!mode) assert(headers && !error && [[headers objectForKey:@"X-Apple-MD"] isEqual:@"otp"]);
        else assert(!headers && [error code] == (mode == 1 ? 17 : mode == 5 ? NSUserCancelledError : mode >= 6 ? 10 : 19));
        if (mode != 6) { pthread_join(thread, NULL); close(f.socket); }
        unlink(address.sun_path);
    }
    for (unsigned char operation = 2; operation <= 3; operation++) {
        NSData *request = operation == 2 ? [@"server-sync" dataUsingEncoding:NSUTF8StringEncoding] : [@"67890" dataUsingEncoding:NSASCIIStringEncoding];
        NSDictionary *fixture = operation == 2 ? @{ @"synchronization":@{ @"mid":[@"mid" dataUsingEncoding:NSUTF8StringEncoding],
            @"srm":[@"srm" dataUsingEncoding:NSUTF8StringEncoding] } } : @{ @"stored":@YES };
        NSData *data = aq_encode(fixture);
        struct IPCFixture f = { socket(AF_UNIX, SOCK_STREAM, 0), [data bytes], [data length], (uint32_t)[data length],
            operation, [request bytes], [request length] };
        assert(f.socket >= 0 && !bind(f.socket, (struct sockaddr *)&address, sizeof address) && !listen(f.socket, 1));
        pthread_t thread; assert(!pthread_create(&thread, NULL, serveFixture, &f));
        NSError *error = nil; NSDictionary *reply = aq_adi_client(nil, &error, address.sun_path, geteuid(), operation, request);
        assert(reply && !error && (operation == 2 ? [aq_dict([reply objectForKey:@"synchronization"]) count] == 2 : [[reply objectForKey:@"stored"] boolValue]));
        pthread_join(thread, NULL); close(f.socket); unlink(address.sun_path);
    }
    rmdir(directory);
    puts("PASS: local IPC operations, framing, errors, malformed/oversized/truncated replies, cancellation, unavailable service and wrong peer identity (10 cases)");
    [pool drain]; return 0;
}
