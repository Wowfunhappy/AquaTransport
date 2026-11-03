/* Every client uses the same local generator process. A Unix socket lets
 * sandboxed apps authenticate without access to Apple's on-disk ADI state.
 * No TCP listener, remote URL, or in-process alternate provider. */
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "aquatransport_anisette_service.h"

static NSString *aq_adi_routing(id value) {
    NSString *s = [value isKindOfClass:[NSNumber class]] ? [value stringValue] : aq_string(value);
    if (![s length] || [s length] > 20 || [s rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789"] invertedSet]].location != NSNotFound) return nil;
    errno = 0;
    return strtoull([s UTF8String], NULL, 10) && errno != ERANGE ? s : nil;
}
static BOOL aq_adi_io(int fd, void *bytes, size_t length, BOOL writing, AQGSAProtocol *owner, NSDate *deadline) {
    while (length && ![owner isStopped] && [deadline timeIntervalSinceNow] > 0) {
        fd_set ready; FD_ZERO(&ready); FD_SET(fd, &ready);
        struct timeval wait = {0, 50000};
        int n = select(fd + 1, writing ? NULL : &ready, writing ? &ready : NULL, NULL, &wait);
        if (n < 0 && errno != EINTR) return NO;
        if (n <= 0) continue;
        ssize_t count = writing ? send(fd, bytes, length, 0) : recv(fd, bytes, length, 0);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) return NO;
        bytes = (char *)bytes + count; length -= count;
    }
    return !length;
}
static NSDictionary *aq_adi_client(AQGSAProtocol *owner, NSError **error, const char *path, uid_t expectedPeer,
                                    unsigned char operation, NSData *request) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || fd >= FD_SETSIZE) { if (fd >= 0) close(fd); *error = aq_error(10, @"Could not open the local Anisette service."); return nil; }
    @try {
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        if (fcntl(fd, F_SETFL, O_NONBLOCK)) { *error = aq_error(10, @"Could not connect to the local Anisette service."); return nil; }
        int one = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
        struct sockaddr_un address; memset(&address, 0, sizeof address); address.sun_family = AF_UNIX;
        if (strlen(path) >= sizeof address.sun_path) { *error = aq_error(10, @"Invalid local Anisette socket path."); return nil; }
        strlcpy(address.sun_path, path, sizeof address.sun_path);
        if (connect(fd, (struct sockaddr *)&address, sizeof address)) {
            /* A local Unix-domain connect completes immediately or fails; a
             * full listen queue also fails instead of creating retry traffic. */
            *error = aq_error(10, @"The local Anisette service is unavailable. Restart after installing AquaTransport."); return nil;
        }
        uid_t uid; gid_t gid;
        if (getpeereid(fd, &uid, &gid) || uid != expectedPeer) { *error = aq_error(10, @"The local Anisette service has an unexpected owner."); return nil; }
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:100];
        NSUInteger fullRequestLength = [request length];
        uint32_t requestLength = (uint32_t)fullRequestLength, wireLength = htonl(requestLength), length = 0;
        if ((operation != 1 && operation != 2 && operation != 3) || fullRequestLength > 1024*1024 ||
            !aq_adi_io(fd, &operation, 1, YES, owner, deadline) ||
            (operation != 1 && (!requestLength || !aq_adi_io(fd, &wireLength, sizeof wireLength, YES, owner, deadline) ||
                !aq_adi_io(fd, (void *)[request bytes], requestLength, YES, owner, deadline))) ||
            !aq_adi_io(fd, &length, sizeof length, NO, owner, deadline)) {
            *error = aq_error([owner isStopped] ? NSUserCancelledError : 19, @"Local device authentication was cancelled or could not complete."); return nil;
        }
        length = ntohl(length);
        if (!length || length > 65536) { *error = aq_error(19, @"Invalid local device authentication response."); return nil; }
        NSMutableData *data = [NSMutableData dataWithLength:length];
        if (!aq_adi_io(fd, [data mutableBytes], length, NO, owner, deadline)) { *error = aq_error(19, @"Incomplete local device authentication response."); return nil; }
        NSDictionary *reply = aq_plist(data);
        if (![reply isKindOfClass:[NSDictionary class]] || [reply objectForKey:@"error"]) {
            NSNumber *code = [reply objectForKey:@"error"];
            NSString *message = aq_device_field([reply objectForKey:@"message"]);
            *error = aq_error([code isKindOfClass:[NSNumber class]] ? [code integerValue] : 19, message ?: @"Local device authentication failed.");
            return nil;
        }
        return reply;
    } @finally { close(fd); }
}
@interface AQNativeAnisette : NSObject
+ (NSDictionary *)headersForOwner:(AQGSAProtocol *)owner error:(NSError **)error;
+ (NSDictionary *)synchronizeServerData:(NSData *)server owner:(AQGSAProtocol *)owner error:(NSError **)error;
+ (BOOL)storeRouting:(NSString *)routing owner:(AQGSAProtocol *)owner error:(NSError **)error;
@end
@implementation AQNativeAnisette
+ (NSDictionary *)headersForOwner:(AQGSAProtocol *)owner error:(NSError **)error {
    return aq_dict([aq_adi_client(owner, error, AQ_ANISETTE_SOCKET, 0, 1, nil) objectForKey:@"headers"]);
}
+ (NSDictionary *)synchronizeServerData:(NSData *)server owner:(AQGSAProtocol *)owner error:(NSError **)error {
    return aq_dict([aq_adi_client(owner, error, AQ_ANISETTE_SOCKET, 0, 2, server) objectForKey:@"synchronization"]);
}
+ (BOOL)storeRouting:(NSString *)routing owner:(AQGSAProtocol *)owner error:(NSError **)error {
    NSData *request = [routing dataUsingEncoding:NSASCIIStringEncoding];
    return [[[aq_adi_client(owner, error, AQ_ANISETTE_SOCKET, 0, 3, request) objectForKey:@"stored"] description] boolValue];
}
@end
