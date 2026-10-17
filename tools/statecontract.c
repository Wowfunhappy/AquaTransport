// What SSLGetSessionState says at each step of a client handshake that pauses for server
// authentication. Run it on the stock stack for the reference answers, then on the engine; the
// two must match. The companion to tools/readcontract.c and tools/writecontract.c.
//
// The pause is the one kSSLSessionOptionBreakOnServerAuth asks for, and the state there is part
// of the contract. Rust's security-framework, which native-tls uses, asks for it before fetching
// the peer trust. On kSSLIdle it returns errSecBadReq (-909), so every native-tls client needs
// kSSLHandshake there, which is what the stock stack says.
//
//   clang -arch x86_64 -mmacosx-version-min=10.6 -Wno-deprecated-declarations \
//       -framework CoreFoundation -framework Security -o statecontract tools/statecontract.c
//
//   statecontract [host]
//
// Prints one line per step: the OSStatus the step returned, and the session state after it.

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// The first read reports that nothing has arrived, as a non-blocking socket does before the
// server answers. So the handshake returns errSSLWouldBlock once, and the state mid-handshake
// can be asked for too. Every later read blocks.
static int g_starve = 1;

static OSStatus sock_read(SSLConnectionRef c, void *data, size_t *len) {
    if (g_starve) { g_starve = 0; *len = 0; return errSSLWouldBlock; }
    int fd = *(const int *)c;
    size_t want = *len, got = 0;
    while (got < want) {
        ssize_t n = read(fd, (char *)data + got, want - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    *len = got;
    return got == want ? noErr : errSSLClosedAbort;
}

static OSStatus sock_write(SSLConnectionRef c, const void *data, size_t *len) {
    int fd = *(const int *)c;
    size_t want = *len, put = 0;
    while (put < want) {
        ssize_t n = write(fd, (const char *)data + put, want - put);
        if (n <= 0) break;
        put += (size_t)n;
    }
    *len = put;
    return put == want ? noErr : errSSLWouldBlock;
}

static const char *stname(OSStatus s) {
    switch (s) {
        case noErr:                   return "noErr";
        case errSSLWouldBlock:        return "errSSLWouldBlock";
        case errSSLPeerAuthCompleted: return "errSSLPeerAuthCompleted";
        case errSSLClosedAbort:       return "errSSLClosedAbort";
        case errSSLClosedGraceful:    return "errSSLClosedGraceful";
        default:                      return "other";
    }
}

static const char *statename(SSLSessionState s) {
    switch (s) {
        case kSSLIdle:      return "kSSLIdle";
        case kSSLHandshake: return "kSSLHandshake";
        case kSSLConnected: return "kSSLConnected";
        case kSSLClosed:    return "kSSLClosed";
        case kSSLAborted:   return "kSSLAborted";
        default:            return "unknown";
    }
}

static SSLContextRef g_ctx;

static void report(const char *what, OSStatus st) {
    SSLSessionState state = (SSLSessionState)-1;
    OSStatus q = SSLGetSessionState(g_ctx, &state);
    printf("  %-28s st=%-24s state=%s\n", what, stname(st),
           q == noErr ? statename(state) : "(query failed)");
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "postman-echo.com";

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "443", &hints, &res) || !res) { printf("FAIL: resolve\n"); return 1; }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0 || connect(fd, res->ai_addr, res->ai_addrlen)) { printf("FAIL: connect\n"); return 1; }
    freeaddrinfo(res);
    struct timeval rcvto = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcvto, sizeof rcvto);

    SSLContextRef ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    g_ctx = ctx;
    SSLSetIOFuncs(ctx, sock_read, sock_write);
    SSLSetConnection(ctx, &fd);
    SSLSetPeerDomainName(ctx, host, strlen(host));
    SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, true);
    report("before the handshake", noErr);

    OSStatus st = SSLHandshake(ctx);
    report("handshake in flight", st);
    if (st == errSSLWouldBlock) while ((st = SSLHandshake(ctx)) == errSSLWouldBlock) ;
    report("paused for server auth", st);
    if (st != errSSLPeerAuthCompleted) { printf("FAIL: no server-auth pause (%d)\n", (int)st); return 1; }

    SecTrustRef trust = NULL;
    OSStatus tr = SSLCopyPeerTrust(ctx, &trust);
    printf("  %-28s st=%-24s trust=%s\n", "peer trust at the pause", stname(tr), trust ? "yes" : "none");
    if (trust) CFRelease(trust);

    while ((st = SSLHandshake(ctx)) == errSSLWouldBlock) ;
    report("resumed", st);
    if (st != noErr) { printf("FAIL: handshake %d\n", (int)st); return 1; }

    st = SSLClose(ctx);
    report("closed", st);
    close(fd);
    CFRelease(ctx);
    return 0;
}
