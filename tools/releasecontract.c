// What a context released without SSLClose leaves behind for the next context. Run it on the
// stock stack for the reference answers, then on the engine; the two must match. The companion
// to tools/statecontract.c.
//
// A caller may end a context with CFRelease alone. Rust's security-framework, under native-tls,
// does so for every stream dropped without a shutdown, and a failed handshake always is. The
// allocator then hands the address to a later context, and that context must behave as a new
// one: nothing from the dead connection may carry over. On the stock stack nothing can. In the
// hooks, whatever is keyed by the address could.
//
// Each case fails a handshake on one context, ends that context one way or another, then makes
// contexts until one lands at the same address and sends a ClientHello from it. The hello is
// compared with one from a fresh context. A context that carried the dead connection's state
// over would send a different hello, or none.
//
// The last case releases many contexts that way while one more is set up and waiting, then
// sends that one's ClientHello. Whatever the dead ones left behind must not crowd it out.
//
// Every listener is on 127.0.0.1 and answers with fixed bytes, so nothing here needs the
// network:
//
//   alert     one fatal handshake_failure alert record, after reading the ClientHello
//   eof       the listener hangs up without answering
//
//   clang -arch x86_64 -mmacosx-version-min=10.6 -Wno-deprecated-declarations \
//       -framework CoreFoundation -framework Security -o releasecontract tools/releasecontract.c
//
//   releasecontract
//
// Prints one line per case: how the first context failed and ended, and whether the next
// context at its address sent the same ClientHello as a fresh context.

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <arpa/inet.h>
#include <malloc/malloc.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum { ALERT, HANG_UP };
enum { CLOSE_THEN_RELEASE, DISPOSE, RELEASE_ONLY };

typedef struct {
    const char *name;
    int         kind;   // how the first handshake fails
    int         end;    // how its context is ended
} Case;

static const Case kCases[] = {
    { "alert, SSLClose then CFRelease", ALERT,   CLOSE_THEN_RELEASE },
    { "alert, SSLDisposeContext",       ALERT,   DISPOSE },
    { "alert, CFRelease alone",         ALERT,   RELEASE_ONLY },
    { "eof, SSLClose then CFRelease",   HANG_UP, CLOSE_THEN_RELEASE },
    { "eof, CFRelease alone",           HANG_UP, RELEASE_ONLY },
};

// What a ClientHello offered, as far as the comparison needs: which versions, and how many
// cipher suites. Both are the same for every fresh context of one stack.
typedef struct { int seen; int legacy; int tls13; int suites; } Hello;

typedef struct { int lfd; int kind; Hello *hello; } Listener;

static int read_full(int fd, unsigned char *p, size_t n) {
    size_t got = 0;
    while (got < n) { ssize_t r = read(fd, p + got, n - got); if (r <= 0) return -1; got += (size_t)r; }
    return 0;
}

static void parse_hello(const unsigned char *ch, size_t n, Hello *h) {
    if (n < 4 + 2 + 32 + 1 || ch[0] != 0x01) return;
    h->seen = 1;
    h->legacy = (ch[4] << 8) | ch[5];
    size_t o = 4 + 2 + 32;
    o += 1 + ch[o];                                                   // session id
    if (o + 2 > n) return;
    size_t cl = ((size_t)ch[o] << 8) | ch[o + 1]; o += 2;
    h->suites = (int)(cl / 2);
    o += cl;
    if (o + 1 > n) return;
    o += 1 + ch[o];                                                   // compression methods
    if (o + 2 > n) return;
    size_t end = o + 2 + (((size_t)ch[o] << 8) | ch[o + 1]); o += 2;
    if (end > n) end = n;
    while (o + 4 <= end) {
        unsigned type = (ch[o] << 8) | ch[o + 1];
        size_t len = ((size_t)ch[o + 2] << 8) | ch[o + 3];
        o += 4;
        if (o + len > end) break;
        if (type == 0x002b && len >= 1)                               // supported_versions
            for (size_t i = 1; i + 1 <= ch[o] && i + 1 < len; i += 2)
                if (ch[o + i] == 0x03 && ch[o + i + 1] == 0x04) h->tls13 = 1;
        o += len;
    }
}

static void *serve(void *arg) {
    Listener *l = arg;
    int fd = accept(l->lfd, NULL, NULL);
    if (fd < 0) return NULL;
    if (l->kind == HANG_UP) { close(fd); return NULL; }
    unsigned char hdr[5], ch[16384];
    if (read_full(fd, hdr, 5) == 0) {
        size_t len = ((size_t)hdr[3] << 8) | hdr[4];
        if (len <= sizeof ch && read_full(fd, ch, len) == 0) {
            if (l->hello) parse_hello(ch, len, l->hello);
            static const unsigned char a[7] = { 0x15, 0x03, 0x03, 0x00, 0x02, 2, 40 };
            write(fd, a, sizeof a);
        }
    }
    // Wait for the client to hang up first, so the answer is never lost to a reset.
    while (read(fd, ch, sizeof ch) > 0) ;
    close(fd);
    return NULL;
}

static OSStatus sock_read(SSLConnectionRef c, void *data, size_t *len) {
    int fd = *(const int *)c;
    size_t want = *len, got = 0;
    OSStatus st = noErr;
    while (got < want) {
        ssize_t n = read(fd, (char *)data + got, want - got);
        if (n <= 0) { st = n == 0 ? errSSLClosedGraceful : errSSLClosedAbort; break; }
        got += (size_t)n;
    }
    *len = got;
    return st;
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
    return put == want ? noErr : errSSLClosedAbort;
}

// A connection to a listener of the given kind, with ctx set up on it in the order
// security-framework uses but not yet handshaking. The listener records the ClientHello in
// *hello if asked to.
typedef struct { int lfd, fd; pthread_t th; Listener l; } Conn;

static void connect_context(Conn *k, SSLContextRef ctx, int kind, Hello *hello) {
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    k->lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (k->lfd < 0 || bind(k->lfd, (struct sockaddr *)&a, sizeof a) || listen(k->lfd, 1) ||
        getsockname(k->lfd, (struct sockaddr *)&a, &al)) { printf("FAIL: listen\n"); exit(1); }
    k->l = (Listener){ k->lfd, kind, hello };
    pthread_create(&k->th, NULL, serve, &k->l);

    k->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (k->fd < 0 || connect(k->fd, (struct sockaddr *)&a, sizeof a)) { printf("FAIL: connect\n"); exit(1); }
    struct timeval to = { 10, 0 };
    setsockopt(k->fd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof to);

    SSLSetPeerDomainName(ctx, "localhost", strlen("localhost"));
    SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, true);
    SSLSetIOFuncs(ctx, sock_read, sock_write);
    SSLSetConnection(ctx, &k->fd);
}

static OSStatus finish_handshake(Conn *k, SSLContextRef ctx) {
    OSStatus st;
    while ((st = SSLHandshake(ctx)) == errSSLWouldBlock) ;
    close(k->fd);
    pthread_join(k->th, NULL);
    close(k->lfd);
    return st;
}

static OSStatus handshake(SSLContextRef ctx, int kind, Hello *hello) {
    Conn k;
    connect_context(&k, ctx, kind, hello);
    return finish_handshake(&k, ctx);
}

static SSLContextRef new_context(void) {
    return SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
}

// Ended as a caller finished with it would end it: what Secure Transport needs is a release,
// and SSLClose before it is optional.
static void end_context(SSLContextRef c, int how) {
    if (how == CLOSE_THEN_RELEASE) { SSLClose(c); CFRelease(c); }
    else if (how == DISPOSE) SSLDisposeContext(c);
    else CFRelease(c);
}

// The ClientHello a context sends, ended cleanly afterwards so it leaves nothing behind.
static Hello hello_from(SSLContextRef c) {
    Hello h = { 0, 0, 0, 0 };
    handshake(c, ALERT, &h);
    end_context(c, CLOSE_THEN_RELEASE);
    return h;
}

static void describe(const Hello *h, char *out, size_t n) {
    if (!h->seen) { snprintf(out, n, "no ClientHello"); return; }
    snprintf(out, n, "version 0x%04x, %s, %d suites", h->legacy, h->tls13 ? "TLS 1.3 offered" : "no TLS 1.3", h->suites);
}

int main(void) {
    Hello fresh = hello_from(new_context());
    char want[96];
    describe(&fresh, want, sizeof want);
    printf("fresh context: %s\n", want);

    for (size_t i = 0; i < sizeof kCases / sizeof kCases[0]; i++) {
        const Case *c = &kCases[i];
        SSLContextRef first = new_context();
        handshake(first, c->kind, NULL);
        const void *addr = first;
        end_context(first, c->end);

        // A freed block goes back to the allocator's magazine for the CPU that first handed it
        // out, and an allocation is served from the magazine of the CPU the thread is on now.
        // So the next context lands at the released address only when this thread is back on
        // that CPU. Contexts are made, and released again, until one does.
        SSLContextRef next = NULL;
        for (int tries = 0; tries < 20000 && !next; tries++) {
            SSLContextRef t = new_context();
            if ((const void *)t == addr) next = t;
            else { CFRelease(t); usleep(50); }
        }
        if (!next) { printf("FAIL: %s: no later context at the released address\n", c->name); return 1; }

        Hello h = hello_from(next);
        char got[96];
        describe(&h, got, sizeof got);
        if (!memcmp(&h, &fresh, sizeof h)) printf("  %-32s next context: a fresh context's hello\n", c->name);
        else printf("  %-32s next context: %s, fresh: %s\n", c->name, got, want);
    }

    // Many contexts released with CFRelease alone, while another, set up and about to
    // handshake, is still alive. Whatever the hooks hold for the released ones must not crowd
    // out what they hold for the live one: its hello must still be a fresh context's.
    //
    // Each released context's memory is taken by a block of the same size at once, so no
    // later context lands at its address, and each one leaves its own address behind.
    {
        Hello h = { 0, 0, 0, 0 };
        Conn k;
        SSLContextRef live = new_context();
        connect_context(&k, live, ALERT, &h);
        size_t size = malloc_size(live);
        enum { MANY = 1000, BATCH = 50 };
        static void *filler[MANY * 2];
        size_t nfill = 0;
        for (int i = 0; i < MANY; i += BATCH) {
            SSLContextRef batch[BATCH];
            for (int j = 0; j < BATCH; j++) {
                batch[j] = new_context();
                SSLSetPeerDomainName(batch[j], "localhost", strlen("localhost"));
            }
            for (int j = 0; j < BATCH; j++) CFRelease(batch[j]);
            for (int j = 0; j < BATCH * 2 && nfill < sizeof filler / sizeof filler[0]; j++)
                filler[nfill++] = malloc(size);
        }
        finish_handshake(&k, live);
        end_context(live, CLOSE_THEN_RELEASE);
        for (size_t i = 0; i < nfill; i++) free(filler[i]);

        const char *name = "1000 others, CFRelease alone";
        char got[96];
        describe(&h, got, sizeof got);
        if (!memcmp(&h, &fresh, sizeof h)) printf("  %-32s live context: a fresh context's hello\n", name);
        else printf("  %-32s live context: %s, fresh: %s\n", name, got, want);
    }
    return 0;
}
