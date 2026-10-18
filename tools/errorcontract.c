// What SSLHandshake returns when the server refuses the handshake, or the client refuses the
// server. Run it on the stock stack for the reference answers, then on the engine; the two
// must match. The companion to tools/statecontract.c.
//
// Callers act on the code, not only on the failure. Codex's HTTP client retries with its own
// TLS stack on errSSLPeerProtocolVersion (-9836), and not on errSSLClosedAbort (-9806), which
// says only that the connection died.
//
// Each case is a listener on 127.0.0.1 that reads the ClientHello and answers it with fixed
// bytes, so nothing here needs the network:
//
//   alert     one fatal alert record
//   cert      ServerHello, Certificate, ServerHelloDone. The certificate is self-signed, so
//             the client refuses it as soon as it arrives, before anything else is needed.
//   not tls   an HTTP response
//   eof       the listener hangs up without answering
//
//   clang -arch x86_64 -mmacosx-version-min=10.6 -Wno-deprecated-declarations \
//       -framework CoreFoundation -framework Security -o errorcontract tools/errorcontract.c
//
//   errorcontract
//
// Prints one line per case: the case, and the OSStatus SSLHandshake returned.

#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Self-signed P-256 certificates for localhost: valid 2020-2120, expired 2000-2001, and valid
// only from 2100. Made with
//
//   openssl req -x509 -new -key key.pem -sha256 -subj /CN=localhost -set_serial 1 \
//       -not_before <date> -not_after <date> -outform DER  (SAN DNS:localhost, nothing else)
//
// Only the certificates are needed. The handshake never gets far enough to need the key.
static const char kCert_valid[] =
    "3082012f3081d7a003020102020101300a06082a8648ce3d04030230143112301006035504030c096c6f6361"
    "6c686f73743020170d3230303130313030303030305a180f32313230303130313030303030305a3014311230"
    "1006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d03010703420004"
    "fdc4abe25332cf43e958916efc607c6f629c7d2c5cc5698b76af78fb1c391bfe80eabcc2d09ff84467ae1ce5"
    "8c0fd3e97fd8a0d0826cadd308a54fa29aacd6e2a318301630140603551d11040d300b82096c6f63616c686f"
    "7374300a06082a8648ce3d040302034700304402203f19edb1bad28b02e941ac7fcc0d6f10cebaf2022a7fe3"
    "75841d35e1787d1905022023821cf174b67647a13ed179dcbc24c3fa3cae6547f0407ada2d271f44763fcb";

static const char kCert_expired[] =
    "3082012e3081d5a003020102020101300a06082a8648ce3d04030230143112301006035504030c096c6f6361"
    "6c686f7374301e170d3030303130313030303030305a170d3031303130313030303030305a30143112301006"
    "035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d03010703420004fdc4"
    "abe25332cf43e958916efc607c6f629c7d2c5cc5698b76af78fb1c391bfe80eabcc2d09ff84467ae1ce58c0f"
    "d3e97fd8a0d0826cadd308a54fa29aacd6e2a318301630140603551d11040d300b82096c6f63616c686f7374"
    "300a06082a8648ce3d0403020348003045022059686237ea9d03e9ebe9da5a8051ce748c75d939e3e471a44f"
    "24d49881cdffce022100a26ddd014feb9b6073baf32afd392a82fa43cebfe1bc41923c93064b0d85f9ca";

static const char kCert_future[] =
    "308201323081d9a003020102020101300a06082a8648ce3d04030230143112301006035504030c096c6f6361"
    "6c686f73743022180f32313030303130313030303030305a180f32313230303130313030303030305a301431"
    "12301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d0301070342"
    "0004fdc4abe25332cf43e958916efc607c6f629c7d2c5cc5698b76af78fb1c391bfe80eabcc2d09ff84467ae"
    "1ce58c0fd3e97fd8a0d0826cadd308a54fa29aacd6e2a318301630140603551d11040d300b82096c6f63616c"
    "686f7374300a06082a8648ce3d040302034800304502203513097db1cb1648577d355c8527be50d3f75b190c"
    "0d25f5cf1dc0665f7951020221008639435dac5d96b887dd9111d048feab9a56b9c938ec9b9c91ec626cc6cd"
    "6a68";


enum { ALERT, CERT, NOT_TLS, HANG_UP };

typedef struct {
    const char *name;
    int         kind;
    int         alert;      // ALERT: the alert description
    const char *cert;       // CERT: the certificate, in hex
    const char *peer;       // the name given to SSLSetPeerDomainName
} Case;

#define A(n, what) { "alert " #n " " what, ALERT, n, NULL, "localhost" }

static const Case kCases[] = {
    A(10, "unexpected_message"),     A(20, "bad_record_mac"),
    A(21, "decryption_failed"),      A(22, "record_overflow"),
    A(30, "decompression_failure"),  A(40, "handshake_failure"),
    A(41, "no_certificate"),         A(42, "bad_certificate"),
    A(43, "unsupported_certificate"),A(44, "certificate_revoked"),
    A(45, "certificate_expired"),    A(46, "certificate_unknown"),
    A(47, "illegal_parameter"),      A(48, "unknown_ca"),
    A(49, "access_denied"),          A(50, "decode_error"),
    A(51, "decrypt_error"),          A(60, "export_restriction"),
    A(70, "protocol_version"),       A(71, "insufficient_security"),
    A(80, "internal_error"),         A(86, "inappropriate_fallback"),
    A(90, "user_canceled"),          A(100, "no_renegotiation"),
    A(109, "missing_extension"),     A(110, "unsupported_extension"),
    A(112, "unrecognized_name"),     A(116, "certificate_required"),
    A(120, "no_application_protocol"),
    A(0, "close_notify"),
    { "cert untrusted",             CERT, 0, kCert_valid,   "localhost" },
    { "cert untrusted, wrong host", CERT, 0, kCert_valid,   "wrong.invalid" },
    { "cert expired",               CERT, 0, kCert_expired, "localhost" },
    { "cert not yet valid",         CERT, 0, kCert_future,  "localhost" },
    { "not tls",                    NOT_TLS, 0, NULL,       "localhost" },
    { "eof",                        HANG_UP, 0, NULL,       "localhost" },
};

typedef struct { int lfd; const Case *c; } Listener;

static int read_full(int fd, unsigned char *p, size_t n) {
    size_t got = 0;
    while (got < n) { ssize_t r = read(fd, p + got, n - got); if (r <= 0) return -1; got += (size_t)r; }
    return 0;
}

static size_t put24(unsigned char *p, size_t v) {
    p[0] = (unsigned char)(v >> 16); p[1] = (unsigned char)(v >> 8); p[2] = (unsigned char)v;
    return 3;
}

static size_t unhex(const char *h, unsigned char *out, size_t max) {
    size_t n = 0;
    for (; h[0] && h[1] && n < max; h += 2) {
        unsigned v; sscanf(h, "%2x", &v); out[n++] = (unsigned char)v;
    }
    return n;
}

// An ECDHE-ECDSA suite the client offered. Both stacks check the certificate as soon as the
// Certificate message arrives, so the ServerKeyExchange the suite calls for is never missed.
static int pick_suite(const unsigned char *ch, size_t n, unsigned char out[2]) {
    static const unsigned char want[][2] = {
        {0xc0,0x09}, {0xc0,0x0a}, {0xc0,0x23}, {0xc0,0x24}, {0xc0,0x2b}, {0xc0,0x2c} };
    size_t o = 4 + 2 + 32;                      // handshake header, version, random
    if (o + 1 > n) return -1;
    o += 1 + ch[o];                             // session id
    if (o + 2 > n) return -1;
    size_t cl = ((size_t)ch[o] << 8) | ch[o + 1]; o += 2;
    if (o + cl > n) return -1;
    for (size_t w = 0; w < sizeof want / sizeof want[0]; w++)
        for (size_t i = 0; i + 1 < cl; i += 2)
            if (!memcmp(ch + o + i, want[w], 2)) { memcpy(out, want[w], 2); return 0; }
    return -1;
}

// ServerHello (TLS 1.2, no session id, renegotiation_info), Certificate, ServerHelloDone,
// in one record.
static size_t cert_flight(const Case *c, const unsigned char *ch, size_t chl, unsigned char *out) {
    unsigned char der[1024], suite[2];
    size_t dl = unhex(c->cert, der, sizeof der), o = 5;
    if (pick_suite(ch, chl, suite)) return 0;
    out[o++] = 0x02; o += put24(out + o, 2 + 32 + 1 + 2 + 1 + 2 + 5);
    out[o++] = 0x03; out[o++] = 0x03;
    memset(out + o, 0x5a, 32); o += 32;
    out[o++] = 0;
    out[o++] = suite[0]; out[o++] = suite[1];
    out[o++] = 0;
    static const unsigned char ext[] = { 0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00 };
    memcpy(out + o, ext, sizeof ext); o += sizeof ext;
    out[o++] = 0x0b; o += put24(out + o, 3 + 3 + dl);
    o += put24(out + o, 3 + dl);
    o += put24(out + o, dl);
    memcpy(out + o, der, dl); o += dl;
    out[o++] = 0x0e; o += put24(out + o, 0);
    out[0] = 0x16; out[1] = 0x03; out[2] = 0x03;
    out[3] = (unsigned char)((o - 5) >> 8); out[4] = (unsigned char)(o - 5);
    return o;
}

static void *serve(void *arg) {
    Listener *l = arg;
    const Case *c = l->c;
    int fd = accept(l->lfd, NULL, NULL);
    if (fd < 0) return NULL;
    if (c->kind == HANG_UP) { close(fd); return NULL; }
    unsigned char hdr[5], ch[16384], out[2048];
    if (read_full(fd, hdr, 5) == 0) {
        size_t len = ((size_t)hdr[3] << 8) | hdr[4];
        if (len <= sizeof ch && read_full(fd, ch, len) == 0) {
            if (c->kind == ALERT) {
                // close_notify is a warning; every other alert here is fatal.
                unsigned char a[7] = { 0x15, 0x03, 0x03, 0x00, 0x02, c->alert ? 2 : 1,
                                       (unsigned char)c->alert };
                write(fd, a, sizeof a);
            } else if (c->kind == NOT_TLS) {
                static const char h[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                write(fd, h, sizeof h - 1);
            } else {
                size_t n = cert_flight(c, ch, len, out);
                if (n) write(fd, out, n);
            }
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

static OSStatus run_case(const Case *c) {
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&a, sizeof a) || listen(lfd, 1) ||
        getsockname(lfd, (struct sockaddr *)&a, &al)) { printf("FAIL: listen\n"); exit(1); }
    Listener l = { lfd, c };
    pthread_t th;
    pthread_create(&th, NULL, serve, &l);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0 || connect(fd, (struct sockaddr *)&a, sizeof a)) { printf("FAIL: connect\n"); exit(1); }
    struct timeval to = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof to);

    SSLContextRef ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    SSLSetIOFuncs(ctx, sock_read, sock_write);
    SSLSetConnection(ctx, &fd);
    SSLSetPeerDomainName(ctx, c->peer, strlen(c->peer));
    OSStatus st;
    while ((st = SSLHandshake(ctx)) == errSSLWouldBlock) ;
    // SSLClose before the release, as a caller finished with a context does. The hooks forget
    // a context there, and a released context's address can come back for the next case.
    SSLClose(ctx);
    close(fd);
    pthread_join(th, NULL);
    close(lfd);
    CFRelease(ctx);
    return st;
}

int main(void) {
    for (size_t i = 0; i < sizeof kCases / sizeof kCases[0]; i++)
        printf("  %-34s %d\n", kCases[i].name, (int)run_case(&kCases[i]));
    return 0;
}
