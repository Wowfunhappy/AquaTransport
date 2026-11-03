// Exercise the exact engine with TLS-1.3-only peers, including a connection
// opened synchronously inside another connection's trust evaluation. Trust
// anchors are attached to these test trust objects only; no keychain is edited.
#include "../src/mac/aquatransport_symbols.h"
#include <Security/Security.h>
#include <Security/SecureTransport.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static SSL_CTX *server;
static CFArrayRef anchors;
static int use_anchor = 1, nested = 0, trust_calls = 0;
static int (*guard_active)(void);
static OSStatus (*original_create)(CFTypeRef, CFTypeRef, SecTrustRef *);
static OSStatus (*original_anchors)(SecTrustRef, CFArrayRef);
static OSStatus (*original_only)(SecTrustRef, Boolean);
static void connection(const char *host, int expected, int app_verified);
static OSStatus create_trust(CFTypeRef certificates, CFTypeRef policies, SecTrustRef *trust);

// Production links Security as a lazy framework. Its __lazy_symbol section
// uses S_LAZY_DYLIB_SYMBOL_POINTERS, which ordinary fishhook intentionally does
// not visit. Supply the per-trust fixture anchor at that import as well.
static void hook_engine_trust(const char *path) {
#ifdef __LP64__
    typedef struct mach_header_64 Header;
    typedef struct segment_command_64 Segment;
    typedef struct section_64 Section;
    typedef struct nlist_64 Symbol;
    const uint32_t segment_command = LC_SEGMENT_64;
#else
    typedef struct mach_header Header;
    typedef struct segment_command Segment;
    typedef struct section Section;
    typedef struct nlist Symbol;
    const uint32_t segment_command = LC_SEGMENT;
#endif
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        if (strcmp(_dyld_get_image_name(i), path)) continue;
        const Header *header = (const Header *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct symtab_command *symtab = NULL;
        const struct dysymtab_command *dysymtab = NULL;
        uintptr_t linkedit = 0;
        const char *cursor = (const char *)(header + 1);
        for (uint32_t j = 0; j < header->ncmds; ++j) {
            const struct load_command *command = (const void *)cursor;
            if (command->cmd == LC_SYMTAB) symtab = (const void *)cursor;
            if (command->cmd == LC_DYSYMTAB) dysymtab = (const void *)cursor;
            if (command->cmd == segment_command) {
                const Segment *segment = (const void *)cursor;
                if (!strcmp(segment->segname, SEG_LINKEDIT))
                    linkedit = slide + segment->vmaddr - segment->fileoff;
            }
            cursor += command->cmdsize;
        }
        CHECK(symtab && dysymtab && linkedit);
        const Symbol *symbols = (const void *)(linkedit + symtab->symoff);
        const char *strings = (const void *)(linkedit + symtab->stroff);
        const uint32_t *indices = (const void *)(linkedit + dysymtab->indirectsymoff);
        for (uint32_t n = 0; n < symtab->nsyms; ++n)
            if (!strcmp(strings + symbols[n].n_un.n_strx, "_tf_reentrant"))
                guard_active = (int (*)(void))(slide + symbols[n].n_value);
        CHECK(guard_active);
        cursor = (const char *)(header + 1);
        for (uint32_t j = 0; j < header->ncmds; ++j) {
            const struct load_command *command = (const void *)cursor;
            if (command->cmd == segment_command) {
                const Segment *segment = (const void *)cursor;
                const Section *sections = (const void *)(segment + 1);
                for (uint32_t k = 0; k < segment->nsects; ++k) {
                    const Section *section = sections + k;
                    if ((section->flags & SECTION_TYPE) != S_LAZY_DYLIB_SYMBOL_POINTERS) continue;
                    void **slots = (void **)(slide + section->addr);
                    for (size_t n = 0; n < section->size / sizeof(void *); ++n) {
                        uint32_t index = indices[section->reserved1 + n];
                        if (index < symtab->nsyms && !strcmp(strings + symbols[index].n_un.n_strx,
                                                          "_SecTrustCreateWithCertificates")) {
                            slots[n] = (void *)create_trust;
                            return;
                        }
                    }
                }
            }
            cursor += command->cmdsize;
        }
    }
    CHECK(!"engine trust import not found");
}

static OSStatus create_trust(CFTypeRef certificates, CFTypeRef policies, SecTrustRef *trust) {
    ++trust_calls;
    CHECK(guard_active && guard_active());
    if (nested) {
        int reject = nested == 2;
        nested = 0;
        connection(reject ? "nested-wrong.invalid" : "localhost", !reject, 0);
        CHECK(guard_active());
        printf("PASS %s nested TLS, outer trust guard preserved\n", reject ? "rejected" : "verified");
    }
    OSStatus status = original_create(certificates, policies, trust);
    if (!status && use_anchor) {
        CHECK(original_anchors(*trust, anchors) == noErr);
        CHECK(original_only(*trust, true) == noErr);
    }
    return status;
}

static OSStatus rd(SSLConnectionRef c, void *buf, size_t *len) {
    size_t want = *len, got = 0;
    while (got < want) {
        ssize_t n = read(*(const int *)c, (char *)buf + got, want - got);
        if (n <= 0) { *len = got; return errSSLClosedGraceful; }
        got += (size_t)n;
    }
    return noErr;
}
static OSStatus wr(SSLConnectionRef c, const void *buf, size_t *len) {
    size_t want = *len, got = 0;
    while (got < want) {
        ssize_t n = write(*(const int *)c, (const char *)buf + got, want - got);
        if (n <= 0) { *len = got; return errSSLClosedAbort; }
        got += (size_t)n;
    }
    return noErr;
}

static void connection(const char *host, int expected, int app_verified) {
    int pair[2]; CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        close(pair[0]); alarm(15);
        SSL *ssl = SSL_new(server); CHECK(ssl && SSL_set_fd(ssl, pair[1]) == 1);
        int accepted = SSL_accept(ssl);
        if (expected) {
            CHECK(accepted == 1 && SSL_version(ssl) == TLS1_3_VERSION);
            char ch;
            CHECK(SSL_read(ssl, &ch, 1) == 1 && ch == 'Q');
            CHECK(SSL_write(ssl, "A", 1) == 1);
        }
        SSL_free(ssl); close(pair[1]); _exit(0);
    }
    close(pair[1]); alarm(20);
    SSLContextRef context;
    CHECK(SSLNewContext(false, &context) == noErr);
    CHECK(SSLSetIOFuncs(context, rd, wr) == noErr);
    CHECK(SSLSetConnection(context, &pair[0]) == noErr);
    CHECK(SSLSetPeerDomainName(context, host, strlen(host)) == noErr);
    if (app_verified)
        CHECK(SSLSetSessionOption(context, kSSLSessionOptionBreakOnServerAuth, true) == noErr);
    OSStatus status;
    do { status = SSLHandshake(context); } while (status == errSSLWouldBlock);
    if (app_verified && status == errSSLPeerAuthCompleted) {
        SecTrustRef trust = NULL; SecTrustResultType result;
        CHECK(SSLCopyPeerTrust(context, &trust) == noErr && trust);
        CHECK(SecTrustEvaluate(trust, &result) == noErr);
        CFRelease(trust);
        if (result == kSecTrustResultProceed || result == kSecTrustResultUnspecified) {
            do { status = SSLHandshake(context); } while (status == errSSLWouldBlock);
        } else status = errSSLXCertChainInvalid;
    }
    if (expected ? status != noErr : status == noErr)
        fprintf(stderr, "connection host=%s app=%d status=%d trust_calls=%d process=%s\n",
                host, app_verified, (int)status, trust_calls, getprogname());
    CHECK(expected ? status == noErr : status != noErr);
    if (expected) {
        size_t n; char reply;
        CHECK(SSLWrite(context, "Q", 1, &n) == noErr && n == 1);
        CHECK(SSLRead(context, &reply, 1, &n) == noErr && n == 1 && reply == 'A');
    }
    SSLClose(context); SSLDisposeContext(context); close(pair[0]);
    int result;
    CHECK(waitpid(child, &result, 0) == child);
    CHECK(WIFEXITED(result) && WEXITSTATUS(result) == 0);
    alarm(0);
}

static EVP_PKEY *key(void) {
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *result = NULL;
    CHECK(context && EVP_PKEY_keygen_init(context) == 1);
    CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) == 1);
    CHECK(EVP_PKEY_keygen(context, &result) == 1);
    EVP_PKEY_CTX_free(context);
    return result;
}

static void extension(X509 *certificate, X509 *issuer, int nid, const char *value) {
    X509V3_CTX context;
    X509V3_set_ctx(&context, issuer, certificate, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &context, nid, (char *)value);
    CHECK(ext && X509_add_ext(certificate, ext, -1) == 1);
    X509_EXTENSION_free(ext);
}

static X509 *certificate(EVP_PKEY *public_key, X509 *issuer, EVP_PKEY *issuer_key) {
    X509 *cert = X509_new(); CHECK(cert);
    CHECK(X509_set_version(cert, 2) == 1);
    CHECK(ASN1_INTEGER_set(X509_get_serialNumber(cert), issuer ? 2 : 1) == 1);
    CHECK(X509_gmtime_adj(X509_getm_notBefore(cert), -60));
    CHECK(X509_gmtime_adj(X509_getm_notAfter(cert), 3600));
    CHECK(X509_set_pubkey(cert, public_key) == 1);
    CHECK(X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC,
          (const unsigned char *)(issuer ? "localhost" : "AquaTransport test root"), -1, -1, 0) == 1);
    CHECK(X509_set_issuer_name(cert, X509_get_subject_name(issuer ? issuer : cert)) == 1);
    extension(cert, issuer ? issuer : cert, NID_basic_constraints,
              issuer ? "critical,CA:FALSE" : "critical,CA:TRUE");
    extension(cert, issuer ? issuer : cert, NID_key_usage,
              issuer ? "critical,digitalSignature,keyEncipherment" : "critical,keyCertSign,cRLSign");
    if (issuer) {
        extension(cert, issuer, NID_subject_alt_name, "DNS:localhost,DNS:nested.localhost");
        extension(cert, issuer, NID_ext_key_usage, "serverAuth");
    }
    CHECK(X509_sign(cert, issuer_key, EVP_sha256()) > 0);
    return cert;
}

int main(int argc, char **argv) {
    CHECK(argc == 4 || argc == 5);
    signal(SIGPIPE, SIG_IGN);
    // The installed loader is excluded by the executable's original name.
    // Name the isolated test process before loading the engine under test.
    setprogname(argv[3]);
    CHECK(setenv("AQUATRANSPORT_DIR", argv[2], 1) == 0);
    CHECK(dlopen(argv[1], RTLD_NOW | RTLD_LOCAL));
    original_create = fishhook_resolve(tf_security_providers, "SecTrustCreateWithCertificates");
    original_anchors = fishhook_resolve(tf_security_providers, "SecTrustSetAnchorCertificates");
    original_only = fishhook_resolve(tf_security_providers, "SecTrustSetAnchorCertificatesOnly");
    CHECK(original_create && original_anchors && original_only);
    struct rebinding hook = { "SecTrustCreateWithCertificates", (void *)create_trust,
                             NULL, tf_security_providers };
    CHECK(rebind_symbols(&hook, 1) == 0);
    hook_engine_trust(argv[1]);

    EVP_PKEY *root_key = key(), *leaf_key = key();
    X509 *root = certificate(root_key, NULL, root_key);
    X509 *leaf = certificate(leaf_key, root, root_key);
    unsigned char *der = NULL; int length = i2d_X509(root, &der); CHECK(length > 0);
    CFDataRef data = CFDataCreate(NULL, der, length); OPENSSL_free(der); CHECK(data);
    SecCertificateRef native_root = SecCertificateCreateWithData(NULL, data); CHECK(native_root);
    const void *values[] = { native_root };
    anchors = CFArrayCreate(NULL, values, 1, &kCFTypeArrayCallBacks); CHECK(anchors);
    CFRelease(native_root); CFRelease(data);
    server = SSL_CTX_new(TLS_server_method()); CHECK(server);
    CHECK(SSL_CTX_set_min_proto_version(server, TLS1_3_VERSION) == 1);
    CHECK(SSL_CTX_set_max_proto_version(server, TLS1_3_VERSION) == 1);
    CHECK(SSL_CTX_use_certificate(server, leaf) == 1);
    CHECK(SSL_CTX_use_PrivateKey(server, leaf_key) == 1);
    X509_free(root); X509_free(leaf); EVP_PKEY_free(root_key); EVP_PKEY_free(leaf_key);

    if (argc == 5) {
        connection("localhost", 0, 0);
        CHECK(trust_calls == 0);
        puts("PASS disabled.txt still excludes trust-service TLS");
    } else {
        nested = 1;
        connection("localhost", 1, 0);
        CHECK(!nested && trust_calls >= 2);
        // A second valid hostname avoids the successful-chain cache and
        // exercises a failing nested connection while the outer one succeeds.
        nested = 2;
        connection("nested.localhost", 1, 0);
        CHECK(!nested && !guard_active());
        connection("localhost", 1, 1);
        connection("wrong.invalid", 0, 0);
        connection("wrong.invalid", 0, 1);
        use_anchor = 0;
        // Use a distinct name to avoid the successful-chain cache.
        connection("untrusted.invalid", 0, 0);
        connection("localhost", 0, 1);
        printf("PASS %s: TLS 1.3, native and app trust, hostname/untrusted rejection\n", argv[3]);
    }
    SSL_CTX_free(server); CFRelease(anchors);
    return 0;
}
