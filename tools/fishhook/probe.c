#include "../../src/mac/aquatransport_symbols.h"
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %d: %s (%s)\n", __LINE__, #x, dlerror()); exit(1); } } while (0)
typedef int (*function)(void);
typedef struct { void *handle; function lazy; void *(*address)(void); } Client;
// Exported by the executable: global lookup must find these, scoped lookup must not.
int AQNamespaceLazy(void) { return 33; }
int AQNamespaceNonlazy(void) { return 33; }
int SSLNewContext(void) { return -12345; }
void *CFHTTPMessageCreateRequest(void) { return NULL; }
static int replacement(void) { return 99; }
static int image_replacement(void) { return 77; }

static Client client(const char *root, const char *name) {
    char path[2048];
    int length = snprintf(path, sizeof path, "%s/%s.dylib", root, name);
    CHECK(length >= 0 && (size_t)length < sizeof path);
    Client c;
    c.handle = dlopen(path, RTLD_LAZY | RTLD_LOCAL | RTLD_FIRST);
    CHECK(c.handle);
    c.lazy = dlsym(c.handle, "probe_lazy");
    c.address = dlsym(c.handle, "probe_address");
    CHECK(c.lazy && c.address);
    return c;
}
static void expect(Client c, int value) {
    CHECK(c.lazy() == value);
    CHECK(((function)c.address())() == value);
}
static void collisions(Client c, int value) {
    function ssl = dlsym(c.handle, "probe_ssl");
    function cf = dlsym(c.handle, "probe_cfnetwork");
    CHECK(ssl && cf && ssl() == value && cf() == value);
}
static void system_originals(void) {
    // RTLD_FIRST still follows actual reexports, as required for libSystem.
    CHECK(fishhook_resolve(tf_dlopen_providers, "dlopen"));
    CHECK(fishhook_resolve(tf_socket_providers, "connect"));
    CHECK(fishhook_resolve(tf_dnssd_providers, "DNSServiceBrowse"));
}

int main(int argc, char **argv) {
    CHECK(argc == 2 || argc == 4);
    const char *root = argv[1];
    char a_path[2048], umbrella_path[2048], absent_path[2048];
    snprintf(a_path, sizeof a_path, "%s/a/libcollision.dylib", root);
    snprintf(umbrella_path, sizeof umbrella_path, "%s/umbrella.dylib", root);
    snprintf(absent_path, sizeof absent_path, "%s/not-loaded.dylib", root);
    const char *providers[] = { a_path, umbrella_path, NULL };
    const char *absent[] = { absent_path, NULL };
    CHECK(!fishhook_resolve(absent, "AQNamespaceLazy"));
    CHECK(!dlopen(absent_path, RTLD_LAZY | RTLD_NOLOAD));
    Client bound = client(root, "bound-a"), unbound = client(root, "unbound-a");
    Client other = client(root, "bound-b"), other_unbound = client(root, "unbound-b");
    Client weak = client(root, "weak"), umbrella = client(root, "umbrella-client");
    Client unapproved = client(root, "unapproved-client");
    Client flat = client(root, "flat"), lookup = client(root, "lookup");
    char client_path[2048];
    snprintf(client_path, sizeof client_path, "%s/bound-a.dylib", root);
    const char *ordinary_dependencies[] = { client_path, NULL };
    CHECK(!fishhook_resolve(ordinary_dependencies, "AQNamespaceLazy"));
    expect(bound, 11); expect(other, 22);
    expect(flat, 33); expect(lookup, 33);
    CHECK(((function)dlsym(RTLD_DEFAULT, "AQNamespaceLazy"))() == 33);
    CHECK(((function)fishhook_resolve(providers, "AQNamespaceLazy"))() == 11);
    const char *umbrella_only[] = { umbrella_path, NULL };
    CHECK(((function)fishhook_resolve(umbrella_only, "AQNamespaceLazy"))() == 11);
    system_originals();

    struct rebinding hooks[] = {
        { "AQNamespaceLazy", (void *)replacement, NULL, providers },
        { "AQNamespaceNonlazy", (void *)replacement, NULL, providers }
    };
    struct rebinding invalid = { "AQNamespaceLazy", (void *)replacement, NULL, NULL };
    CHECK(rebind_symbols(&invalid, 1) == -1);
    expect(bound, 11); expect(other, 22);

    // Image-specific rebinding must enforce the same provider rule.
    Dl_info image;
    CHECK(dladdr((void *)other.lazy, &image));
    const struct mach_header *header = image.dli_fbase;
    intptr_t slide = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++)
        if (_dyld_get_image_header(i) == header) slide = _dyld_get_image_vmaddr_slide(i);
    CHECK(rebind_symbols_image((void *)header, slide, hooks, 2) == 0);
    expect(other, 22);
    CHECK(dladdr((void *)bound.lazy, &image));
    header = image.dli_fbase;
    for (uint32_t i = 0; i < _dyld_image_count(); i++)
        if (_dyld_get_image_header(i) == header) slide = _dyld_get_image_vmaddr_slide(i);
    struct rebinding specific = { "AQNamespaceLazy", (void *)image_replacement, NULL, providers };
    CHECK(rebind_symbols_image((void *)header, slide, &specific, 1) == 0);
    CHECK(bound.lazy() == 77 && ((function)bound.address())() == 11);
    CHECK(rebind_symbols(hooks, 2) == 0);
    expect(bound, 99); expect(unbound, 99); expect(weak, 99); expect(umbrella, 99);
    expect(other, 22); expect(other_unbound, 22); expect(unapproved, 11);
    expect(flat, 33); expect(lookup, 33);
    expect(client(root, "late-a"), 99); expect(client(root, "late-b"), 22);
    CHECK(((function)fishhook_resolve(providers, "AQNamespaceLazy"))() == 11);
    // A later registration for a different provider must not mask this one.
    const char *wrong[] = { "/not/the/provider/libcollision.dylib", NULL };
    struct rebinding mismatch = { "AQNamespaceLazy", (void *)image_replacement, NULL, wrong };
    CHECK(rebind_symbols(&mismatch, 1) == 0);
    expect(bound, 99); expect(other, 22);
    puts("PASS provider filtering: bound/lazy/non-lazy/weak/late/image-specific/reexports/flat/dynamic lookup");

    if (argc == 4) {
        // The installed loader is disabled at startup by the script. Enable only
        // the engine being tested, with local rules that disable optional modules.
        CHECK(setenv("AQUATRANSPORT_DIR", argv[3], 1) == 0);
        CHECK(dlopen(argv[2], RTLD_NOW | RTLD_LOCAL));
        collisions(bound, 11); collisions(unbound, 11); collisions(other, 22);
        collisions(client(root, "engine-late-a"), 11);
        collisions(client(root, "engine-late-b"), 22);
        // Resolve real originals after both conflicting providers are loaded.
        CHECK(dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY | RTLD_LOCAL));
        void *security_read = fishhook_resolve(tf_security_providers, "SSLRead");
        CHECK(security_read && security_read != fishhook_resolve(providers, "SSLRead"));
        CHECK(dlopen("/System/Library/Frameworks/CFNetwork.framework/CFNetwork", RTLD_LAZY | RTLD_LOCAL));
        CHECK(fishhook_resolve(tf_cfnetwork_providers, "CFURLRequestCreateMutableCopy"));
        CHECK(dlsym(RTLD_DEFAULT, "SSLNewContext") == (void *)&SSLNewContext);
        CHECK(dlsym(RTLD_DEFAULT, "CFHTTPMessageCreateRequest") == (void *)&CFHTTPMessageCreateRequest);
        char system_path[2048];
        snprintf(system_path, sizeof system_path, "%s/system-client.dylib", root);
        void *system = dlopen(system_path, RTLD_LAZY | RTLD_LOCAL | RTLD_FIRST);
        CHECK(system);
        function system_probe = dlsym(system, "probe_system");
        CHECK(system_probe && system_probe() == 1);
        puts("PASS engine: unrelated SSLRead/CFURLRequestCreateMutableCopy imports survive, including late loads");
        puts("PASS engine: real Security calls and CFNetwork header rewriting work despite shadowing executable exports");
    }
    return 0;
}
