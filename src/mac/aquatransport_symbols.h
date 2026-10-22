// Exact import providers used by the macOS hooks. Keep paths explicit: matching
// only a framework basename would also accept an application's private framework.
// These static lists outlive fishhook's registrations. The first path is preferred
// for original-function lookup; later paths cover older install names/reexports.
#ifndef AQUATRANSPORT_SYMBOLS_H
#define AQUATRANSPORT_SYMBOLS_H

#include "../../deps/fishhook/fishhook.h"

#define TF_PROVIDERS(name, ...) \
    static const char *const name[] __attribute__((unused)) = { __VA_ARGS__, NULL }

TF_PROVIDERS(tf_security_providers,
    "/System/Library/Frameworks/Security.framework/Versions/A/Security");
TF_PROVIDERS(tf_cfnetwork_providers,
    "/System/Library/Frameworks/CFNetwork.framework/Versions/A/CFNetwork",
    "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/CFNetwork.framework/Versions/A/CFNetwork",
    "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices");
TF_PROVIDERS(tf_corefoundation_providers,
    "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation");
TF_PROVIDERS(tf_dlopen_providers,
    "/usr/lib/libSystem.B.dylib", "/usr/lib/system/libdyld.dylib");
TF_PROVIDERS(tf_socket_providers,
    "/usr/lib/libSystem.B.dylib", "/usr/lib/system/libsystem_kernel.dylib");
TF_PROVIDERS(tf_dnssd_providers,
    "/usr/lib/libSystem.B.dylib", "/usr/lib/system/libsystem_dnssd.dylib",
    "/usr/lib/libdns_sd.dylib");
TF_PROVIDERS(tf_bom_providers,
    "/System/Library/PrivateFrameworks/Bom.framework/Versions/A/Bom");

#undef TF_PROVIDERS
#endif
