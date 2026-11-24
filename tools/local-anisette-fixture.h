/* Test-only replacement of the native provider boundary. Production has no provider
 * injection or configuration switch. All OTPs and credentials are synthetic;
 * each probe installs a catch-all URL protocol and supplies a synthetic device ID. */
#import <objc/runtime.h>
#include <dlfcn.h>
#include <assert.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

static NSString *aq_test_client_info(void) {
    char model[256]; size_t length = sizeof model;
    assert(!sysctlbyname("hw.model", model, &length, NULL, 0) && length && length <= sizeof model);
    model[sizeof model-1] = 0;
    NSDictionary *system = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    NSString *version = [system objectForKey:@"ProductVersion"], *build = [system objectForKey:@"ProductBuildVersion"];
    assert([version length] && [build length]);
    return [NSString stringWithFormat:@"<%s> <Mac OS X;%@;%@> <com.apple.AuthKit/1 (com.apple.akd/1.0)>", model, version, build];
}
#define AQTestClient aq_test_client_info()
#define AQTestDevice @"00000000-0000-4000-8000-000000000001"

static NSString *aq_test_user_agent(void) {
    NSBundle *network = [NSBundle bundleWithPath:@"/System/Library/Frameworks/CFNetwork.framework"];
    NSString *version = [network objectForInfoDictionaryKey:@"CFBundleVersion"];
    struct utsname system; assert([version length] && !uname(&system));
    return [NSString stringWithFormat:@"akd/1.0 CFNetwork/%@ Darwin/%s", version, system.release];
}
#define AQTestUserAgent aq_test_user_agent()

static IMP aq_test_install_otp(IMP implementation) {
    Class utility = NSClassFromString(@"AQNativeAnisette");
    if (!utility) {
        const char *loader = getenv("DYLD_INSERT_LIBRARIES"); assert(loader);
        NSString *path = [[[NSString stringWithUTF8String:loader] stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"aquatransport_gsa.dylib"];
        assert(dlopen([path fileSystemRepresentation], RTLD_LAZY | RTLD_LOCAL));
        utility = NSClassFromString(@"AQNativeAnisette");
    }
    Method method = class_getClassMethod(utility, NSSelectorFromString(@"headersForOwner:error:"));
    assert(method && method_getNumberOfArguments(method) == 4);
    char result[8] = {0}, argument[8] = {0};
    method_getReturnType(method, result, sizeof result);
    method_getArgumentType(method, 2, argument, sizeof argument);
    assert(!strcmp(result, "@") && !strcmp(argument, "@"));
    return method_setImplementation(method, implementation);
}

static IMP aq_test_install_sync(IMP implementation) {
    Class utility = NSClassFromString(@"AQNativeAnisette");
    assert(utility);
    Method method = class_getClassMethod(utility, NSSelectorFromString(@"synchronizeServerData:owner:error:"));
    assert(method && method_getNumberOfArguments(method) == 5);
    char result[8] = {0}, argument[8] = {0};
    method_getReturnType(method, result, sizeof result);
    method_getArgumentType(method, 2, argument, sizeof argument);
    assert(!strcmp(result, "@") && !strcmp(argument, "@"));
    return method_setImplementation(method, implementation);
}

static IMP aq_test_install_routing(IMP implementation) {
    Class utility = NSClassFromString(@"AQNativeAnisette");
    assert(utility);
    Method method = class_getClassMethod(utility, NSSelectorFromString(@"storeRouting:owner:error:"));
    assert(method && method_getNumberOfArguments(method) == 5);
    return method_setImplementation(method, implementation);
}
