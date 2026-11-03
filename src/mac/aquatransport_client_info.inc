/* A coherent GrandSlam client description: real Mac model and installed OS,
 * with the akd application token Apple currently accepts for this endpoint.
 * Do not substitute a model or OS from another machine. */
#ifndef AQUATRANSPORT_CLIENT_INFO_INC
#define AQUATRANSPORT_CLIENT_INFO_INC

#include <sys/types.h>
#include <sys/sysctl.h>

static BOOL aq_client_component(NSString *value, NSString *allowed, NSUInteger maximum) {
    return [value isKindOfClass:[NSString class]] && [value length] && [value length] <= maximum &&
        [value rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:allowed] invertedSet]].location == NSNotFound;
}

static NSString *aq_client_info(void) {
    char model[256]; size_t length = sizeof model;
    if (sysctlbyname("hw.model", model, &length, NULL, 0) || !length || length > sizeof model) return nil;
    model[sizeof model-1] = 0;
    NSString *hardware = [NSString stringWithUTF8String:model];
    NSDictionary *system = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    NSString *version = [system objectForKey:@"ProductVersion"], *build = [system objectForKey:@"ProductBuildVersion"];
    NSString *letters = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    if (!aq_client_component(hardware, [letters stringByAppendingString:@",._-"], 128) ||
        !aq_client_component(version, @"0123456789.", 32) || !aq_client_component(build, letters, 32)) return nil;
    return [NSString stringWithFormat:@"<%@> <Mac OS X;%@;%@> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
        hardware, version, build];
}

#endif
