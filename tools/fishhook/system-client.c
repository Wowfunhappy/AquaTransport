#include <Security/SecureTransport.h>
#include <CFNetwork/CFNetwork.h>
// This image's imports name Apple's frameworks, even though the executable
// exports identically named functions. Calls exercise the engine's scoped originals.
int probe_system(void) {
    SSLContextRef context = NULL;
    if (SSLNewContext(false, &context) != noErr || !context) return 0;
    SSLSessionState state;
    int ok = SSLGetSessionState(context, &state) == noErr && state == kSSLIdle;
    SSLDisposeContext(context);
    CFURLRef url = CFURLCreateWithString(NULL, CFSTR("https://namespace.invalid/"), NULL);
    CFHTTPMessageRef message = CFHTTPMessageCreateRequest(NULL, CFSTR("GET"), url, kCFHTTPVersion1_1);
    ok = ok && message != NULL;
    if (message) {
        CFStringRef header = CFHTTPMessageCopyHeaderFieldValue(message, CFSTR("X-Namespace-Test"));
        // The local test rule supplies this header. This asserts that the real
        // CFNetwork import was hooked, rather than merely continuing to work.
        ok = ok && header && CFEqual(header, CFSTR("active"));
        if (header) CFRelease(header);
        CFRelease(message);
    }
    CFRelease(url);
    return ok;
}
