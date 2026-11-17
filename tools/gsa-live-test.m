/* Interactive, local-only GrandSlam diagnostic.
 *
 * Credentials are entered in secure AppKit fields, remain only in this process,
 * and are never printed or written. The test runs the production login bridge
 * through iCloud authentication and account-settings retrieval. Returned account
 * credentials stay in this process; no system account or keychain is updated. */
#import <AppKit/AppKit.h>

#include "../src/mac/aquatransport_gsa.m"

static NSTextField *AQAccountField;
static NSSecureTextField *AQPasswordField;
static NSSecureTextField *AQCodeField;
static const char *AQLiveStage = "starting";
static NSMutableArray *AQLiveResponses;
static void aq_live_stage(const char *stage) {
    AQLiveStage = stage;
    fprintf(stderr, "STAGE: %s\n", stage);
    fflush(stderr);
}

/* Preserve the production transport, but report each actual response before
 * a modal result window can block main(). Never print request credentials. */
static void (*AQLiveWireFinished)(id, SEL, NSURLConnection *);
static void aq_live_wire_finished(id object, SEL selector, NSURLConnection *connection) {
    AQGSAWire *wire = object;
    NSDictionary *outer = aq_plist(wire->body);
    NSDictionary *reply = aq_dict([outer objectForKey:@"Response"]);
    NSDictionary *status = [outer objectForKey:@"ec"] ? outer : aq_dict([(reply ?: outer) objectForKey:@"Status"]);
    if (!AQLiveResponses) AQLiveResponses = [NSMutableArray new];
    if ([AQLiveResponses count] < 20 && wire->response)
        [AQLiveResponses addObject:@{@"response":wire->response, @"body":[NSData dataWithData:wire->body]}];
    id ec = [status objectForKey:@"ec"], hsc = [status objectForKey:@"hsc"];
    NSString *path = [[wire->response URL] path];
    if ([path hasPrefix:@"/setup/authenticate/"]) path = @"/setup/authenticate/<account>";
    fprintf(stderr, "RESPONSE: path=%s HTTP=%ld bytes=%lu plist=%s ec=%ld hsc=%ld\n",
        [path UTF8String], (long)[wire->response statusCode],
        (unsigned long)[wire->body length], outer ? "yes" : "no",
        [ec isKindOfClass:[NSNumber class]] ? (long)[ec integerValue] : LONG_MIN,
        [hsc isKindOfClass:[NSNumber class]] ? (long)[hsc integerValue] : LONG_MIN);
    fflush(stderr);
    AQLiveWireFinished(object, selector, connection);
}

static void aq_live_activate(void) {
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    [NSApp activateIgnoringOtherApps:YES];
}

static NSDictionary *aq_live_credentials(void) {
    NSAlert *alert = [[[NSAlert alloc] init] autorelease];
    [alert setMessageText:@"AquaTransport live iCloud login test"];
    [alert setInformativeText:@"This test authenticates with Apple and retrieves iCloud account settings. Enter your Apple Account and normal password. It will not add or change the Mac's configured iCloud account."];
    [alert addButtonWithTitle:@"Begin Test"];
    [alert addButtonWithTitle:@"Cancel"];

    NSView *view = [[[NSView alloc] initWithFrame:NSMakeRect(0, 0, 420, 86)] autorelease];
    NSTextField *accountLabel = [[[NSTextField alloc] initWithFrame:NSMakeRect(0, 60, 110, 20)] autorelease];
    [accountLabel setStringValue:@"Apple Account:"];
    [accountLabel setBezeled:NO]; [accountLabel setDrawsBackground:NO]; [accountLabel setEditable:NO]; [accountLabel setSelectable:NO];
    AQAccountField = [[[NSTextField alloc] initWithFrame:NSMakeRect(112, 56, 308, 24)] autorelease];
    NSTextField *passwordLabel = [[[NSTextField alloc] initWithFrame:NSMakeRect(0, 25, 110, 20)] autorelease];
    [passwordLabel setStringValue:@"Password:"];
    [passwordLabel setBezeled:NO]; [passwordLabel setDrawsBackground:NO]; [passwordLabel setEditable:NO]; [passwordLabel setSelectable:NO];
    AQPasswordField = [[[NSSecureTextField alloc] initWithFrame:NSMakeRect(112, 21, 308, 24)] autorelease];
    [view addSubview:accountLabel]; [view addSubview:AQAccountField];
    [view addSubview:passwordLabel]; [view addSubview:AQPasswordField];
    [alert setAccessoryView:view];
    [[alert window] setInitialFirstResponder:AQAccountField];
    aq_live_stage("awaiting-credentials");
    if ([alert runModal] != NSAlertFirstButtonReturn) return nil;
    NSString *account = [[AQAccountField stringValue] lowercaseString];
    NSString *password = [AQPasswordField stringValue];
    if (![account length] || ![password length]) return nil;
    return [NSDictionary dictionaryWithObjectsAndKeys:account, @"account", password, @"password", nil];
}

static NSString *aq_live_code(void) {
    NSAlert *alert = [[[NSAlert alloc] init] autorelease];
    [alert setMessageText:@"Enter the Apple verification code"];
    [alert setInformativeText:@"Approve the sign-in notification on a trusted device. If no notification appears, generate a verification code manually on that device."];
    [alert addButtonWithTitle:@"Validate Code"];
    [alert addButtonWithTitle:@"Cancel"];
    AQCodeField = [[[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 240, 24)] autorelease];
    [alert setAccessoryView:AQCodeField];
    [[alert window] setInitialFirstResponder:AQCodeField];
    aq_live_stage("awaiting-verification-code");
    if ([alert runModal] != NSAlertFirstButtonReturn) return nil;
    NSString *code = [AQCodeField stringValue];
    if ([code length] != 6 ||
        [code rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789"] invertedSet]].location != NSNotFound) return nil;
    return code;
}

static void aq_live_result(NSString *title, NSString *message) {
    NSAlert *alert = [[[NSAlert alloc] init] autorelease];
    [alert setMessageText:title]; [alert setInformativeText:message];
    [alert addButtonWithTitle:@"OK"]; [alert runModal];
}

static int aq_live_failure(NSString *stage, NSError *error) {
    NSInteger code = error ? [error code] : -1;
    NSString *message = [NSString stringWithFormat:@"%@ failed (domain %@, code %ld). No account changes were made.",
        stage, error ? [error domain] : @"none", (long)code];
    fprintf(stderr, "FAIL: %s (code %ld)\n", [stage UTF8String], (long)code);
    aq_live_stage("finished-failure-awaiting-dismissal");
    aq_live_result(@"AquaTransport live test failed", message);
    return 1;
}

static NSDictionary *aq_live_bridge(NSString *account, NSString *input, NSError **error) {
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:
        [NSURL URLWithString:@"https://setup.icloud.com/setup/login_or_create_account"]];
    [request setHTTPMethod:@"POST"];
    [request setValue:aq_basic(account, input) forHTTPHeaderField:@"Authorization"];
    return aq_bridge(nil, request, error);
}

int main(void) {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    Method finished = class_getInstanceMethod([AQGSAWire class], @selector(connectionDidFinishLoading:));
    AQLiveWireFinished = (void *)method_setImplementation(finished, (IMP)aq_live_wire_finished);
    aq_live_activate();
    NSDictionary *credentials = aq_live_credentials();
    if (!credentials) { [pool drain]; return 2; }
    NSMutableString *account = [[[credentials objectForKey:@"account"] mutableCopy] autorelease];
    NSMutableString *password = [[[credentials objectForKey:@"password"] mutableCopy] autorelease];
    [AQAccountField setStringValue:@""]; [AQPasswordField setStringValue:@""];

    int result = 1;
    NSError *error = nil;
    aq_live_stage("authenticating-password");
    NSDictionary *responseResult = aq_live_bridge(account, password, &error);
    BOOL attemptedVerification = NO;
    if (!responseResult && [[error domain] isEqual:AQErrorDomain] && [error code] == 401) {
        NSString *code = aq_live_code();
        if (!code) { result = 2; goto finished; }
        attemptedVerification = YES;
        error = nil;
        aq_live_stage("validating-code-and-authenticating-icloud");
        responseResult = aq_live_bridge(account, code, &error);
        [AQCodeField setStringValue:@""];
        if (!responseResult) {
            result = aq_live_failure(@"Code validation or iCloud login", error); goto finished;
        }
    }
    if (!responseResult) { result = aq_live_failure(@"iCloud authentication", error); goto finished; }

    NSHTTPURLResponse *response = [responseResult objectForKey:@"response"];
    if ([response statusCode] != 200 ||
        ![[[response URL] path] isEqual:@"/setup/get_account_settings"] ||
        ![[responseResult objectForKey:@"data"] length]) {
        result = aq_live_failure(@"iCloud account-settings retrieval",
            aq_error([response statusCode], @"The login did not reach a successful account-settings response."));
        goto finished;
    }
    puts("PASS: live production login reached iCloud authentication and account-settings HTTP 200; credentials were not installed or saved");
    fflush(stdout);
    aq_live_stage("finished-success-awaiting-dismissal");
    aq_live_result(@"AquaTransport live test passed", attemptedVerification ?
        @"Apple accepted the verification code and decoded PET. iCloud authentication and account-settings retrieval completed successfully. No iCloud account was installed or changed." :
        @"iCloud authentication and account-settings retrieval completed successfully without a verification challenge. This run did not exercise two-factor verification. No iCloud account was installed or changed.");
    result = 0;

finished:
    [AQLiveResponses release]; AQLiveResponses = nil;
    [AQPending removeAllObjects];
    [account setString:@""]; [password setString:@""];
    AQAccountField = nil; AQPasswordField = nil; AQCodeField = nil;
    [pool drain];
    aq_live_stage("exited");
    return result;
}
