/* The user explicitly toggled Safari. Prepare credentials out of process;
 * commit the native enable only on success. No initialization on observation. */
#include <signal.h>
#import <AppKit/AppKit.h>
#include "prompt_channel.h"
#ifndef AQ_CLOUDTABS_COORDINATOR
#define AQ_CLOUDTABS_COORDINATOR "/usr/share/aquatransport/aquatransport-bootstrap"
#endif
typedef void (*AQServiceSetter)(id,SEL,BOOL);
@interface AQSafariServiceOperation : NSObject {
@public
    id service;
    NSString *account;
    AQServiceSetter native;
    BOOL enable,cancelled,succeeded;
    pid_t child;
    NSWindow *window;
    NSAlert *alert;
    NSDictionary *promptRequest,*promptResponse;
    int promptFD;
    dispatch_semaphore_t answer,uiFinished;
}
@end
@implementation AQSafariServiceOperation
- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [service release];[account release];[window release];[alert release];[promptRequest release];[promptResponse release];
    if(answer)dispatch_release(answer);if(uiFinished)dispatch_release(uiFinished);[super dealloc];
}
@end
static NSMutableSet *AQServiceOperations;
static NSMapTable *AQServiceWindows;
static dispatch_queue_t AQServiceQueue;
static NSString *AQSignedInAccount(void) {
    NSDictionary *prefs=[NSDictionary dictionaryWithContentsOfFile:[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Preferences/MobileMeAccounts.plist"]];
    id accounts=[prefs objectForKey:@"Accounts"];if(![accounts isKindOfClass:[NSArray class]]) return nil;
    NSString *found=nil;
    for(id value in accounts) {
        if(![value isKindOfClass:[NSDictionary class]] || !AQEnabled([value objectForKey:@"LoggedIn"])) continue;
        id dsid=[value objectForKey:@"AccountDSID"];
        if(![dsid isKindOfClass:[NSNumber class]] && ![dsid isKindOfClass:[NSString class]]) return nil;
        if(found) return nil;found=[dsid description];
    }
    return found.length?found:nil;
}
@interface AQSafariPreferencesAdapter : NSObject
+ (void)setService:(id)service enabled:(BOOL)enabled native:(AQServiceSetter)original;
+ (void)rememberWindow:(NSWindow *)window forService:(id)service;
@end
@implementation AQSafariServiceOperation (WindowLifecycle)
- (void)windowClosed:(NSNotification *)notification {
    (void)notification;
    if(enable && !cancelled) [AQSafariPreferencesAdapter setService:service enabled:NO native:native];
}
@end
static void AQPromptEnd(AQSafariServiceOperation *op,NSInteger result) {
    BOOL accepted=result==NSAlertFirstButtonReturn && !op->cancelled;
    NSTextField *field=(NSTextField *)[op->alert accessoryView];
    NSString *value=field?[[field.stringValue copy] autorelease]:@"";
    [op->promptResponse release];op->promptResponse=[@{@"accepted":@(accepted),@"value":accepted?value:@""} retain];
    [field setStringValue:@""];[op->alert.window orderOut:nil];
    [op->alert release];op->alert=nil;
    dispatch_semaphore_signal(op->answer);
}
static void AQPromptPresent(void *context) {
    AQSafariServiceOperation *op=context;NSDictionary *request=op->promptRequest;
    NSString *title=[request objectForKey:@"title"],*message=[request objectForKey:@"message"];
    if(op->cancelled || !op->window || ![title isKindOfClass:[NSString class]] || !title.length || title.length>256 ||
       ![message isKindOfClass:[NSString class]] || message.length>4096 ||
       ![[request objectForKey:@"input"] isKindOfClass:[NSNumber class]] || ![[request objectForKey:@"hidden"] isKindOfClass:[NSNumber class]]) {
        AQPromptEnd(op,NSAlertSecondButtonReturn);return;
    }
    op->alert=[[NSAlert alloc] init];[op->alert setMessageText:title];[op->alert setInformativeText:message];
    [[op->alert addButtonWithTitle:@"OK"] setKeyEquivalent:@"\r"];
    [[op->alert addButtonWithTitle:@"Cancel"] setKeyEquivalent:@"\033"];
    if([[request objectForKey:@"input"] boolValue]) {
        Class fieldClass=[[request objectForKey:@"hidden"] boolValue]?[NSSecureTextField class]:[NSTextField class];
        NSTextField *field=[[[fieldClass alloc] initWithFrame:NSMakeRect(0,0,360,24)] autorelease];
        [op->alert setAccessoryView:field];[op->alert.window setInitialFirstResponder:field];
    }
    // The actual iCloud pane window, including its remote-view host, owns the
    // sheet. Authentication stays out of process; no extra floating application.
    [op->alert beginSheetModalForWindow:op->window completionHandler:^(NSModalResponse result) {AQPromptEnd(op,result);}];
}
static void AQPromptStop(void *context) {
    AQSafariServiceOperation *op=context;
    if(op->alert) [NSApp endSheet:op->alert.window returnCode:NSAlertSecondButtonReturn];
}
static void AQPromptServe(void *context) {
    NSAutoreleasePool *pool=[[NSAutoreleasePool alloc] init];
    AQSafariServiceOperation *op=context;
    for(;;) {
        NSDictionary *request=AQPromptRead(op->promptFD);if(!request)break;
        [op->promptRequest release];op->promptRequest=[request retain];
        dispatch_async_f(dispatch_get_main_queue(),op,AQPromptPresent);
        dispatch_semaphore_wait(op->answer,DISPATCH_TIME_FOREVER);
        BOOL ok=AQPromptWrite(op->promptFD,op->promptResponse);
        [op->promptResponse release];op->promptResponse=nil;
        [op->promptRequest release];op->promptRequest=nil;
        if(!ok)break;
    }
    dispatch_semaphore_signal(op->uiFinished);[pool drain];
}
static void AQServiceComplete(void *context);
static void AQServiceRun(void *context) {
    NSAutoreleasePool *pool=[[NSAutoreleasePool alloc] init];
    AQSafariServiceOperation *op=context;
    char *arguments[]={"aquatransport-bootstrap",op->enable?"--safari-prepare":"--safari-disable",op->enable?(char *)op->account.UTF8String:NULL,NULL};
    posix_spawnattr_t attributes;posix_spawnattr_init(&attributes);
    posix_spawnattr_setflags(&attributes,POSIX_SPAWN_SETPGROUP);posix_spawnattr_setpgroup(&attributes,0);
    posix_spawn_file_actions_t actions;posix_spawn_file_actions_init(&actions);
    int sockets[2]={-1,-1};BOOL bridge=NO;
    NSMutableArray *environment=[NSMutableArray array];
    for(char **entry=*_NSGetEnviron();*entry;entry++)
        if(strncmp(*entry,"AQ_CLOUDTABS_UI_FD=",strlen("AQ_CLOUDTABS_UI_FD="))) [environment addObject:[NSString stringWithUTF8String:*entry]];
    if(op->enable && !socketpair(AF_UNIX,SOCK_STREAM,0,sockets)) {
        int yes=1;setsockopt(sockets[0],SOL_SOCKET,SO_NOSIGPIPE,&yes,sizeof yes);setsockopt(sockets[1],SOL_SOCKET,SO_NOSIGPIPE,&yes,sizeof yes);
        fcntl(sockets[0],F_SETFD,FD_CLOEXEC);
        posix_spawn_file_actions_addclose(&actions,sockets[0]);
        posix_spawn_file_actions_adddup2(&actions,sockets[1],AQ_PROMPT_FD);
        if(sockets[1]!=AQ_PROMPT_FD)posix_spawn_file_actions_addclose(&actions,sockets[1]);
        [environment addObject:@"AQ_CLOUDTABS_UI_FD=198"];
        op->promptFD=sockets[0];bridge=YES;
        dispatch_async_f(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),op,AQPromptServe);
    }
    char **env=calloc(environment.count+1,sizeof(char *));
    for(NSUInteger index=0;index<environment.count;index++)env[index]=(char *)[[environment objectAtIndex:index] UTF8String];
    int error=ECANCELED;pid_t pid=0;
    @synchronized(op) {
        if(!op->cancelled && (!op->enable || bridge)) {
            error=posix_spawn(&pid,AQ_CLOUDTABS_COORDINATOR,&actions,&attributes,arguments,env);
            if(!error) op->child=pid;
        }
    }
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);free(env);if(sockets[1]>=0)close(sockets[1]);
    int status=0;pid_t waited=-1;
    if(!error) do {waited=waitpid(pid,&status,0);} while(waited<0 && errno==EINTR);
    if(bridge) {
        shutdown(sockets[0],SHUT_RDWR);
        dispatch_async_f(dispatch_get_main_queue(),op,AQPromptStop);
        dispatch_semaphore_wait(op->uiFinished,DISPATCH_TIME_FOREVER);
        close(sockets[0]);op->promptFD=-1;
    }
    @synchronized(op) {
        op->child=0;
        op->succeeded=!op->cancelled && !error && waited==pid && WIFEXITED(status) && WEXITSTATUS(status)==0;
    }
    dispatch_async_f(dispatch_get_main_queue(),op,AQServiceComplete);
    [pool drain];
}
static void AQServiceQueueOperation(id service,BOOL enable,AQServiceSetter original,NSString *account) {
    if(!AQServiceQueue) AQServiceQueue=dispatch_queue_create("org.aquatransport.cloudtabs.authorization",DISPATCH_QUEUE_SERIAL);
    if(!AQServiceOperations) AQServiceOperations=[[NSMutableSet alloc] init];
    AQSafariServiceOperation *op=[[AQSafariServiceOperation alloc] init];
    op->service=[service retain];op->account=[account copy];op->native=original;op->enable=enable;
    op->window=[[AQServiceWindows objectForKey:service] retain];op->promptFD=-1;
    op->answer=dispatch_semaphore_create(0);op->uiFinished=dispatch_semaphore_create(0);
    if(enable && op->window) [[NSNotificationCenter defaultCenter] addObserver:op selector:@selector(windowClosed:) name:NSWindowWillCloseNotification object:op->window];
    [AQServiceOperations addObject:op];
    dispatch_async_f(AQServiceQueue,op,AQServiceRun);
    [op release];
}
static void AQServiceComplete(void *context) {
    AQSafariServiceOperation *op=context;
    if(op->enable && !op->cancelled) {
        BOOL commit=op->succeeded && [op->account isEqual:AQSignedInAccount()] && !tf_flag("disable-safari-cloudtabs");
        op->native(op->service,sel_registerName("_setEnabled:"),commit);
        BOOL enabled=((BOOL(*)(id,SEL))objc_msgSend)(op->service,sel_registerName("isEnabled"));
        if(commit && enabled) [AQSafariTabsAdapter requestRefresh];
        else AQServiceQueueOperation(op->service,NO,op->native,op->account);
        // Use the system model's normal update path to restore the checkbox.
        for(NSString *name in @[@"reconcileEnableStatus",@"_updateUI"])
            if([op->service respondsToSelector:NSSelectorFromString(name)]) ((void(*)(id,SEL))objc_msgSend)(op->service,NSSelectorFromString(name));
    }
    [AQServiceOperations removeObject:op];
}
@implementation AQSafariPreferencesAdapter
+ (void)rememberWindow:(NSWindow *)window forService:(id)service {
    if(![NSThread isMainThread])return;
    if(!AQServiceWindows)AQServiceWindows=[[NSMapTable weakToWeakObjectsMapTable] retain];
    if(window)[AQServiceWindows setObject:window forKey:service];
}
+ (void)setService:(id)service enabled:(BOOL)enabled native:(AQServiceSetter)original {
    if(![NSThread isMainThread] || tf_flag("disable-safari-cloudtabs")) {original(service,sel_registerName("_setEnabled:"),enabled);return;}
    BOOL wasEnabled=((BOOL(*)(id,SEL))objc_msgSend)(service,sel_registerName("isEnabled"));
    NSString *account=AQSignedInAccount();
    if(enabled && wasEnabled) {original(service,sel_registerName("_setEnabled:"),YES);return;}
    // Cancel only this feature's in-flight authorization, including its prompt
    // and transport subprocesses. The serial queue drains before a new attempt.
    for(AQSafariServiceOperation *op in AQServiceOperations) {
        if(op->enable && op->service==service) @synchronized(op) {
            op->cancelled=YES;if(op->child>0) kill(-op->child,SIGTERM);
            AQPromptStop(op);
        }
    }
    if(!enabled || !account) {
        original(service,sel_registerName("_setEnabled:"),NO);
        AQServiceQueueOperation(service,NO,original,account);
        return;
    }
    AQServiceQueueOperation(service,YES,original,account);
}
@end
