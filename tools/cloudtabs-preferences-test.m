#import <Foundation/Foundation.h>
#include <spawn.h>
#include <dispatch/dispatch.h>
#include <sys/wait.h>
#include <signal.h>
#include <assert.h>
static NSString *TestHome;
static NSString *fixtureHome(void) {return TestHome;}
static dispatch_semaphore_t started,finish;
static int prepareCount,disableCount,helperStatus,killCount;
static BOOL featureDisabled;
int tf_flag(const char *name) {(void)name;return featureDisabled;}
static int fixtureSpawn(pid_t *pid,const char *path,const posix_spawn_file_actions_t *actions,const posix_spawnattr_t *attr,char *const args[],char *const env[]) {
    (void)actions;(void)attr;(void)env;
    assert(!strcmp(path,"/usr/share/aquatransport/aquatransport-bootstrap"));
    if(!strcmp(args[1],"--safari-prepare")) {
        assert(!strcmp(args[2],"fixture-account"));prepareCount++;*pid=41;
        dispatch_semaphore_signal(started);
    } else if(!strcmp(args[1],"--safari-disable")) {disableCount++;*pid=42;}
    else {assert(!strcmp(args[1],"--user-features"));*pid=43;}
    return 0;
}
static pid_t fixtureWait(pid_t pid,int *status,int options) {
    (void)options;
    if(pid==41) {assert(!dispatch_semaphore_wait(finish,dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC)));*status=helperStatus<<8;}
    else *status=0;
    return pid;
}
static int fixtureKill(pid_t pid,int signal) {
    assert(pid==-41 && signal==SIGTERM);killCount++;helperStatus=3;dispatch_semaphore_signal(finish);return 0;
}
#define NSHomeDirectory fixtureHome
#define posix_spawn fixtureSpawn
#define waitpid fixtureWait
#define kill fixtureKill
#include "../src/mac/cloudtabs/AQSafariTabs.m"
#undef NSHomeDirectory
#undef posix_spawn
#undef waitpid
#undef kill

static void preferences(BOOL enabled,NSString *account) {
    NSDictionary *record=@{@"LoggedIn":@YES,@"AccountDSID":account,@"Services":@[@{@"Name":@"BOOKMARKS",@"Enabled":@(enabled)}]};
    assert([@{@"Accounts":@[record]} writeToFile:[TestHome stringByAppendingPathComponent:@"Library/Preferences/MobileMeAccounts.plist"] atomically:YES]);
}
@interface FixtureService : NSObject {
@public BOOL enabled;unsigned updates,commits;
}
- (BOOL)isEnabled;
- (void)reconcileEnableStatus;
- (void)_updateUI;
@end
@implementation FixtureService
- (BOOL)isEnabled {return enabled;}
- (void)reconcileEnableStatus {updates++;}
- (void)_updateUI {updates++;}
@end
static void nativeSet(id value,SEL selector,BOOL enabled) {
    assert(selector==sel_registerName("_setEnabled:"));
    FixtureService *service=value;service->enabled=enabled;service->commits++;
    preferences(enabled,@"fixture-account");
}
static void drain(void) {
    NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:5];
    while(AQServiceOperations.count || AQBootstrapPending) {
        assert(deadline.timeIntervalSinceNow>0);
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    }
}
static void begin(FixtureService *service) {
    [AQSafariPreferencesAdapter setService:service enabled:YES native:nativeSet];
    assert(!dispatch_semaphore_wait(started,dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC)));
    assert(!service->enabled); // Never commit before authorization completes.
}
int main(void) { @autoreleasepool {
    char temporary[]="/private/tmp/aquatransport-preferences.XXXXXX";assert(mkdtemp(temporary));TestHome=[NSString stringWithUTF8String:temporary];
    assert([[NSFileManager defaultManager] createDirectoryAtPath:[TestHome stringByAppendingPathComponent:@"Library/Preferences"] withIntermediateDirectories:YES attributes:nil error:NULL]);
    started=dispatch_semaphore_create(0);finish=dispatch_semaphore_create(0);
    FixtureService *service=[[[FixtureService alloc] init] autorelease];
    preferences(NO,@"fixture-account");
    assert(!prepareCount); // Observation alone does not initialize existing sessions.
    begin(service);helperStatus=3;dispatch_semaphore_signal(finish);drain();
    assert(!service->enabled && disableCount==1 && service->updates==2);
    begin(service);helperStatus=1;dispatch_semaphore_signal(finish);drain();
    assert(!service->enabled && disableCount==2);
    begin(service);helperStatus=0;dispatch_semaphore_signal(finish);drain();
    assert(service->enabled && prepareCount==3);
    [AQSafariPreferencesAdapter setService:service enabled:YES native:nativeSet];drain();
    assert(prepareCount==3); // No setup because an already-enabled state was seen.
    [AQSafariPreferencesAdapter setService:service enabled:NO native:nativeSet];drain();
    assert(!service->enabled && disableCount==3);
    begin(service);assert(prepareCount==4);
    [AQSafariPreferencesAdapter setService:service enabled:NO native:nativeSet];drain();
    assert(!service->enabled && killCount==1 && disableCount==4);
    begin(service);preferences(NO,@"changed-account");helperStatus=0;dispatch_semaphore_signal(finish);drain();
    assert(!service->enabled && disableCount==5); // Late completion cannot enable a different account.
    featureDisabled=YES;
    [AQSafariPreferencesAdapter setService:service enabled:YES native:nativeSet];drain();
    assert(service->enabled && prepareCount==5);
    assert([[NSFileManager defaultManager] removeItemAtPath:TestHome error:NULL]);
    puts("PASS: Safari enable commits only after success; cancellation, failure, account changes and disable/re-enable stay isolated");
}return 0;}
