#import <Foundation/Foundation.h>
#include <launch.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

static NSString *TestBase,*TestState;
static uid_t testUID=501,testEUID=501;
static int testDarwin=13,queries,loads,starts,unloads,execs,queryError=ESRCH,spawnError;
static BOOL lastUnload;
static NSString *execAction,*execAccount;
static BOOL disabled,registered,noReply,unsafeCode,unsafeState,wrongOwner,enabled=YES;
static int fakeUname(struct utsname *os) {memset(os,0,sizeof(*os));snprintf(os->release,sizeof(os->release),"%d.0.0",testDarwin);return 0;}
static uid_t fakeUID(void) {return testUID;}
static uid_t fakeEUID(void) {return testEUID;}
int tf_flag(const char *name) {(void)name;return disabled;}
static int fakeStat(const char *path,struct stat *st) {
    if(lstat(path,st)) return -1;
    if(TestState && !strncmp(path,TestState.fileSystemRepresentation,strlen(TestState.fileSystemRepresentation))) {
        st->st_uid=wrongOwner?502:501;
        if(unsafeState) st->st_mode|=0044;
    } else {st->st_uid=0;st->st_mode&=~022;if(unsafeCode) st->st_mode|=0020;}
    return 0;
}
static CFPropertyListRef fakePreferences(CFStringRef key,CFStringRef application) {
    assert(CFEqual(key,CFSTR("Accounts")) && CFEqual(application,CFSTR("MobileMeAccounts")));
    return CFRetain((CFTypeRef)@[@{@"LoggedIn":@YES,@"AccountDSID":@"fixture",@"Services":@[@{@"Name":@"BOOKMARKS",@"Enabled":@(enabled)}]}]);
}
static launch_data_t fakeLaunch(launch_data_t request) {
    assert(!strcmp(launch_data_get_string(launch_data_dict_lookup(request,LAUNCH_KEY_GETJOB)),"org.aquatransport.cloudtabs"));
    queries++;if(noReply)return NULL;
    return launch_data_alloc(registered?LAUNCH_DATA_DICTIONARY:LAUNCH_DATA_ERRNO);
}
static int fakeErrno(launch_data_t response) {(void)response;return queryError;}
static int fakeSpawn(pid_t *pid,const char *path,const posix_spawn_file_actions_t *actions,const posix_spawnattr_t *attr,char *const args[],char *const env[]) {
    (void)actions;(void)attr;(void)env;assert(!strcmp(path,"/bin/launchctl"));
    lastUnload=!strcmp(args[1],"unload");
    if(!strcmp(args[1],"load")) {assert(!strcmp(args[2],[[TestBase stringByAppendingPathComponent:@"org.aquatransport.cloudtabs.plist"] fileSystemRepresentation]));loads++;}
    else if(lastUnload) {assert(!strcmp(args[2],[[TestBase stringByAppendingPathComponent:@"org.aquatransport.cloudtabs.plist"] fileSystemRepresentation]));unloads++;}
    else {assert(!strcmp(args[1],"start") && !strcmp(args[2],"org.aquatransport.cloudtabs"));starts++;}
    *pid=123;return spawnError;
}
static pid_t fakeWait(pid_t pid,int *status,int flags) {(void)flags;*status=0;registered=!lastUnload;return pid;}
static int fakeExec(const char *path,char *const args[]) {
    assert(!strcmp(path,[[TestBase stringByAppendingPathComponent:@"aquatransport-cloudtabs"] fileSystemRepresentation]));
    execs++;execAction=[NSString stringWithUTF8String:args[1]];execAccount=args[2]?[NSString stringWithUTF8String:args[2]]:nil;
    errno=ENOEXEC;return -1;
}
#define AQ_CLOUDTABS_DIRECTORY TestBase
#define AQ_CLOUDTABS_STATE_DIRECTORY TestState
#define uname fakeUname
#define getuid fakeUID
#define geteuid fakeEUID
#define lstat fakeStat
#define CFPreferencesCopyAppValue fakePreferences
#define launch_msg fakeLaunch
#define launch_data_get_errno fakeErrno
#define posix_spawn fakeSpawn
#define waitpid fakeWait
#define execv fakeExec
#define main bootstrap_main
#include "../src/mac/aquatransport_bootstrap.m"
#undef main
#undef lstat

static void put(NSString *path,NSData *data,mode_t mode) {assert([data writeToFile:path atomically:YES]);assert(!chmod(path.fileSystemRepresentation,mode));}
static void credentials(NSString *account) {
    NSDictionary *data=@{@"dsid":account};
    put([TestState stringByAppendingPathComponent:@"session.plist"],
        [NSPropertyListSerialization dataWithPropertyList:data format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL],0600);
}
int main(void) { @autoreleasepool {
    char directory[]="/private/tmp/aquatransport-user-bootstrap.XXXXXX";assert(mkdtemp(directory));TestBase=[NSString stringWithUTF8String:directory];
    NSFileManager *files=[NSFileManager defaultManager];NSString *state=[TestBase stringByAppendingPathComponent:@"home/Library/Application Support/AquaTransport/CloudTabs"];TestState=state;
    assert([files createDirectoryAtPath:state withIntermediateDirectories:YES attributes:nil error:NULL]);assert(!chmod(state.fileSystemRepresentation,0700));
    for(NSString *name in @[@"org.aquatransport.cloudtabs.plist",@"aquatransport-cloudtabs",@"sync.py",@"setup.py",@"aquatransport-cloudtabs-authorize"])
        put([TestBase stringByAppendingPathComponent:name],[@"fixture" dataUsingEncoding:NSUTF8StringEncoding],0644);
    put([state stringByAppendingPathComponent:@"safari-service-keys.plist"],[@"synthetic" dataUsingEncoding:NSUTF8StringEncoding],0600);
    // No credentials: no job query or process launch.
    assert(loadUserFeatures() && !queries && !loads && !starts);
    credentials(@"fixture");
    testUID=testEUID=0;assert(loadUserFeatures() && !queries);
    testUID=501;testEUID=0;assert(loadUserFeatures() && !queries);testEUID=501;
    testDarwin=12;assert(loadUserFeatures() && !queries);testDarwin=13;
    disabled=YES;assert(loadUserFeatures() && !queries);disabled=NO;
    unsafeCode=YES;assert(loadUserFeatures() && !queries);unsafeCode=NO;
    unsafeState=YES;assert(loadUserFeatures() && !queries);unsafeState=NO;
    wrongOwner=YES;assert(loadUserFeatures() && !queries);wrongOwner=NO;
    enabled=NO;assert(loadUserFeatures() && !queries);enabled=YES;
    credentials(@"other-account");assert(loadUserFeatures() && !queries);credentials(@"fixture");
    assert(loadUserFeatures() && registered && loads==1 && starts==1);
    assert(loadUserFeatures() && loads==1 && starts==2); // registered jobs aren't loaded twice
    registered=NO;queryError=EACCES;assert(!loadUserFeatures() && loads==1 && starts==2);
    noReply=YES;assert(!loadUserFeatures() && loads==1);noReply=NO;queryError=ESRCH;
    spawnError=EAGAIN;assert(!loadUserFeatures() && loads==2 && starts==2);spawnError=0;
    assert(loadUserFeatures() && loads==3 && starts==3);
    disabled=YES;assert(cloudTabsServiceAction(YES,"fixture")==1 && !execs && !unloads);disabled=NO;
    unsafeCode=YES;assert(cloudTabsServiceAction(YES,"fixture")==1 && !execs && !unloads);unsafeCode=NO;
    assert(cloudTabsServiceAction(NO,NULL)==1 && execs==1 && unloads==1 && !registered);
    assert([execAction isEqual:@"--disable"] && !execAccount);
    assert(cloudTabsServiceAction(YES,"fixture")==1 && execs==2 && unloads==1);
    assert([execAction isEqual:@"--prepare"] && [execAccount isEqual:@"fixture"]);
    registered=YES;spawnError=EAGAIN;
    assert(cloudTabsServiceAction(YES,"fixture")==1 && execs==2 && unloads==2);
    spawnError=0;registered=NO;noReply=YES;
    assert(cloudTabsServiceAction(YES,"fixture")==1 && execs==2);noReply=NO;
    assert([files removeItemAtPath:TestBase error:NULL]);
    puts("PASS: coordinator user-session loading, account/permission gates, conditional registration, duplicate-load avoidance and failures");
} return 0; }
