#import <Foundation/Foundation.h>
#include <spawn.h>
#include <assert.h>
static NSString *TestHome;
static NSString *fixtureHome(void){return TestHome;}
static CFPropertyListRef fixturePreference(CFStringRef key,CFStringRef app,CFStringRef user,CFStringRef host) {
    (void)user;(void)host;assert(CFEqual(key,CFSTR("SyncedTabsDeviceUUID")) && CFEqual(app,CFSTR("com.apple.Safari")));
    return CFRetain(CFSTR("11111111-2222-4333-8444-555555555555"));
}
static int fixtureSpawn(pid_t *pid,const char *path,const posix_spawn_file_actions_t *actions,const posix_spawnattr_t *attrs,char *const args[],char *const env[]){(void)pid;(void)path;(void)actions;(void)attrs;(void)args;(void)env;return EACCES;}
static uint32_t fixtureNotify(const char *name){(void)name;return 0;}
int tf_flag(const char *name){(void)name;return 0;}
#define NSHomeDirectory fixtureHome
#define CFPreferencesCopyValue fixturePreference
#define posix_spawn fixtureSpawn
#define notify_post fixtureNotify
#include "../src/mac/cloudtabs/AQSafariTabs.m"
#undef NSHomeDirectory
int main(void){@autoreleasepool {
    char temporary[]="/private/tmp/aquatransport-snapshot.XXXXXX";assert(mkdtemp(temporary));TestHome=[NSString stringWithUTF8String:temporary];
    NSFileManager *files=[NSFileManager defaultManager];
    assert([files createDirectoryAtPath:[TestHome stringByAppendingPathComponent:@"Library/Preferences"] withIntermediateDirectories:YES attributes:nil error:NULL]);
    NSString *directory=AQCloudTabsStateDirectory();assert([files createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0700} error:NULL]);
    assert(([@{@"Accounts":@[@{@"LoggedIn":@YES,@"AccountDSID":@"fixture",@"Services":@[@{@"Name":@"BOOKMARKS",@"Enabled":@YES}]}]} writeToFile:[TestHome stringByAppendingPathComponent:@"Library/Preferences/MobileMeAccounts.plist"] atomically:YES]));
    AQEventsStarted=YES;
    NSString *path=[directory stringByAppendingPathComponent:@"local-tabs.plist"],*own=@"11111111-2222-4333-8444-555555555555";
    NSDictionary *dictionary=@{@"DeviceName":@"Fixture Mac",@"LastModified":[NSDate date],@"Tabs":@[@{@"Title":@"Fixture",@"URL":@"https://example.invalid/"},@{@"Title":@"Local",@"URL":@"file:///private/not-exported"}]};
    [AQSafariTabsAdapter savedDictionary:dictionary forKey:@"foreign-device"];assert(![files fileExistsAtPath:path]);
    [AQSafariTabsAdapter savedDictionary:dictionary forKey:own];
    NSDictionary *saved=[NSDictionary dictionaryWithContentsOfFile:path];assert([[saved objectForKey:@"Tabs"] count]==1);assert([[saved objectForKey:@"Account"] isEqual:@"fixture"]);
    struct stat info;assert(!lstat(path.fileSystemRepresentation,&info) && (info.st_mode&0777)==0600);
    NSData *before=[NSData dataWithContentsOfFile:path];assert(!chmod(directory.fileSystemRepresentation,0755));
    [AQSafariTabsAdapter savedDictionary:@{@"DeviceName":@"Changed",@"LastModified":[NSDate date],@"Tabs":@[]} forKey:own];
    assert([before isEqual:[NSData dataWithContentsOfFile:path]]);assert(!chmod(directory.fileSystemRepresentation,0700));
    while(AQBootstrapPending)[[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    assert([files removeItemAtPath:TestHome error:NULL]);
    puts("PASS: native snapshot identity/account scope, URL filtering, private permissions and no foreign-device export");
}return 0;}
