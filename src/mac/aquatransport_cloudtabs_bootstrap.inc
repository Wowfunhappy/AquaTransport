/* Per-user features use the same coordinator, invoked in Safari's existing
 * GUI bootstrap session. The root boot job remains the only global entry. */
#include "cloudtabs/state.h"
#ifndef AQ_CLOUDTABS_DIRECTORY
#define AQ_CLOUDTABS_DIRECTORY @"/usr/share/aquatransport/cloudtabs"
#endif

static BOOL privateCloudTabsFile(NSString *path,uid_t uid) {
    struct stat st;
    return !lstat(path.fileSystemRepresentation,&st) && S_ISREG(st.st_mode) &&
        st.st_uid==uid && !(st.st_mode&077) && st.st_size>0 && st.st_size<=4*1024*1024;
}
static NSString *cloudTabsAccount(void) {
    CFTypeRef raw=CFPreferencesCopyAppValue(CFSTR("Accounts"),CFSTR("MobileMeAccounts"));
    if(!raw) return nil;
    NSString *result=nil;
    @try {
        if(CFGetTypeID(raw)!=CFArrayGetTypeID()) return nil;
        for(id account in (NSArray *)raw) {
            if(![account isKindOfClass:[NSDictionary class]]) continue;
            id logged=[account objectForKey:@"LoggedIn"],services=[account objectForKey:@"Services"];
            if(![logged isKindOfClass:[NSNumber class]] || ![logged boolValue] || ![services isKindOfClass:[NSArray class]]) continue;
            BOOL enabled=NO;
            for(id service in services) {
                if(![service isKindOfClass:[NSDictionary class]]) continue;
                id value=[service objectForKey:@"Enabled"];
                if([[service objectForKey:@"Name"] isEqual:@"BOOKMARKS"] && [value isKindOfClass:[NSNumber class]] && [value boolValue]) enabled=YES;
            }
            id dsid=[account objectForKey:@"AccountDSID"];
            if(!enabled || (![dsid isKindOfClass:[NSString class]] && ![dsid isKindOfClass:[NSNumber class]])) continue;
            if(result) return nil;
            result=[NSString stringWithFormat:@"%@",dsid];
        }
    } @finally {CFRelease(raw);}
    return result;
}
static BOOL cloudTabsConfigured(uid_t uid) {
    NSString *state=AQCloudTabsStateDirectory();
    struct stat st;
    if(lstat(state.fileSystemRepresentation,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=uid || (st.st_mode&077)) return NO;
    NSString *session=[state stringByAppendingPathComponent:@"session.plist"];
    if(!privateCloudTabsFile(session,uid) || !privateCloudTabsFile([state stringByAppendingPathComponent:@"safari-service-keys.plist"],uid)) return NO;
    NSString *account=cloudTabsAccount();
    if(!account.length) return NO;
    NSDictionary *saved=[NSDictionary dictionaryWithContentsOfFile:session];
    return [saved isKindOfClass:[NSDictionary class]] && [[saved objectForKey:@"dsid"] isEqual:account];
}
static BOOL startCloudTabs(void) {
    char *arguments[]={"launchctl","start","org.aquatransport.cloudtabs",NULL};
    char *environment[]={"PATH=/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL=C",NULL};
    pid_t child=0;int status=0;pid_t waited=-1;
    int error=posix_spawn(&child,"/bin/launchctl",NULL,NULL,arguments,environment);
    if(!error) do {waited=waitpid(child,&status,0);} while(waited<0 && errno==EINTR);
    return !error && waited==child && WIFEXITED(status) && !WEXITSTATUS(status);
}
static BOOL loadUserFeatures(void) {
    struct utsname os;uid_t uid=getuid();
    if(uid<500 || geteuid()!=uid || uname(&os) || atoi(os.release)!=13 || tf_flag("disable-safari-cloudtabs")) return YES;
    NSString *job=[AQ_CLOUDTABS_DIRECTORY stringByAppendingPathComponent:@"org.aquatransport.cloudtabs.plist"];
    if(!trusted(job) || !trusted([AQ_CLOUDTABS_DIRECTORY stringByAppendingPathComponent:@"aquatransport-cloudtabs"]) ||
       !trusted([AQ_CLOUDTABS_DIRECTORY stringByAppendingPathComponent:@"sync.py"]) || !cloudTabsConfigured(uid)) return YES;
    if(!loadJob(job.fileSystemRepresentation,"org.aquatransport.cloudtabs")) return NO;
    // RunAtLoad starts newly registered jobs. Starting an already registered
    // job also handles setup finishing after an earlier clean, inactive exit.
    return startCloudTabs();
}

static int cloudTabsServiceAction(BOOL enable,const char *account) {
    struct utsname os;uid_t uid=getuid();
    if(uid<500 || geteuid()!=uid || uname(&os) || atoi(os.release)!=13 || tf_flag("disable-safari-cloudtabs")) return 1;
    NSString *worker=[AQ_CLOUDTABS_DIRECTORY stringByAppendingPathComponent:@"aquatransport-cloudtabs"];
    NSString *job=[AQ_CLOUDTABS_DIRECTORY stringByAppendingPathComponent:@"org.aquatransport.cloudtabs.plist"];
    if(!trusted(worker) || !trusted(job) || !trusted([AQ_CLOUDTABS_DIRECTORY stringByAppendingPathComponent:@"setup.py"]) ||
       !trusted([AQ_CLOUDTABS_DIRECTORY stringByAppendingPathComponent:@"aquatransport-cloudtabs-authorize"])) return 1;
    AQJobState state=jobState("org.aquatransport.cloudtabs");
    if(state==AQJobUnknown) return 1;
    if(state==AQJobRegistered) {
        char *arguments[]={"launchctl","unload",(char *)job.fileSystemRepresentation,NULL};
        char *environment[]={"PATH=/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL=C",NULL};
        pid_t child=0;int status=0;pid_t waited=-1;
        if(posix_spawn(&child,"/bin/launchctl",NULL,NULL,arguments,environment)) return 1;
        do {waited=waitpid(child,&status,0);} while(waited<0 && errno==EINTR);
        if(waited!=child || !WIFEXITED(status) || WEXITSTATUS(status)) return 1;
    }
    // Remain in the caller's GUI session and process group. No new global job,
    // login watcher, or call into the system's iCloud authentication exchange.
    char *arguments[]={"aquatransport-cloudtabs",enable?"--prepare":"--disable",enable?(char *)account:NULL,NULL};
    execv(worker.fileSystemRepresentation,arguments);
    return 1;
}
