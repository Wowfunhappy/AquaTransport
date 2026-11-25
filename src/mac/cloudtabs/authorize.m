/* Foreground authorization and secure-input helper for Safari tab sync.
 * Authentication state is written only to the private per-user Library directory. */
#import <Foundation/Foundation.h>
static BOOL AQIncorrectCredentials;
static void AQObserveLoginFailure(NSHTTPURLResponse *response, NSDictionary *status) {
 id code=[status objectForKey:@"ec"];
 // Prefer the approved credential-rejection wording for ambiguous sign-in
 // failures. A known device-resynchronization failure is not a bad password.
 id challenge=[status objectForKey:@"hsc"];
 BOOL resynchronization=[code isKindOfClass:[NSNumber class]] && [code integerValue]==-22421 && [challenge isKindOfClass:[NSNumber class]] && [challenge integerValue]==434;
 AQIncorrectCredentials=(response.statusCode==200 || response.statusCode==401 || response.statusCode==403) && !resynchronization;
}
#define AQ_GSA_EXCHANGE_FAILURE AQObserveLoginFailure
#define AQGSAProtocol AQCloudTabsGSAProtocol
#define AQGSAWire AQCloudTabsGSAWire
#define AQFindMyAdapter AQCloudTabsFindMyAdapter
#define AQNativeAnisette AQCloudTabsNativeAnisette
#define AQDAVProtocol AQCloudTabsDAVProtocol
#define AQMailTokenAdapter AQCloudTabsMailTokenAdapter
#include "../aquatransport_gsa.m"
#include <sys/stat.h>
#import <AppKit/AppKit.h>
#include <sys/resource.h>
#include "transport.inc"
#include "state.h"
#include "prompt_channel.h"
static BOOL panePromptRequested(void) {return getenv("AQ_CLOUDTABS_UI_FD")!=NULL;}
static NSDictionary *panePrompt(NSString *title,NSString *message,BOOL input,BOOL hidden) {
 const char *descriptor=getenv("AQ_CLOUDTABS_UI_FD");
 uid_t uid;gid_t gid;
 if(!descriptor || strcmp(descriptor,"198") || getpeereid(AQ_PROMPT_FD,&uid,&gid) || uid!=getuid()) return nil;
 int yes=1;setsockopt(AQ_PROMPT_FD,SOL_SOCKET,SO_NOSIGPIPE,&yes,sizeof yes);
 if(!AQPromptWrite(AQ_PROMPT_FD,@{@"title":title,@"message":message,@"input":@(input),@"hidden":@(hidden)})) return nil;
 return AQPromptRead(AQ_PROMPT_FD);
}
static void buttons(NSAlert *alert) {
 NSButton *ok=[alert addButtonWithTitle:@"OK"];[ok setKeyEquivalent:@"\r"];
 NSButton *cancel=[alert addButtonWithTitle:@"Cancel"];[cancel setKeyEquivalent:@"\033"];
}
static NSString *secret(NSString *title, NSString *message, BOOL hidden) {
 if(panePromptRequested()) {
  NSDictionary *reply=panePrompt(title,message,YES,hidden);
  NSString *value=[reply objectForKey:@"value"];
  return [[reply objectForKey:@"accepted"] isEqual:@YES] && [value isKindOfClass:[NSString class]] && value.length && value.length<=16384?value:nil;
 }
 NSAlert *alert=[[[NSAlert alloc] init] autorelease];
 [alert setMessageText:title]; [alert setInformativeText:message];
 buttons(alert);
 NSTextField *field=[[[(hidden ? [NSSecureTextField class] : [NSTextField class]) alloc] initWithFrame:NSMakeRect(0,0,360,24)] autorelease];
 [alert setAccessoryView:field]; [[alert window] setInitialFirstResponder:field];
 [NSApp activateIgnoringOtherApps:YES];
 if([alert runModal]!=NSAlertFirstButtonReturn) return nil;
 NSString *result=[[[field stringValue] copy] autorelease]; [field setStringValue:@""];
 return [result length] ? result : nil;
}
static BOOL failure(BOOL credentials) {
 NSString *title=credentials?@"Your Apple ID or password was incorrect.":@"Something went wrong.";
 NSString *message=credentials?@"Try signing in again.":@"You can’t use iCloud with Safari at this time.";
 if(panePromptRequested()) return [[panePrompt(title,message,NO,NO) objectForKey:@"accepted"] isEqual:@YES];
 NSAlert *alert=[[[NSAlert alloc] init] autorelease];
 [alert setMessageText:title];[alert setInformativeText:message];
 buttons(alert);[NSApp activateIgnoringOtherApps:YES];
 return [alert runModal]==NSAlertFirstButtonReturn;
}
int main(int argc,char **argv) { @autoreleasepool {
 struct rlimit noCore={0,0}; setrlimit(RLIMIT_CORE,&noCore);
 if(geteuid()==0) {fputs("Run Safari setup in your own login session, without sudo.\n",stderr);return 2;}
 if(argc==2 && !strcmp(argv[1],"--transport")) return AQTransport();
 if(!panePromptRequested()) {[NSApplication sharedApplication]; [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];}
 if(argc==2 && !strcmp(argv[1],"--failure")) return failure(NO)?0:3;
 if(argc==2 && !strcmp(argv[1],"--prompt")) {
  NSData *input=[[NSFileHandle fileHandleWithStandardInput] readDataToEndOfFile];
  if(input.length>8192) return 2;
  NSDictionary *options=aq_dict([NSJSONSerialization JSONObjectWithData:input options:0 error:NULL]);
  NSString *title=aq_string([options objectForKey:@"title"]),*message=aq_string([options objectForKey:@"message"]);
  if(!title || !message || title.length>256 || message.length>4096) return 2;
  NSString *result=secret(title,message,NO);if(!result) return 3;
  NSData *data=[result dataUsingEncoding:NSUTF8StringEncoding];
  NSFileHandle *output=[NSFileHandle fileHandleWithStandardOutput];[output writeData:data];return 0;
 }
 if((argc!=2 && argc!=3) || strcmp(argv[1],"--authorize")) {fputs("Usage: aquatransport-cloudtabs-authorize --authorize [account]\n",stderr);return 2;}
 NSString *directory=AQCloudTabsStateDirectory();
 if(![[NSFileManager defaultManager] createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0700} error:NULL]) {fputs("Could not create private Safari sync storage.\n",stderr);return 8;}
 struct stat directoryInfo;
 if(lstat(directory.fileSystemRepresentation,&directoryInfo) || !S_ISDIR(directoryInfo.st_mode) || directoryInfo.st_uid!=getuid() || (directoryInfo.st_mode&077)) {fputs("Safari sync storage has unsafe permissions.\n",stderr);return 8;}
 NSDictionary *prefs=[NSDictionary dictionaryWithContentsOfFile:[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Preferences/MobileMeAccounts.plist"]];
 NSArray *accounts=[prefs objectForKey:@"Accounts"];
 if([accounts count]!=1) { puts("Expected one configured iCloud account."); return 2; }
 NSString *user=aq_string([[accounts objectAtIndex:0] objectForKey:@"AccountID"]);
 NSString *expected=argc==3?[NSString stringWithUTF8String:argv[2]]:nil;
 if(!user || (expected && ![expected isEqual:[[[accounts objectAtIndex:0] objectForKey:@"AccountDSID"] description]])) return 2;
 NSError *error=nil; NSDictionary *session=nil;
 while(!session) {
  NSString *password=secret(@"Enter your password to use iCloud with Safari.",[NSString stringWithFormat:@"Verify the Apple ID password for %@.",user],YES);
  if(!password) { puts("Authorization cancelled."); return 3; }
  AQIncorrectCredentials=NO;
  error=nil; session=aq_login(nil,[user lowercaseString],password,&error); password=nil;
  if(!session && [error code]==401) {
   NSString *code=secret(@"Two-Factor Authentication",@"A message with a verification code has been sent to your devices. Enter the code to continue.",NO);
   if(!code) { puts("Verification cancelled."); return 3; }
   error=nil; session=aq_login(nil,[user lowercaseString],code,&error);
  }
  if(!session) {
   printf("Sign-in failed: code=%ld\n",(long)[error code]); fflush(stdout);
   if(!failure(AQIncorrectCredentials)) return 3;
  }
 }
 if(!session) return 4;
 NSString *pet=aq_string([aq_dict([aq_dict([session objectForKey:@"t"]) objectForKey:@"com.apple.gs.idms.pet"]) objectForKey:@"token"]);
 NSString *adsid=aq_string([session objectForKey:@"adsid"]),*dsid=[[session objectForKey:@"DsPrsId"] description];
 if(!pet || !adsid || !dsid) return 5;
 if(expected && ![expected isEqual:dsid]) return 5;
 NSDictionary *headers=aq_anisette(nil,&error);if(!headers) return 6;
 NSString *real=aq_client_info();NSRange boundary=[real rangeOfString:@"> <"];
 if(boundary.location==NSNotFound) return 6;
 NSString *client=[NSString stringWithFormat:@"%@ <macOS;13.6;22G120> <com.apple.AOSKit/282>",[real substringToIndex:boundary.location+1]];
 NSMutableURLRequest *req=aq_apple_request(@"https://setup.icloud.com/setup/iosbuddy/loginDelegates",headers);
 [req setHTTPMethod:@"POST"];[req setValue:aq_basic([user lowercaseString],pet) forHTTPHeaderField:@"Authorization"];
 [req setValue:adsid forHTTPHeaderField:@"X-Apple-ADSID"];[req setValue:client forHTTPHeaderField:@"X-Mme-Client-Info"];
 [req setValue:@"com.apple.iCloudHelper/282 CFNetwork/1410.0.3" forHTTPHeaderField:@"User-Agent"];
 [req setHTTPBody:aq_encode(@{@"apple-id":[user lowercaseString],@"password":pet,@"client-id":[headers objectForKey:@"X-Mme-Device-Id"],@"delegates":@{@"com.apple.mobileme":@{}}})];
 NSHTTPURLResponse *response=nil;NSData *body=aq_send(nil,req,&response,&error);NSDictionary *reply=aq_plist(body);
 NSDictionary *delegate=aq_dict([aq_dict([reply objectForKey:@"delegates"]) objectForKey:@"com.apple.mobileme"]);
 NSDictionary *service=aq_dict([delegate objectForKey:@"service-data"]),*tokens=aq_dict([service objectForKey:@"tokens"]);
 if(response.statusCode!=200 || ![[reply objectForKey:@"status"] isKindOfClass:[NSNumber class]] || [[reply objectForKey:@"status"] integerValue] ||
  ![[delegate objectForKey:@"status"] isKindOfClass:[NSNumber class]] || [[delegate objectForKey:@"status"] integerValue] || !aq_string([tokens objectForKey:@"cloudKitToken"]) || !aq_string([tokens objectForKey:@"mmeAuthToken"])) {
  fprintf(stderr,"CloudKit authorization failed (HTTP %ld).\n",(long)response.statusCode);return 7;
 }
 NSDictionary *saved=@{@"user":[user lowercaseString],@"dsid":dsid,@"adsid":adsid,@"pet":pet,@"tokens":tokens,@"config":service,@"clientInfo":client,@"created":[NSDate date]};
 NSData *data=[NSPropertyListSerialization dataWithPropertyList:saved format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
 struct stat st;
 if(!data || data.length>1024*1024 || lstat(directory.fileSystemRepresentation,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=getuid() || (st.st_mode&077)) { fputs("Private Safari sync directory is unavailable.\n",stderr);return 8; }
 NSString *temporary=[directory stringByAppendingPathComponent:[NSString stringWithFormat:@"session-%@.new",aq_request_uuid()]];
 int fd=open(temporary.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(fd<0) return 8;
 const char *p=data.bytes;size_t remaining=data.length;BOOL ok=YES;
 while(remaining) {ssize_t count=write(fd,p,remaining);if(count<0 && errno==EINTR) continue;if(count<=0) {ok=NO;break;}p+=count;remaining-=count;}
 if(fsync(fd)) ok=NO;close(fd);
 if(ok) ok=rename(temporary.fileSystemRepresentation,[[directory stringByAppendingPathComponent:@"session.plist"] fileSystemRepresentation])==0;
 if(!ok) {unlink(temporary.fileSystemRepresentation);return 8;}
 puts("Safari CloudKit authorization saved.");
} return 0; }
