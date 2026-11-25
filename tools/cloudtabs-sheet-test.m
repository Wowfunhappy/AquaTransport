#import <AppKit/AppKit.h>
#include <assert.h>
int tf_flag(const char *name) {(void)name;return 0;}
#include "../src/mac/cloudtabs/AQSafariTabs.m"
int main(void) { @autoreleasepool {
    [NSApplication sharedApplication];[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    NSWindow *parent=[[[NSWindow alloc] initWithContentRect:NSMakeRect(0,0,600,400) styleMask:NSTitledWindowMask backing:NSBackingStoreBuffered defer:NO] autorelease];
    for(NSNumber *hidden in @[@YES,@NO]) {
        AQSafariServiceOperation *op=[[[AQSafariServiceOperation alloc] init] autorelease];
        op->window=[parent retain];op->answer=dispatch_semaphore_create(0);
        op->promptRequest=[@{@"title":@"Device Passcode",@"message":@"Enter the passcode for Fixture. Your passcode will not be saved.",@"input":@YES,@"hidden":hidden} retain];
        AQPromptPresent(op);
        assert(op->alert && [(NSWindow *)op->alert.window sheetParent]==parent);
        assert([op->alert.accessoryView isKindOfClass:[NSSecureTextField class]]==hidden.boolValue);
        [(NSTextField *)op->alert.accessoryView setStringValue:@"135790"];
        [parent endSheet:op->alert.window returnCode:NSAlertFirstButtonReturn];
        NSDate *limit=[NSDate dateWithTimeIntervalSinceNow:3];
        while(!op->promptResponse && limit.timeIntervalSinceNow>0)
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
        assert([[op->promptResponse objectForKey:@"accepted"] boolValue]);
        assert([[op->promptResponse objectForKey:@"value"] isEqual:@"135790"]);
        assert(!op->alert);
    }
    puts("PASS: real AppKit window-attached sheets, secure/plain fields and sheet completion");
}return 0;}
