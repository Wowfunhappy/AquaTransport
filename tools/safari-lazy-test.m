#import <Foundation/Foundation.h>
#import <objc/message.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <assert.h>
int main(int argc,char **argv) { @autoreleasepool {
    assert(argc==2);assert(!NSClassFromString(@"AQSafariTabsAdapter"));
    assert(dlopen(argv[1],RTLD_NOW|RTLD_LOCAL));
    dispatch_async(dispatch_get_main_queue(),^{ @autoreleasepool {
        id kvs=[[NSClassFromString(@"CloudTabKeyValueStore") alloc] init];
        ((void(*)(id,SEL,id,id))objc_msgSend)(kvs,sel_registerName("setDictionary:forKey:"),@{},@"synthetic-foreign-device");
        assert(NSClassFromString(@"AQSafariTabsAdapter"));[kvs release];
        Class store=NSClassFromString(@"CloudTabStore");id object=[[store alloc] init];
        id native=((id(*)(id,SEL))objc_msgSend)(object,sel_registerName("syncedCloudTabDevices"));
        assert([native isEqual:@[@"native fixture"]]);
        assert(NSClassFromString(@"AQSafariTabsAdapter"));
        [object release];puts("PASS: Safari framework late load, main-queue trampoline, lazy adapter and native fallback");exit(0);
    }});
    dispatch_main();
} }
