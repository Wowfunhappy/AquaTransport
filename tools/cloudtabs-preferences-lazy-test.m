#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <assert.h>
int main(int argc,char **argv) { @autoreleasepool {
    assert(argc==2);assert(!NSClassFromString(@"AQSafariPreferencesAdapter"));
    assert(dlopen(argv[1],RTLD_NOW|RTLD_LOCAL));
    Class base=NSClassFromString(@"MMService"),bookmarks=NSClassFromString(@"MMBookmarksService");
    SEL selector=sel_registerName("_setEnabled:");
    IMP original=class_getMethodImplementation(base,selector);
    dispatch_async(dispatch_get_main_queue(),^{ @autoreleasepool {
        assert(class_getMethodImplementation(base,selector)==original);
        assert(class_getMethodImplementation(bookmarks,selector)!=original);
        id service=[[bookmarks alloc] init];
        // The fixture reports already enabled: exercise the real lazy adapter
        // without authorizing, disabling, or touching any user's saved state.
        ((void(*)(id,SEL,BOOL))objc_msgSend)(service,selector,YES);
        assert(NSClassFromString(@"AQSafariPreferencesAdapter"));
        [service release];puts("PASS: preferences late load, Safari-only service override, lazy adapter, no change to other iCloud services");exit(0);
    }});
    dispatch_main();
} }
