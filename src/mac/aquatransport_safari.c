/* Safari-only main-queue entry. No Foundation loading in a constructor/dyld callback. */
#include "aquatransport_config.h"
#include <dispatch/dispatch.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

static void *(*safari_native)(void *,void *);
static void (*safari_native_write)(void *,void *,void *,void *);
static void (*safari_native_remove)(void *,void *,void *);
static void (*safari_native_bookmark_save)(void *,void *);
static void (*safari_native_bookmark_reload)(void *,void *);
static void (*safari_native_bookmark_sync)(void *,void *);
static void *(*safari_class)(const char *);
static void *(*safari_selector)(const char *);
static void *safari_send;
static pthread_once_t safari_once=PTHREAD_ONCE_INIT;
static int safari_queued;

static void safari_load(void) {
    Dl_info own;char path[1024];
    if(!dladdr((void *)&safari_load,&own) || !own.dli_fname) return;
    const char *slash=strrchr(own.dli_fname,'/');
    if(!slash || snprintf(path,sizeof path,"%.*s/aquatransport_safari.dylib",(int)(slash-own.dli_fname),own.dli_fname)>=(int)sizeof path) return;
    if(!dlopen(path,RTLD_NOW|RTLD_LOCAL)) tf_log("Safari cloud tabs module could not be loaded");
}
static void *safari_devices(void *store,void *selector) {
    void *native=safari_native(store,selector);
    if(tf_flag("disable-safari-cloudtabs")) return native;
    pthread_once(&safari_once,safari_load);
    void *adapter=safari_class("AQSafariTabsAdapter");
    return adapter?((void *(*)(void *,void *,void *,void *))safari_send)(adapter,safari_selector("devicesForStore:native:"),store,native):native;
}
static void safari_saved_dictionary(void *store,void *selector,void *dictionary,void *key) {
    safari_native_write(store,selector,dictionary,key);
    if(tf_flag("disable-safari-cloudtabs"))return;
    pthread_once(&safari_once,safari_load);void *adapter=safari_class("AQSafariTabsAdapter");
    if(adapter)((void(*)(void *,void *,void *,void *))safari_send)(adapter,safari_selector("savedDictionary:forKey:"),dictionary,key);
}
static void safari_removed_dictionary(void *store,void *selector,void *key) {
    safari_native_remove(store,selector,key);
    if(tf_flag("disable-safari-cloudtabs"))return;
    pthread_once(&safari_once,safari_load);void *adapter=safari_class("AQSafariTabsAdapter");
    if(adapter)((void(*)(void *,void *,void *))safari_send)(adapter,safari_selector("removedDictionaryForKey:"),key);
}
static void safari_bookmarks_saved(void *controller,void *selector) {
    safari_native_bookmark_save(controller,selector);
    if(tf_flag("disable-safari-cloudtabs"))return;
    pthread_once(&safari_once,safari_load);void *adapter=safari_class("AQSafariBookmarksAdapter");
    if(adapter)((void(*)(void *,void *,void *))safari_send)(adapter,safari_selector("nativeDidSave:"),controller);
}
static void safari_bookmarks_reloaded(void *controller,void *selector) {
    safari_native_bookmark_reload(controller,selector);
    if(tf_flag("disable-safari-cloudtabs"))return;
    pthread_once(&safari_once,safari_load);void *adapter=safari_class("AQSafariBookmarksAdapter");
    if(adapter)((void(*)(void *,void *,void *))safari_send)(adapter,safari_selector("nativeReloaded:"),controller);
}
static void safari_bookmarks_sync(void *controller,void *selector) {
    if(!tf_flag("disable-safari-cloudtabs")) {
        pthread_once(&safari_once,safari_load);void *adapter=safari_class("AQSafariBookmarksAdapter");
        if(adapter && ((signed char(*)(void *,void *))safari_send)(adapter,safari_selector("nativeSyncRequested")))return;
    }
    safari_native_bookmark_sync(controller,selector);
}
static void safari_install_on_main(void *unused) {
    (void)unused;if(safari_native || tf_flag("disable-safari-cloudtabs")) return;
    safari_class=dlsym(RTLD_DEFAULT,"objc_getClass");safari_selector=dlsym(RTLD_DEFAULT,"sel_registerName");safari_send=dlsym(RTLD_DEFAULT,"objc_msgSend");
    void *(*method)(void *,void *)=dlsym(RTLD_DEFAULT,"class_getInstanceMethod");
    void *(*implementation)(void *)=dlsym(RTLD_DEFAULT,"method_getImplementation");
    void (*return_type)(void *,char *,size_t)=dlsym(RTLD_DEFAULT,"method_getReturnType");
    unsigned (*arguments)(void *)=dlsym(RTLD_DEFAULT,"method_getNumberOfArguments");
    void *(*replace)(void *,void *)=dlsym(RTLD_DEFAULT,"method_setImplementation");
    if(!safari_class || !safari_selector || !safari_send || !method || !implementation || !return_type || !arguments || !replace) return;
    void *cls=safari_class("CloudTabStore");void *m=cls?method(cls,safari_selector("syncedCloudTabDevices")):NULL;
    if(!m || arguments(m)!=2) return;
    char type[8]={0};return_type(m,type,sizeof type);if(strcmp(type,"@")) return;
    void *supported=method(cls,safari_selector("cloudTabsSupported"));
    if(!supported || arguments(supported)!=2) return;
    char support_type[8]={0};return_type(supported,support_type,sizeof support_type);
    if(strcmp(support_type,"c") && strcmp(support_type,"B")) return;
    void *original=implementation(m);Dl_info owner;
    if(!dladdr(original,&owner) || !owner.dli_fname || !strstr(owner.dli_fname,"/Safari.framework/")) return;
    safari_native=original;replace(m,(void *)&safari_devices);
    void *keyValue=safari_class("CloudTabKeyValueStore");
    const char *names[]={"setDictionary:forKey:","removeObjectForKey:"};
    for(unsigned index=0;keyValue && index<2;index++) {
        void *entry=method(keyValue,safari_selector(names[index]));
        if(!entry || arguments(entry)!=(index?3:4))continue;
        return_type(entry,type,sizeof type);if(strcmp(type,"v"))continue;
        void *native=implementation(entry);
        if(!dladdr(native,&owner) || !owner.dli_fname || !strstr(owner.dli_fname,"/Safari.framework/"))continue;
        if(index) {safari_native_remove=native;replace(entry,(void *)&safari_removed_dictionary);}
        else {safari_native_write=native;replace(entry,(void *)&safari_saved_dictionary);}
    }
    void *bookmarks=safari_class("BookmarksController");
    void *saved=bookmarks?method(bookmarks,safari_selector("didSavePendingChanges")):NULL;
    if(saved && arguments(saved)==2) {
        return_type(saved,type,sizeof type);void *native=implementation(saved);
        if(!strcmp(type,"v") && dladdr(native,&owner) && owner.dli_fname && strstr(owner.dli_fname,"/Safari.framework/")) {
            safari_native_bookmark_save=native;replace(saved,(void *)&safari_bookmarks_saved);
        }
    }
    void *reload=bookmarks?method(bookmarks,safari_selector("reloadBookmarksFromFileIfChanged")):NULL;
    if(reload && arguments(reload)==2) {
        return_type(reload,type,sizeof type);void *native=implementation(reload);
        if(!strcmp(type,"v") && dladdr(native,&owner) && owner.dli_fname && strstr(owner.dli_fname,"/Safari.framework/")) {safari_native_bookmark_reload=native;replace(reload,(void *)&safari_bookmarks_reloaded);}
    }
    void *(*meta_class)(const char *)=dlsym(RTLD_DEFAULT,"objc_getMetaClass");
    void *meta=meta_class?meta_class("BookmarksController"):NULL;
    void *sync=meta?method(meta,safari_selector("notifySyncClientOfBookmarkChanges")):NULL;
    if(sync && arguments(sync)==2) {
        return_type(sync,type,sizeof type);void *native=implementation(sync);
        if(!strcmp(type,"v") && dladdr(native,&owner) && owner.dli_fname && strstr(owner.dli_fname,"/Safari.framework/")) {safari_native_bookmark_sync=native;replace(sync,(void *)&safari_bookmarks_sync);}
    }
    pthread_once(&safari_once,safari_load);
    void *adapter=safari_class("AQSafariTabsAdapter");
    if(adapter)((void(*)(void *,void *))safari_send)(adapter,safari_selector("startForCurrentProcess"));
}
static void safari_image(const struct mach_header *header,intptr_t slide) {
    (void)slide;Dl_info image;
    if(!dladdr(header,&image) || !image.dli_fname || !strstr(image.dli_fname,"/Safari.framework/")) return;
    if(__sync_bool_compare_and_swap(&safari_queued,0,1)) dispatch_async_f(dispatch_get_main_queue(),NULL,safari_install_on_main);
}
#include "cloudtabs/preferences_loader.inc"
void tf_safari_install(void) {
    safari_preferences_install();
    struct utsname os;
    if(!getprogname() || strcmp(getprogname(),"Safari") || uname(&os) || atoi(os.release)!=13 || tf_flag("disable-safari-cloudtabs")) return;
    _dyld_register_func_for_add_image(safari_image);
}
