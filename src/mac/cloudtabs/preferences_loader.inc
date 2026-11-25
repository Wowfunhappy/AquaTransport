/* Mavericks' Safari service commit, after Apple's merge confirmation.
 * Only install an override on MMBookmarksService, never on other services. */
static void (*preferences_native)(void *,void *,signed char);
static void (*preferences_native_with_window)(void *,void *,signed char,signed char,void *);
static void *(*preferences_class)(const char *);
static void *(*preferences_selector)(const char *);
static void *preferences_send;
static int preferences_queued;

static void preferences_window(void *service,void *selector,signed char enabled,signed char creating,void *window) {
    if(!tf_flag("disable-safari-cloudtabs")) {
        pthread_once(&safari_once,safari_load);
        void *adapter=preferences_class("AQSafariPreferencesAdapter");
        if(adapter) ((void (*)(void *,void *,void *,void *))preferences_send)(adapter,
            preferences_selector("rememberWindow:forService:"),window,service);
    }
    preferences_native_with_window(service,selector,enabled,creating,window);
}

static void preferences_enable(void *service,void *selector,signed char enabled) {
    if(!tf_flag("disable-safari-cloudtabs")) {
        pthread_once(&safari_once,safari_load);
        void *adapter=preferences_class("AQSafariPreferencesAdapter");
        if(adapter) {
            ((void (*)(void *,void *,void *,signed char,void *))preferences_send)(adapter,
                preferences_selector("setService:enabled:native:"),service,enabled,(void *)preferences_native);
            return;
        }
    }
    preferences_native(service,selector,enabled);
}
static void preferences_install_on_main(void *unused) {
    (void)unused;
    if(preferences_native || tf_flag("disable-safari-cloudtabs")) return;
    preferences_class=dlsym(RTLD_DEFAULT,"objc_getClass");preferences_selector=dlsym(RTLD_DEFAULT,"sel_registerName");preferences_send=dlsym(RTLD_DEFAULT,"objc_msgSend");
    void *(*method)(void *,void *)=dlsym(RTLD_DEFAULT,"class_getInstanceMethod");
    void *(*implementation)(void *)=dlsym(RTLD_DEFAULT,"method_getImplementation");
    void (*return_type)(void *,char *,size_t)=dlsym(RTLD_DEFAULT,"method_getReturnType");
    void (*argument_type)(void *,unsigned,char *,size_t)=dlsym(RTLD_DEFAULT,"method_getArgumentType");
    unsigned (*arguments)(void *)=dlsym(RTLD_DEFAULT,"method_getNumberOfArguments");
    const char *(*encoding)(void *)=dlsym(RTLD_DEFAULT,"method_getTypeEncoding");
    signed char (*add)(void *,void *,void *,const char *)=dlsym(RTLD_DEFAULT,"class_addMethod");
    void *(*replace)(void *,void *)=dlsym(RTLD_DEFAULT,"method_setImplementation");
    if(!preferences_class || !preferences_selector || !preferences_send || !method || !implementation || !return_type || !argument_type || !arguments || !encoding || !add || !replace) return;
    void *cls=preferences_class("MMBookmarksService");
    void *sel=preferences_selector("_setEnabled:");void *m=cls?method(cls,sel):NULL;
    if(!m || arguments(m)!=3) return;
    char type[8]={0};return_type(m,type,sizeof type);if(strcmp(type,"v")) return;
    argument_type(m,2,type,sizeof type);if(strcmp(type,"c") && strcmp(type,"B")) return;
    void *getter=method(cls,preferences_selector("isEnabled"));if(!getter || arguments(getter)!=2) return;
    return_type(getter,type,sizeof type);if(strcmp(type,"c") && strcmp(type,"B")) return;
    void *original=implementation(m);Dl_info owner;
    if(!dladdr(original,&owner) || !owner.dli_fname || !strstr(owner.dli_fname,"/AOSUI.framework/")) return;
    void *windowMethod=method(cls,preferences_selector("setEnabled:creating:withWindow:"));
    if(!windowMethod || arguments(windowMethod)!=5) return;
    return_type(windowMethod,type,sizeof type);if(strcmp(type,"v"))return;
    argument_type(windowMethod,4,type,sizeof type);if(strcmp(type,"@"))return;
    for(unsigned index=2;index<4;index++) {argument_type(windowMethod,index,type,sizeof type);if(strcmp(type,"c") && strcmp(type,"B"))return;}
    void *windowOriginal=implementation(windowMethod);
    if(!dladdr(windowOriginal,&owner) || !owner.dli_fname || !strstr(owner.dli_fname,"/AOSUI.framework/"))return;
    preferences_native=original;
    if(!add(cls,sel,(void *)&preferences_enable,encoding(m))) {preferences_native=NULL;return;}
    preferences_native_with_window=windowOriginal;replace(windowMethod,(void *)&preferences_window);
}
static void preferences_image(const struct mach_header *header,intptr_t slide) {
    (void)slide;Dl_info image;
    if(!dladdr(header,&image) || !image.dli_fname || !strstr(image.dli_fname,"/AOSUI.framework/")) return;
    if(__sync_bool_compare_and_swap(&preferences_queued,0,1)) dispatch_async_f(dispatch_get_main_queue(),NULL,preferences_install_on_main);
}
static void safari_preferences_install(void) {
    struct utsname os;
    const char *process=getprogname();
    if(!process || (strcmp(process,"System Preferences") && strcmp(process,"com.apple.preferences.icloud.remoteservice")) ||
       uname(&os) || atoi(os.release)!=13 || tf_flag("disable-safari-cloudtabs")) return;
    _dyld_register_func_for_add_image(preferences_image);
}
