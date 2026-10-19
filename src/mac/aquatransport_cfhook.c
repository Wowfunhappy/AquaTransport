// See aquatransport_cfhook.h for why this exists alongside fishhook.

#include "aquatransport_cfhook.h"
#include "aquatransport_config.h"
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <string.h>
#include <mach/mach.h>

// The head of CFRuntimeClass, as far as finalize: a version, the name, then init, copy and
// finalize, as CoreFoundation's open-source CFRuntime.h lays it out. That header is not in the
// SDK, so the part this needs is spelled out, and the name is checked before the layout is
// trusted.
typedef struct {
    CFIndex     version;
    const char *className;
    void      (*init)(CFTypeRef);
    CFTypeRef (*copy)(CFAllocatorRef, CFTypeRef);
    void      (*finalize)(CFTypeRef);
} CFClassHead;

// A class record is static data in its framework's __DATA, written once at load for its
// relocations and writable after. Checked rather than assumed, since a write to a read-only
// page would take the process down.
static int writable(void *p) {
    vm_address_t at = (vm_address_t)p;
    vm_size_t size; vm_region_basic_info_data_64_t info; mach_port_t obj;
    mach_msg_type_number_t n = VM_REGION_BASIC_INFO_COUNT_64;
    return vm_region_64(mach_task_self(), &at, &size, VM_REGION_BASIC_INFO_64,
                        (vm_region_info_t)&info, &n, &obj) == KERN_SUCCESS &&
           (info.protection & VM_PROT_WRITE);
}

int rebind_cf_finalizers(const struct cf_rebinding rebindings[], size_t rebindings_nel) {
    // Private, though exported. Resolved rather than linked, so a system without it leaves the
    // rows inert instead of the library failing to load.
    CFClassHead *(*class_of)(CFTypeID) =
        (CFClassHead *(*)(CFTypeID))dlsym(RTLD_DEFAULT, "_CFRuntimeGetClassWithTypeID");
    int rv = 0;
    for (size_t i = 0; i < rebindings_nel; i++) {
        const struct cf_rebinding *r = &rebindings[i];
        CFTypeID (*type_id)(void) = (CFTypeID (*)(void))dlsym(RTLD_DEFAULT, r->type_id);
        if (!type_id) {                                  // not on this system
            tf_log("%s absent on this system; its finalize row is inert", r->type_id);
            continue;
        }
        CFClassHead *cls = class_of ? class_of(type_id()) : NULL;
        if (!cls || !cls->className || strcmp(cls->className, r->class_name) || !cls->finalize) {
            tf_log("%s: class not as expected; its finalize is not hooked", r->type_id);
            rv = -1;
            continue;
        }
        if (!writable(&cls->finalize)) {
            tf_log("%s: class is read-only; its finalize is not hooked", r->type_id);
            rv = -1;
            continue;
        }
        // Like fishhook, never record our own replacement as the original.
        if (cls->finalize != (void (*)(CFTypeRef))r->replacement) {
            *r->replaced = (void *)cls->finalize;
            cls->finalize = (void (*)(CFTypeRef))r->replacement;
            tf_log("%s: %s finalize hooked", r->type_id, r->class_name);
        }
    }
    return rv;
}
