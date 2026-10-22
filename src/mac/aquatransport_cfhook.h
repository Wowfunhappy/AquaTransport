// Destructor hooks for CoreFoundation classes, shaped like fishhook's rebinding.
//
// fishhook replaces a function wherever one image calls it from another, by name. Some
// functions are never called that way. CoreFoundation ends every object the same way: its last
// release calls the finalize function the object's class registered, through the class record
// handed to _CFRuntimeRegisterClass. That function is usually static in the framework that owns
// the class -- Secure Transport's is a local symbol, sslContextDestroy -- so no image imports
// it, dlsym cannot find it, and fishhook has no call site to rebind. Rebinding CFRelease would
// not do either: CoreFoundation's own releases are calls inside its own image, which no
// rebinding reaches.
//
// So the pointer replaced is the one in the class record, which CF calls through. That is the
// move method_setImplementation makes for an Objective-C method, and the shape is fishhook's,
// so a table of these reads like a table of rebindings.

#ifndef AQUATRANSPORT_CFHOOK_H
#define AQUATRANSPORT_CFHOOK_H

#include <stddef.h>

struct cf_rebinding {
    const char *type_id;      // exported function returning the class's CFTypeID
    const char *class_name;   // what the class calls itself, checked before anything is written
    void       *replacement;  // takes the object, and must call *replaced before returning
    void      **replaced;     // receives the original finalize; left NULL if nothing was hooked
    const char *const *providers; // exact providers of the type-ID function
};

// For each row, replaces its class's finalize with the replacement. A row whose type_id cannot
// be resolved is skipped: the class does not exist on this system, which is how a row is
// written for something that arrived after 10.6. A class that does not look as the row says,
// or whose record is not writable, is logged and skipped. Returns 0 when every row with a
// resolvable type_id was hooked, -1 otherwise.
//
// Needs the owning framework loaded and CoreFoundation initialised, since type_id is called.
// So unlike rebind_symbols it cannot run from a constructor or a dyld add-image callback. It
// belongs where the original entry points are resolved, at the first hook entered.
int rebind_cf_finalizers(const struct cf_rebinding rebindings[], size_t rebindings_nel);

#endif
