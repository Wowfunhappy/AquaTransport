#ifdef WEAK_IMPORT
#define IMPORT __attribute__((weak_import))
#else
#define IMPORT
#endif
extern int AQNamespaceLazy(void) IMPORT;
extern int AQNamespaceNonlazy(void) IMPORT;
extern int SSLRead(void);
extern int CFURLRequestCreateMutableCopy(void);
int probe_lazy(void) { return AQNamespaceLazy(); }
// Returning the function's address produces a non-lazy symbol pointer, whereas
// the other entry above uses a lazy call stub. A saved pointer in ordinary __DATA
// would not exercise fishhook's non-lazy section handling.
void *probe_address(void) { return (void *)&AQNamespaceNonlazy; }
int probe_ssl(void) { return SSLRead(); }
int probe_cfnetwork(void) { return CFURLRequestCreateMutableCopy(); }
