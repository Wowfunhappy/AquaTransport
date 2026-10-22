// Built twice with the same exported names and different return values.
#ifndef VALUE
#define VALUE 11
#endif
int AQNamespaceLazy(void) { return VALUE; }
int AQNamespaceNonlazy(void) { return VALUE; }
// Deliberately unrelated APIs with signatures incompatible with Apple's APIs.
int SSLRead(void) { return VALUE; }
int CFURLRequestCreateMutableCopy(void) { return VALUE; }
