/* Simulated IOKit events only: never register with the real power manager. */
#import "../src/mac/airdrop/AQHelperSupport.h"
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <assert.h>
static CFRunLoopSourceRef testSource;
static IOServiceInterestCallback callback;
static natural_t queuedMessage;
static BOOL session,registrationFails,sourceFails;
static int stops,acknowledgements,closed,deregistered,destroyed;
static void radioStop(void) { session=NO; stops++; }
static void perform(void *context) {
    (void)context;
    natural_t message=queuedMessage; queuedMessage=0;
    callback(NULL,0,message,(void *)1234);
}
static io_connect_t registerPower(void *context,IONotificationPortRef *port,IOServiceInterestCallback handler,io_object_t *notifier) {
    (void)context;
    callback=handler;
    CFRunLoopSourceContext sourceContext; memset(&sourceContext,0,sizeof(sourceContext)); sourceContext.perform=perform;
    testSource=CFRunLoopSourceCreate(NULL,0,&sourceContext);
    *port=(IONotificationPortRef)(uintptr_t)1;
    *notifier=registrationFails ? 0 : 2;
    return registrationFails ? 0 : 3;
}
static CFRunLoopSourceRef sourceForPort(IONotificationPortRef port) {
    assert(port==(IONotificationPortRef)(uintptr_t)1);
    return sourceFails ? NULL : testSource;
}
static IOReturn allowPower(io_connect_t connection,long token) {
    assert(connection==3 && token==1234);
    if(acknowledgements) assert(!session); // Teardown precedes the sleep acknowledgement.
    acknowledgements++; return kIOReturnSuccess;
}
static IOReturn deregisterPower(io_object_t *notifier) {
    assert(*notifier==2); deregistered++; return kIOReturnSuccess;
}
static IOReturn closePower(io_connect_t connection) {
    assert(connection==3); closed++; return kIOReturnSuccess;
}
static void destroyPort(IONotificationPortRef port) {
    assert(port==(IONotificationPortRef)(uintptr_t)1);
    CFRelease(testSource); testSource=NULL; destroyed++;
}
#define IORegisterForSystemPower registerPower
#define IONotificationPortGetRunLoopSource sourceForPort
#define IOAllowPowerChange allowPower
#define IODeregisterForSystemPower deregisterPower
#define IOServiceClose closePower
#define IONotificationPortDestroy destroyPort
#include "../src/mac/airdrop/AQHelperPower.inc"
static void enqueue(natural_t message) {
    assert(!queuedMessage); queuedMessage=message;
    CFRunLoopSourceSignal(testSource);
}
static BOOL radioAllowed(void) {
    @try { requireRadioAwake(); return YES; }
    @catch(NSException *exception) { return NO; }
}
int main(void) { @autoreleasepool {
    registrationFails=YES; assert(!startPowerMonitor());
    assert(!powerConnection && !powerPort && !powerNotifier && destroyed==1 && !closed);
    registrationFails=NO; sourceFails=YES; assert(!startPowerMonitor());
    assert(!powerConnection && !powerPort && !powerNotifier && destroyed==2 && closed==1 && deregistered==1);
    sourceFails=NO; assert(startPowerMonitor());
    assert(radioAllowed()); session=YES;
    // An idle-sleep query (and its cancellation) must leave a live session alone.
    enqueue(kIOMessageCanSystemSleep); assert(radioAllowed());
    assert(session && !stops && acknowledgements==1);
    enqueue(kIOMessageSystemWillNotSleep); assert(radioAllowed());
    assert(session && !stops && acknowledgements==1);
    // Servicing a request also drains a queued sleep event before allowing it.
    enqueue(kIOMessageSystemWillSleep); assert(!radioAllowed());
    assert(!session && stops==1 && acknowledgements==2);
    enqueue(kIOMessageSystemWillPowerOn); assert(!radioAllowed());
    assert(!session && stops==1 && acknowledgements==2);
    enqueue(kIOMessageSystemHasPoweredOn); assert(radioAllowed());
    assert(!session && stops==2 && acknowledgements==2);
    // Wake alone also discards an old process; it never starts a new session.
    session=YES;
    enqueue(kIOMessageSystemHasPoweredOn); drainPowerEvents();
    assert(!session && stops==3 && radioAllowed());
    // Repeated sleep/wake cycles remain usable.
    enqueue(kIOMessageSystemWillSleep); drainPowerEvents();
    assert(powerSleeping && acknowledgements==3);
    enqueue(kIOMessageSystemHasPoweredOn); drainPowerEvents();
    assert(!powerSleeping && radioAllowed());
    stopPowerMonitor(); stopPowerMonitor();
    assert(!powerConnection && !powerPort && !powerNotifier);
    assert(closed==2 && deregistered==2 && destroyed==3);
    puts("PASS: simulated sleep/wake, idle-sleep cancellation, queued events, early wake gating, missed sleep, repeated cycles and monitor cleanup");
} return 0; }
