/* The helper's select loop also services this run-loop source. Keep power
 * callbacks and radio ownership on the same thread: a heartbeat must never
 * renew the pre-sleep OWL/Bluetooth session after the hardware has reset. */
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
static io_connect_t powerConnection;
static IONotificationPortRef powerPort;
static io_object_t powerNotifier;
static BOOL powerSleeping;
static void powerChanged(void *context,io_service_t service,natural_t message,void *argument) {
    (void)context; (void)service;
    switch(message) {
        case kIOMessageCanSystemSleep:
            IOAllowPowerChange(powerConnection,(long)argument);
            break;
        case kIOMessageSystemWillSleep:
            powerSleeping=YES;
            NSLog(@"AquaTransport AirDrop: ending radio session for system sleep");
            radioStop();
            IOAllowPowerChange(powerConnection,(long)argument);
            break;
        case kIOMessageSystemWillPowerOn:
            // Drivers are still waking. Only HasPoweredOn permits a new start.
            powerSleeping=YES;
            break;
        case kIOMessageSystemHasPoweredOn:
            // Also discard any session if we missed the earlier notification.
            radioStop();
            powerSleeping=NO;
            NSLog(@"AquaTransport AirDrop: system awake; waiting for a new radio request");
            break;
    }
}
static void stopPowerMonitor(void) {
    if(powerPort) {
        CFRunLoopSourceRef source=IONotificationPortGetRunLoopSource(powerPort);
        if(source) CFRunLoopRemoveSource(CFRunLoopGetCurrent(),source,kCFRunLoopDefaultMode);
    }
    if(powerNotifier) { IODeregisterForSystemPower(&powerNotifier); powerNotifier=0; }
    if(powerConnection) { IOServiceClose(powerConnection); powerConnection=0; }
    if(powerPort) { IONotificationPortDestroy(powerPort); powerPort=NULL; }
}
static BOOL startPowerMonitor(void) {
    powerConnection=IORegisterForSystemPower(NULL,&powerPort,powerChanged,&powerNotifier);
    CFRunLoopSourceRef source=powerPort ? IONotificationPortGetRunLoopSource(powerPort) : NULL;
    if(!powerConnection || !source) { stopPowerMonitor(); return NO; }
    CFRunLoopAddSource(CFRunLoopGetCurrent(),source,kCFRunLoopDefaultMode);
    return YES;
}
static void drainPowerEvents(void) {
    while(CFRunLoopRunInMode(kCFRunLoopDefaultMode,0,true)==kCFRunLoopRunHandledSource) {}
}
static void requireRadioAwake(void) {
    drainPowerEvents();
    AQRequire(!powerSleeping,@"The system is sleeping or its radios are still waking.");
}
