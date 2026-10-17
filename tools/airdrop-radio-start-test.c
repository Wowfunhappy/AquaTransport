/* Exercise OWL's real startup error path without opening a network device. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include "../deps/owl/daemon/io.h"
#include "../deps/owl/daemon/netutils.h"
#include "../deps/owl/src/log.h"
static int capture_attempts,address_reads,monitor_error,capture_closes,system_errors;
static int fail_activation;
// Capture the production error logger's system sink without writing system.log.
void vsyslog(int level,const char *format,va_list args) { (void)format; (void)args; assert(level<=LOG_ERR); system_errors++; }
unsigned int if_nametoindex(const char *name) { assert(!strcmp(name,"test-wifi")); return 7; }
pcap_t *pcap_open_offline(const char *path,char *error) { (void)path; strcpy(error,"not a capture file"); return NULL; }
pcap_t *pcap_create(const char *device,char *error) {
    assert(!strcmp(device,"test-wifi")); capture_attempts++;
    strcpy(error,"radio not ready after wake"); return fail_activation ? (pcap_t *)(uintptr_t)1 : NULL;
}
int pcap_set_snaplen(pcap_t *handle,int value) { (void)handle; (void)value; return 0; }
int pcap_set_promisc(pcap_t *handle,int value) { (void)handle; (void)value; return 0; }
int pcap_set_rfmon(pcap_t *handle,int value) { (void)handle; (void)value; return 0; }
int pcap_set_timeout(pcap_t *handle,int value) { (void)handle; (void)value; return 0; }
int pcap_activate(pcap_t *handle) { assert(handle==(pcap_t *)(uintptr_t)1); return PCAP_ERROR; }
char *pcap_geterr(pcap_t *handle) { (void)handle; return "monitor mode not ready after wake"; }
void pcap_close(pcap_t *handle) { assert(handle==(pcap_t *)(uintptr_t)1); capture_closes++; }
int link_down(int index) { assert(index==7); return 0; }
int link_up(int index) { assert(index==7); return 0; }
int set_monitor_mode(int index) { assert(index==7); return monitor_error; }
int link_ether_addr_get(const char *name,struct ether_addr *address) {
    (void)name; memset(address,0,sizeof(*address)); address_reads++; return 0;
}
void rfc4291_addr(const struct ether_addr *address,struct in6_addr *result) { (void)address; (void)result; assert(0); }
int main(void) {
    struct io_state state; memset(&state,0,sizeof(state)); struct ether_addr bssid={{0}};
    log_set_level(LOG_ERR); log_set_quiet(1);
    monitor_error=-EIO;
    assert(io_state_init(&state,"test-wifi","",&bssid)<0 && !capture_attempts);
    monitor_error=0;
    int error=io_state_init(&state,"test-wifi","",&bssid);
    if(error>=0) {
        fprintf(stderr,"FAIL: OWL reported successful startup after capture failed (fd=%d)\n",state.wlan_fd);
        return 1;
    }
    assert(capture_attempts==1 && !address_reads && state.wlan_fd<0 && !state.wlan_handle);
    fail_activation=1;
    assert(io_state_init(&state,"test-wifi","",&bssid)<0);
    assert(capture_attempts==2 && capture_closes==1 && !address_reads && !state.wlan_handle);
    assert(system_errors==5);
    puts("PASS: failed monitor/capture creation/activation is propagated before TAP or AWDL; errors survive redirected stderr");
    return 0;
}
