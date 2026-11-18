#ifndef AQUATRANSPORT_AIRDROP_H
#define AQUATRANSPORT_AIRDROP_H
/* The universal engine contains only this small, process-gated loader. */
void tf_airdrop_install(void);
int tf_airdrop_active(void);
int tf_airdrop_native_peer(const char *host);
#endif
