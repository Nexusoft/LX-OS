#define PROXYCAP_H_SHIELD
#ifndef PROXYCAP_H_SHIELD

#include "tunnel.h"

extern void tunnel_data(Tunnel *t, unsigned int sender, void *data, int datalen);
extern void tunnel_poll(Tunnel *t);

#endif
