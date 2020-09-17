/** NexusOS: userspace network interface
 
    Users should only use the libc socket interface.
    This file exports lower-level functionality */

#ifndef NEXUS_USER_NET_H
#define NEXUS_USER_NET_H

/** Start the lwIP network stack in its own thread */
void nxnet_init(void);
void nxnet_init_raw(int lowlevel_api);

/** The IPC port on which the network stack receives packets from the kerne */
extern int nexusif_port;	

/** Initialize an skb header encapsulated in a page */
void * nxnet_init_skb(void *page, unsigned long);
void * nxnet_alloc_page(void);
void   nxnet_free_page(void *page);

void nxnet_page_setlen(void *page, unsigned short len);
unsigned short nxnet_page_getlen(void *page);

#endif /* NEXUS_USER_NET_H */

