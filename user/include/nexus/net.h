/** NexusOS: userspace network interface
 
    Users should only use the libc socket interface.
    This file exports lower-level functionality */

#ifndef NEXUS_USER_NET_H
#define NEXUS_USER_NET_H

/** Start the lwIP network stack in its own thread */
void nxnet_init(void);

/** The IPC port on which the network stack receives packets from the kerne */
extern int nexusif_port;	

#endif /* NEXUS_USER_NET_H */

