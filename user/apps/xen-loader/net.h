#ifndef _XEN_NET_H_
#define _XEN_NET_H_
int xen_vnet_init(int vnic_num, char *assigned_mac);
int xen_vnet_poll(int vnic_num);
int xen_vnet_usend(int vnic_num, char *data, int len);
int xen_vnet_urecv(int vnic_num, char *data, int len);
int xen_vnet_setup_irq(int vnic_num, int irq_num);

#endif // _XEN_NET_H_
