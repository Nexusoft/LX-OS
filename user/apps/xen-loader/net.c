#include <nexus/VNIC.interface.h>
#include "loader.h"
#include <nexus/sema.h>
#include <nexus/netcomp.h>
#include "io.h"
#include <nexus/env.h>

typedef struct XenHWState XenHWState;
struct XenHWState {
  VNIC_Client *vnic_client;
  VNIC_Server *vnic_server;

  Sema rx_queue_mutex;
  dlist_head_list rx_queue;

  int virq_enabled;
  int consumer_virq;
};

static XenHWState *xen_hw_state = NULL;
static XenHWState *XenHWState_new(void) {
  XenHWState *rv = galloc(sizeof(XenHWState));
  rv->vnic_client = NULL;
  rv->vnic_server = NULL;
  rv->rx_queue_mutex = ((Sema) SEMA_MUTEX_INIT);
  dlist_init_head(&rv->rx_queue);

  rv->virq_enabled = 0;
  rv->consumer_virq = -1;
  return rv;
}

static XenHWState *
XenHWState_get(int do_alloc) {
  XenHWState *rv = xen_hw_state;
  if(rv == NULL) {
    if(do_alloc) {
      rv = xen_hw_state = XenHWState_new();
    }
  }
  return rv;
}


static void vnet_up_tx_handler(IPD_ID source_ipd, Call_Handle call_handle, void *_ctx) {
  printf("vnet got new packet?\n");
  assert(0);
}

static void vnet_down_tx_handler(IPD_ID source_ipd, Call_Handle call_handle, void *_ctx) {
  XenHWState *hw = _ctx;
  NetComp_Packet *pkt = NetComp_Packet_new(call_handle);

  P(&hw->rx_queue_mutex);
  dlist_insert_tail(&hw->rx_queue, &pkt->link);
  V_nexus(&hw->rx_queue_mutex);

  if(hw->virq_enabled) {
    send_virq(hw->consumer_virq);
  }
}


static void XenHWState_destroy(XenHWState *hw) {
  VNIC_destroy_server(hw->vnic_client->control_port);
  VNIC_destroy_client(hw->vnic_client);

  dlist_head *_pkt, *_next_pkt;
  P(&hw->rx_queue_mutex);
  dlist_head_walk_safe(&hw->rx_queue, _pkt, _next_pkt) {
    dlist_unlink(_pkt);
    NetComp_Packet *pkt = CONTAINER_OF(NetComp_Packet, link, _pkt);
    NetComp_Packet_destroy(pkt, 1);
  }
  V_nexus(&hw->rx_queue_mutex);
  sema_destroy_contents(&hw->rx_queue_mutex);
  gfree(hw);
}


int xen_vnet_init(int vnic_num, char *assigned_mac) {
  if(XenHWState_get(0) != NULL) {
    printf("vnet_init(): already initialized!\n");
    return -SC_INVALID;
  }
  int rval = 0;
  XenHWState *hw = XenHWState_get(1);
#ifdef DO_BROKEN
  int default_ip_switch = NetComp_get_default_ip_switch();
  printf("got default ip switch %d\n", default_ip_switch);
#else
  // XXX fix
  printf("DEPRECATED AND BROKEN: ip switch. \n");
#endif
  hw->vnic_client = VNIC_new("Xen-VNIC", default_ip_switch, 1, 0);
  if(hw->vnic_client == NULL) {
    printf("vnet_init(): could not create new VNIC\n");
    rval = -SC_INVALID;
    goto out_pop;
  }
  hw->vnic_server = VNIC_Server_find(hw->vnic_client->control_port);
  assert(hw->vnic_server != NULL);
  VNIC_Server_set_tx_handlers(hw->vnic_server, hw, vnet_up_tx_handler, vnet_down_tx_handler);

  MAC_Address addr;
  struct VarLen vl = {
    .data = &addr,
    .len = sizeof(addr),
  };
  int rv = NIC_get_mac_addresses_ext(hw->vnic_client->control_conn, vl);
  if(rv != 1) {
    printf("vnet_init(): could not get mac addresses (rv = %d)\n", rv);
    XenHWState_destroy(hw);
    rval = -SC_INVALID;
    goto out_pop;
  }
  printf("mac address: "); MAC_Address_print(addr);
  if( (rv = copy_to_guest(assigned_mac, &addr.addr[0], ETH_ADDR_LEN)) != 0) {
    XenHWState_destroy(hw);
    xen_hw_state = NULL;
    rval = -SC_ACCESSERROR;
    goto out_pop;
  }
 out_pop:
  return 0;
}

#define XEN_GET_VNIC()				\
  XenHWState *hw = XenHWState_get(0);	\
  if(hw == NULL) {				\
    printf("vnic not initialized!\n");	\
    return -SC_INVALID;				\
  }

int xen_vnet_poll(int vnic_num) {
  XEN_GET_VNIC();
  P(&hw->rx_queue_mutex);
  int length = hw->rx_queue.len;
  V_nexus(&hw->rx_queue_mutex);
  return length;
}

int xen_vnet_usend(int vnic_num, char *data, int len) {
  XEN_GET_VNIC();
  // printf("sending %p,%d\n", data, len);
  int rv = NetComp_IPC_from_buf(hw->vnic_server->down.out_conn, data, len);
  if(rv != 0) {
    printf("vnet_send error %d\n", rv);
  }
  return rv;
}

int xen_vnet_urecv(int vnic_num, char *data, int max_len) {
  XEN_GET_VNIC();
    
  P(&hw->rx_queue_mutex);
  dlist_head *_pkt = dlist_dequeue(&hw->rx_queue);
  V_nexus(&hw->rx_queue_mutex);

  if(_pkt == NULL) {
    // no packet
    return 0;
  }
  NetComp_Packet *pkt = CONTAINER_OF(NetComp_Packet, link, _pkt);
  int len = NetComp_Packet_get_len(pkt);
  if(max_len < len) {
    printf("not enough length for urecv (%d < %d)\n", max_len, len);
    return -1;
  }
  int rv = NetComp_Packet_extract(pkt, 0, data, len);
  if(rv != 0) {
    printf("error extracting data from packet\n");
    len = -SC_INVALID;
  }
  NetComp_Packet_destroy(pkt, 1);
  return len;
}

int xen_vnet_setup_irq(int vnic_num, int irq_num) {
  XEN_GET_VNIC();
  
  hw->virq_enabled = 1;
  hw->consumer_virq = irq_num;
  return 0;
}
