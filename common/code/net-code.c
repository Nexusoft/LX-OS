
#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X,Y) ((X) > (Y) ? (X) : (Y))
// Kernel network components
// At some point, these will be ported to run as userspace processes

void MAC_Address_print(MAC_Address addr) {
  int i;
  for(i=0; i < ETH_ADDR_LEN; i++) {
    if(i != 0) {
      nxcompat_printf(":");
    }
    nxcompat_printf("%02x", ((unsigned char *)addr.addr)[i]);
  }
}

int MAC_Address_is_local(MAC_Address addr, int num_addrs, MAC_Address *local_addrs) {
  int i;
  for(i=0; i < num_addrs; i++) {
    if(MAC_Address_eq(addr, local_addrs[i])) {
      return 1;
    }
  }
  return 0;
}

#define EXTRACT_IMMED_COPY_LEN						\
  int immed_copy_len = MIN(MAX(0, (int)(packet->msg_data_len - sizeof(NetComp_Packet_Header) - offset)), len); \
  /* nxcompat_printf("immed len = %d %d %d %d (%d,%d)\n", immed_copy_len, packet->msg_data_len, sizeof(NetComp_Packet_Header), offset, MAX(0, (int)(packet->msg_data_len - sizeof(NetComp_Packet_Header) - offset)), len);*/ \
  assert(immed_copy_len >= 0)

#define EXTRACT_IMMED_START				\
  (packet->msg_data + sizeof(NetComp_Packet_Header) + offset)
#define ADJUSTED_OFFSET (offset - immed_copy_len)
#define ADJUSTED_LEN (len - immed_copy_len)
#define VERIFY_COPY_LEN()				\
  assert(ADJUSTED_LEN == 0 || ADJUSTED_OFFSET >= 0)


static int NetComp_IPC_from_skb_helper(Connection_Handle conn_handle, struct sk_buff *skb);

static struct sk_buff *net_alloc_skb(void) {
#ifdef __NEXUSKERNEL__
  void *v = getKernelPages(1);
  Page *p = VIRT_TO_PAGE(v);
  struct sk_buff *skb = skb_alloc_indirect(p, 0, 0);
  freeKernelPages(v, 1); v = NULL;
  return skb;
#else
  nxcompat_printf("NOT IMPLEMENTED at %s:%d\n", __FILE__, __LINE__);
  //struct sk_buff *skb = alloc_skb(PAGE_SIZE-32, 0);
  return NULL;
#endif
}

static inline char *skb_data_start(struct sk_buff *skb) {
  return (char *) skb->mac.raw;
}
static inline int skb_data_length(struct sk_buff *skb) {
  return (char *) skb->tail - (char *)skb_data_start(skb);
}

// XXX don't need to allocate skb; useless allocation/deallocation overhead
int NetComp_IPC_from_buf(Connection_Handle conn_handle, char *data, int len) {
#ifdef __NEXUSKERNEL__
  struct sk_buff *skb = net_alloc_skb();
  unsigned char *dest = skb_put(skb, len);
  skb->mac.raw = dest;
  memcpy(dest, data, len);

  return NetComp_IPC_from_skb_helper(conn_handle, skb);
#else
  struct TransferDesc descs[2] = {
    { .access = 0, .u.direct.base = 0, .u.direct.length = 0 },
    { .access = IPC_READ | // read-only access to the 
        ( IPC_MODE_NORMAL << TRANSFER_USER_MODE_SHIFT),
      .u.direct.base = (__u32)NULL,
      .u.direct.length = 0,
    },
  };
  char transfer_buf[1600];
  NetComp_Packet_Header *hdr = (NetComp_Packet_Header *)transfer_buf;
  assert(sizeof(*hdr) + len <= sizeof(transfer_buf));
  *hdr = ((NetComp_Packet_Header){ .type = NETCOMP_TYPE_PLAIN });
  memcpy((char *)(hdr+1), data, len);
  int rv = IPC_AsyncSend(conn_handle, hdr, sizeof(*hdr) + len, descs, 2);
  return rv;
#endif
}

int NetComp_Packet_extract(NetComp_Packet *packet, int offset, void *dest, int len) {
  // packet data starts in descriptor 1
  EXTRACT_IMMED_COPY_LEN;
  VERIFY_COPY_LEN();
  memcpy(dest, EXTRACT_IMMED_START, immed_copy_len);
  // nxcompat_printf("extract: %p\n", dest + immed_copy_len);
  int rv = IPC_TransferFrom(packet->call_handle, packet->desc_num,
			    dest + immed_copy_len, 
			    TransferDesc_get_base(&packet->data_desc) + 
			    ADJUSTED_OFFSET, 
			    ADJUSTED_LEN);
  if(rv != 0) {
    nxcompat_printf("error %d transferring in NetComp_Packet_extract()\n", rv);
  }
  return rv;
}

static int NetComp_Packet_handoff_clone_or_copy(int do_copy, NetComp_Packet *packet, Connection_Handle target) {
  int err = 0;
  struct TransferDesc descs[2];
  int mode = TransferDesc_get_kmode(&packet->data_desc);
  if( mode == IPC_KMODE_PHYSICAL ) {
    int transfer_mode = do_copy ?
      IPC_MODE_COPY_TRANSFERED_DESC :
      IPC_MODE_CLONE_TRANSFERED_DESC ;
    struct TransferDesc temp_descs[2] = {
      { .access = 0, .u.direct.base = 0, .u.direct.length = 0 },
      { .access = 
	(packet->data_desc.access & TRANSFER_ACCESS_MODE_MASK)
	| ( transfer_mode << TRANSFER_USER_MODE_SHIFT ),
	.u.copy_or_clone.rel_base = 0,
	.u.copy_or_clone.length = packet->data_desc.u.direct.length,
	.u.copy_or_clone.call_handle = packet->call_handle,
	.u.copy_or_clone.desc_num = packet->desc_num,
      },
    };
    memcpy(descs, temp_descs, sizeof(descs));
  } else {
    // Support only fully immed packets
    assert(mode == 0);
    if(packet->data_desc.u.direct.length != 0) {
      printk_red("Not fully immed (%d,%d)!\n", packet->msg_data_len, packet->data_desc.u.direct.length);
      err = -1;
      goto out;
    }
    struct TransferDesc temp_descs[2] = {
      { .access = 0, .u.direct.base = 0, .u.direct.length = 0 },
      { .access = 
	(packet->data_desc.access & TRANSFER_ACCESS_MODE_MASK)
	| ( 0 << TRANSFER_USER_MODE_SHIFT ),
	.u.direct.base = 0,
	.u.direct.length = 0,
      },
    };
    memcpy(descs, temp_descs, sizeof(descs));
  }

  IPC_AsyncSend(target, packet->msg_data,
		packet->msg_data_len, descs, 2);
  out:
  if(!do_copy) {
    NetComp_Packet_destroy(packet, 1);
  }
  return err;
}

NetComp_Packet *NetComp_Packet_new(Call_Handle call_handle) {
  IPC_Msg *msg = CallHandle_to_IPC_Msg(nexusthread_current_ipd(), call_handle);
  NetComp_Packet *rv = galloc(sizeof(NetComp_Packet) + msg->data_len);
  assert(msg->common_ctx.num_transfer_descs >= 2);

  dlist_init_link(&rv->link);

  rv->call_handle = call_handle;
  rv->desc_num = NETCOMP_PACKET_DESCNUM;
  rv->data_desc = msg->common_ctx.transfer_descs[NETCOMP_PACKET_DESCNUM];
  rv->msg_data_len = msg->data_len;
  // XXX 11/6/07: Removed user code for wrapped descriptor num, which was
  // used for pcap demo.
  int v; v = IPCMsg_copy_data(msg, NULL, rv->msg_data, msg->data_len);
  assert(v == 0);
#ifdef __NEXUSKERNEL__
  if(skb_data_length(skb) == 0) {
    nexusthread_dump_regs_stack(nexusthread_self());
  }
  // IPCMsg_put(msg) ?
#endif // __NEXUSKERNEL__
  return rv;
}

// XXX Temporary hack. Should be available from userspace !
static int NetComp_IPC_from_skb_helper(Connection_Handle conn_handle, struct sk_buff *skb) {
  struct TransferDesc descs[2] = {
    { .access = 0, .u.direct.base = 0, .u.direct.length = 0 },
    { .access = IPC_READ | IPC_WRITE |
        ( IPC_MODE_TRANSFERPAGE << TRANSFER_USER_MODE_SHIFT),
      .u.direct.base = (__u32)skb_data_start(skb),
      .u.direct.length = skb_data_length(skb),
    },
  };
#ifdef __NEXUSKERNEL__
  if(skb_data_length(skb) == 0) {
    nexusthread_dump_regs_stack(nexusthread_self());
  }
#endif // __NEXUSKERNEL__
  NetComp_Packet_Header hdr = {
    .type = NETCOMP_TYPE_PLAIN,
  };
  //printk("skb->len = %d\n", skb->len);
  int rv = IPC_AsyncSend(conn_handle, &hdr, sizeof(hdr), descs, 2);
#ifdef __NEXUSKERNEL__
  skb_destroy(skb);
#else
  nxcompat_printf("don't know how to destroy packet\n");
#endif
  return rv;
}

int NetComp_IPC_from_skb(Connection_Handle conn_handle, struct sk_buff *skb) {
  if(
#ifdef __NEXUSKERNEL__
	!(skb->allocator == INDIRECT_PAGE || skb->allocator == PAGE) 
#else
	0 // uspace driver always uses full pages
#endif
) {

    // can only do zero-copy with complete pages, since the reference
    // counting is done at the page level, rather than at, say, the
    // allocator level
    struct sk_buff *skb_new = net_alloc_skb();
    int len = skb_data_length(skb);
    memcpy(skb_put(skb_new, len), skb_data_start(skb), len);
#ifdef __NEXUSKERNEL__
    skb_destroy(skb);
#else
    nxcompat_printf("NOT IMPLEMENTED at %s:%d\n", __FILE__, __LINE__);
#endif
    skb = skb_new;
  }

  return NetComp_IPC_from_skb_helper(conn_handle, skb);
}

#ifdef __NEXUSKERNEL__
IPD *create_netcomp_ipd(const char *name) {
      Port_Num control_port;
      IPC_Port *new_port;
      IPD *ipd; 
 
      // create process structure
      ipd = ipd_new();
      ipd->map = kernelMap;
      ipd_setName(ipd, name);
      ipd->is_user_ipd = 0;

      // create port for this process
      nexusthread_impersonate_push(ipd);
      control_port = IPC_CreatePort(NULL);
      assert(control_port);
      new_port = IPCPort_find(control_port);
      assert(new_port);
#ifdef DO_INTERPOSITION
      ipd_set_notification(ipd, control_port);
#endif

      IPCPort_put(new_port);
      nexusthread_impersonate_pop();
      return ipd;
}
#endif // __NEXUSKERNEL__

void IP_Address_print(uint32_t addr) {
  uint8_t *comps = (uint8_t *)&addr;
  nxcompat_printf("%d.%d.%d.%d", comps[0], comps[1], comps[2], comps[3]);
}

#ifndef __NEXUSKERNEL__
int 
NetComp_get_default_ip_switch(void) 
{
	char *value;
	long ivalue;

	// read from env
	value = Env_get_value("default_ip_switch", NULL);
	if (!value) {
		fprintf(stderr, "[net] no default switch\n");
		return -1;
	}

	// convert to integer
	ivalue = strtol(value, NULL, 10);
	free(value);

	return (int) ivalue;
}
#endif // __NEXUSKERNEL__

void NetComp_init(void) {
  extern void NIC_serverInit(void);
  extern void VNIC_serverInit(void);
  extern void PNIC_serverInit(void);
  extern void NIC_Async_serverInit(void);
  extern void Switch_serverInit(void);

  // This initialization depends on having more of the kernel than nexus_io_init()
  NIC_serverInit();
  // This initialization depends on having more of the kernel than nexus_io_init()
  VNIC_serverInit();
  PNIC_serverInit();
  NIC_Async_serverInit();
  Switch_serverInit();

#ifndef __NEXUSKERNEL__
  extern Port_Num NIC_port_handle;
  extern Port_Num VNIC_port_handle;
  extern Port_Num PNIC_port_handle;
  extern Port_Num NIC_Async_port_handle;
  extern Port_Num Switch_port_handle;
  IPC_DestroyPort(NIC_port_handle);
  IPC_DestroyPort(VNIC_port_handle);
  IPC_DestroyPort(PNIC_port_handle);
  IPC_DestroyPort(NIC_Async_port_handle);
  IPC_DestroyPort(Switch_port_handle);

  // Uspace IPCPort_set*handler() API requires handles to be initialized to 0
  NIC_port_handle = 0;
  VNIC_port_handle = 0;
  PNIC_port_handle = 0;
  NIC_Async_port_handle = 0;
  Switch_port_handle = 0;
#endif
}

int 
netservice_bind_accept_all(Connection_Handle caller, 
			   Port_Handle *_notification_handle_p) 
{
#ifdef DO_INTERPOSITION
#ifdef __NEXUSKERNEL__
  // NB: this code might have varied in subtle ways 
  // (notification_port_p vs notification_handle_p) when in individual users.
  // XXX verify correctness before use
  IPC_Port **notification_handle_p = (IPC_Port **)_notification_handle_p;
  IPD *ipd = nexusthread_current_ipd();
  assert(ipd_is_kernel(ipd) && ipd != kernelIPD);
  IPC_Port *port = IPCPort_find(g_Wrap_port_handle);
  assert(port != NULL);
  *notification_port_p = port;
  IPCPort_put(port);
#else
  *notification_handle_p = g_Wrap_port_handle;
#endif 
#endif
  return 0;
}

