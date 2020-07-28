#include <linux/kernel.h> // for min()
#include <asm/delay.h> // for udelay
#include <asm/param.h> // for HZ

#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/defs.h>
#include <nexus/device.h>
#include <nexus/mousedev.h>
#include <nexus/syscall-defs.h>
#include <nexus/ipd.h>
#ifdef __NEXUSXEN__
#include <nexus/xen-defs.h>
#include <xen/xen.h>
#endif

#if 0
#define MOUSE_DEBUG(...) printk_red(__VA_ARGS__)
#else
#define MOUSE_DEBUG(...)
#endif
// The mouse protocol handling is derived from Xorg 1.1.1

#define MOUSE_EVENT_QUEUELEN (512)

#define ALLOW_MULTIPLE_PROTOCOL_SWITCH 0

NexusDevice *nexus_mouse_device;

/* mouse proto flags */
#define MPF_NONE		0x00
#define MPF_SAFE		0x01

static int do_parse = 0;

static unsigned char proto_params[MPROT_LAST][8] = {
  [MPROT_DEFAULT]= {  0xc8, 0x08, 0x00, 0x00,  3,   0x00, 0x00, MPF_NONE },  /* genericPS/2 mouse*/
  [MPROT_IMPS2] 	= {  0x08, 0x08, 0x00, 0x00,  4,   0x00, 0xff, MPF_NONE },  /* IntelliMouse */
  [MPROT_EXPPS2]	= {  0x08, 0x08, 0x00, 0x00,  4,   0x00, 0xff, MPF_NONE },  /* Explorer */
};

typedef struct MouseContext {
  enum MouseProto protocol;
  Sema *mutex;
  Sema *event_counter_sema;

  int head;
  int tail;
  struct MouseEvent events[MOUSE_EVENT_QUEUELEN];
} MouseContext;

#define RETRY_COUNT (8)

static int do_psaux_reset(NexusDevice *nd);
static int psaux_reset(NexusDevice *nd);
static int psaux_enable(NexusDevice *nd);

static void mouse_delay(void) {
  udelay(100000);
}

// Delay with interrupts enabled (so data can be read)
static void mouse_delay_with_ints(void) {
  int intlevel = disable_intr();
  restore_intr(1);
  mouse_delay();
  restore_intr(intlevel);
}

// Returns true if successfully parsed a packet
static int mouse_parse(NexusDevice *nd, struct MouseEvent *mevent);
static void nd_mouse_setProtocol(NexusDevice *nd, NexusOpenDevice *nod);
static void nd_mouse_flush(NexusDevice *nd);
static int nd_mouse_peek(NexusDevice *nd, char *dest, int len);
static int nd_mouse_read(NexusDevice *nd, char *dest, int len);
static int nd_mouse_send_packet(NexusDevice *nd, const char *src, int len);
static int nd_mouse_write(NexusDevice *nd, const char *src, int len);

// No event notification: The raw data queue is only used for
// detecting ACKs and mouse protocol parsing
void mouse_handleScancode(unsigned char scancode) {
  NexusDevice *nd = nexus_mouse_device;
  if(nd == NULL) {
    // not ready for interrupts
    return;
  }
  struct device_mouse_ops *mops = nd->data;
  mops->raw_data[mops->tail] = scancode;
  mops->tail = (mops->tail + 1) % MOUSE_RAW_DATA_LEN;

  if(do_parse) {
    while(1) {
      // Parse next packet according to protocol
      struct MouseEvent new_event;
      int parse_success = mouse_parse(nd, &new_event);
      if(!parse_success) {
	// incomplete packet, try parsing when more data arrives
	break;
      }

      // Deliver to the currently focused IPD
      IPD *ipd = focus_current_ipd();
      if(ipd == NULL) {
	// Active window does not have mouse opened, throw away events
	continue;
      }
      NexusOpenDevice *nod = ipd_get_open_device(ipd, DEVICE_MOUSE, -1);
      if(nod == NULL) {
	// Active window does not have mouse opened, throw away events
	continue;
      }
      MouseContext *mctx = nod->odata;
      mctx->events[mctx->tail] = new_event;
      mctx->tail = (mctx->tail + 1) % MOUSE_EVENT_QUEUELEN;

#ifdef __NEXUSXEN__
      if(ipd_isXen(ipd)) {
	ipd_Xen_sendVIRQ(ipd, VIRQ_VMOUSE);
      } else {
	V(mctx->event_counter_sema);
      }
#endif /* __NEXUSXEN__ */
    }
  }
}

NexusOpenDevice *mouse_new(NexusDevice *nd, IPD *ipd) {
  assert(nd->type == DEVICE_MOUSE);
  MouseContext *mctx = galloc(sizeof(MouseContext));
  mctx->protocol = MPROT_DEFAULT;
  mctx->mutex = sema_new_mutex();
  mctx->event_counter_sema = sema_new();
  mctx->head = mctx->tail = 0;
  memset(mctx->events, 0, sizeof(mctx->events));

  NexusOpenDevice *nod = nexus_open_device(nd, mctx);
  // mouse_setProtocol(nod, MPROT_IMPS2);
  return nod;
}

int mouse_setProtocol(NexusOpenDevice *nod, enum MouseProto proto) {
  MouseContext *mctx = nod->odata;
  NexusDevice *nd = nod->nd;
  struct device_mouse_ops *mops = nd->data;

  if(!ALLOW_MULTIPLE_PROTOCOL_SWITCH) {
    // ASHIEH: Since I don't understand the mouse state machine
    // ramifications of mode switches, I only allow one mode switch
    if(mops->protocol != MPROT_DEFAULT) {
      MOUSE_DEBUG("Protocol already changed!\n");
      return -1;
    }
    if(mops->protocol == proto) {
      MOUSE_DEBUG("Already using protocol %d\n", proto);
      return 0;
    }
  }

  mctx->protocol = proto;
  if(nod->focused) {
    nd_mouse_setProtocol(nod->nd, nod);
  } else {
    MOUSE_DEBUG("Not focused\n");
  }
  return 0;
}

void mouse_focus(NexusOpenDevice *nod, int focus) {
  if(ALLOW_MULTIPLE_PROTOCOL_SWITCH) {
    // Switching protocols seems dangerous
    if(focus) {
      nd_mouse_setProtocol(nod->nd, nod);
    }
  }
}

int mouse_poll(NexusOpenDevice *nod) {
  MouseContext *mctx = nod->odata;
  while(mctx->tail - mctx->head == 0) {
    P(mctx->event_counter_sema);
  }
  return (mctx->tail - mctx->head + MOUSE_EVENT_QUEUELEN) % 
    MOUSE_EVENT_QUEUELEN;
}

#define MAX_MOUSE_LOG (32)
static struct MouseEvent last_mouse_events[MAX_MOUSE_LOG];
static int last_mouse_pos = 0;

void mouse_dump_log(void) {
  int i;
  for(i=0; i < MAX_MOUSE_LOG; i++) {
    struct MouseEvent *event = &last_mouse_events[(last_mouse_pos + i) % MAX_MOUSE_LOG];
    printk("[%d] = { %d, %d, %d, %x } ", i, event->dx, event->dy, event->dz, event->buttons);
  }
}

int mouse_read(NexusOpenDevice *nod, 
	       struct MouseEvent *dest, int max_num_events) {
  MouseContext *mctx = nod->odata;
  P(mctx->mutex);
  int read_len = 
    min(max_num_events, 
	(mctx->tail - mctx->head + MOUSE_EVENT_QUEUELEN) % 
	MOUSE_EVENT_QUEUELEN);
  int i;
  for(i=0; i < read_len; i++) {
    dest[i] = mctx->events[(mctx->head + i) % MOUSE_EVENT_QUEUELEN];

    last_mouse_events[last_mouse_pos] = dest[i];
    last_mouse_pos = (last_mouse_pos + 1) % MAX_MOUSE_LOG;
  }
  mctx->head = (mctx->head + read_len) % MOUSE_EVENT_QUEUELEN;
  V(mctx->mutex);
  return read_len;
}

//
// Non-multiplexed code below this point
//

void mouse_parse_disable(void) {
  do_parse = 0;
}

void mouse_parse_enable(void) {
  do_parse = 1;
}

static int do_psaux_reset(NexusDevice *nd) {
  int i;
  for(i=0; i < RETRY_COUNT; i++) {
    if(psaux_reset(nd) == 0) {
      return 0;
    }
  }
  return -1;
}

static int psaux_reset(NexusDevice *nd) {
  // XXX psaux_reset() might be broken. The mouse does not come back
  unsigned char u;
  unsigned char packet[] = { 0xff };
  unsigned char reply[] = { 0xaa, 0x00 }; // " Device attached "
  unsigned int i;

  nd_mouse_flush(nd);
  if (nd_mouse_send_packet(nd, packet, sizeof(packet)) != 0) {
    MOUSE_DEBUG("psaux_reset: could not write to mouse\n");
    goto EXIT;
  }

  /* we need a little delay here */
  mouse_delay_with_ints();
  for (i = 0; i < sizeof(reply) ; i++) {
    if (!nd_mouse_read(nd,&u, 1)) {
      MOUSE_DEBUG("psaux_reset: could not read from mouse (%d)\n", i);
      goto EXIT;
    }
    if (u != reply[i]) {
      MOUSE_DEBUG("psaux_reset: ack mismatch at %d (%02x != %02x)\n", i, u, reply[i]);
      goto EXIT;
    }
  }

  if(psaux_enable(nd) != 0) {
    MOUSE_DEBUG("enable failed\n");
    goto EXIT;
  }
  return 0;

 EXIT:
  nd_mouse_flush(nd);
  return -1;
}

static int psaux_enable(NexusDevice *nd) {
  // Send an enable device message. Xorg doesn't need this, but we do.
  unsigned char enable[] = { 0xf4 };
  if(nd_mouse_send_packet(nd, enable, sizeof(enable)) != 0) {
    MOUSE_DEBUG("psaux_enable failed!\n");
    goto EXIT;
  }
  nd_mouse_flush(nd);
  return 0;
 EXIT:
  nd_mouse_flush(nd);
  return -1;
}

int nd_set_protocol(NexusDevice *nd, enum MouseProto proto) {
  MOUSE_DEBUG("setting protocol %d\n", proto);
  int do_reset = 0;
  const char *param;
  int paramlen;
  int do_mse_init = 0;
  struct device_mouse_ops *mops = nd->data;
  mops->protocol = proto;

  switch(proto) {
  case MPROT_DEFAULT:
    do_mse_init = 1;
    param = NULL;
    paramlen = 0;
    break;
  case MPROT_IMPS2:		/* IntelliMouse */
    {
      static const unsigned char seq[] = { 243, 200, 243, 100, 243, 80 };
      do_mse_init = 1;
      param = seq;
      paramlen = sizeof(seq);
    }
    break;
  case MPROT_EXPPS2:		/* IntelliMouse Explorer (vmware) */
    {
      static unsigned char seq[] = { 243, 200, 243, 100, 243, 80,
				     243, 200, 243, 200, 243, 80 };
      do_mse_init = 1;
      param = seq;
      paramlen = sizeof(seq);
    }
    break;
 default:
   MOUSE_DEBUG("Unknown mouse protocol %d!\n", proto);
   return -SC_INVALID;
   break;
  }

  if(do_reset) {
    if(do_psaux_reset(nd) != 0) {
      MOUSE_DEBUG("Reset failed! Mouse is probably unusable\n");
      return -SC_INVALID;
    }
    psaux_set_default_params();
    mouse_delay();
  }

  if(do_mse_init) {
    int count = RETRY_COUNT; // retry_count
  REDO:
    do_psaux_reset(nd);
    if (paramlen > 0) {
      if (nd_mouse_send_packet(nd,param,paramlen) != 0) {
	mouse_delay();
	nd_mouse_flush(nd);
	if (!count--) {
	  MOUSE_DEBUG("Protocol change retry count exceeded!\n");
	  return 0;
	}
	MOUSE_DEBUG("Redo protocol change\n");
	goto REDO;
      }
      // ps2GetDeviceID(pInfo);
      mouse_delay();
      nd_mouse_flush(nd);
    }

#if 1
    // Xorg PS2  speed , resolution, etc. modification. We re-invoke the Linux code
    psaux_set_default_params();
    mouse_delay();
    // we don't want to read any lingering junk from setting the parameters while we re-enable
    nd_mouse_flush(nd);
    psaux_enable(nd);
    nd_mouse_flush(nd);
#else // Some other complicated Xorg stuff
    if (osInfo->SetPS2Res) {
      osInfo->SetPS2Res(pInfo, pMse->protocol, pMse->sampleRate,
			pMse->resolution);
    } else {
      unsigned char c2[2];
		
      c = 0xE6;	/*230*/	/* 1:1 scaling */
      if (!ps2SendPacket(pInfo,&c,1)) {
	if (!count--)
	  return TRUE;
	goto REDO;
      }
      c2[0] = 0xF3; /*243*/ /* set sampling rate */
      if (pMse->sampleRate > 0) {
	if (pMse->sampleRate >= 200)
	  c2[1] = 200;
	else if (pMse->sampleRate >= 100)
	  c2[1] = 100;
	else if (pMse->sampleRate >= 80)
	  c2[1] = 80;
	else if (pMse->sampleRate >= 60)
	  c2[1] = 60;
	else if (pMse->sampleRate >= 40)
	  c2[1] = 40;
	else
	  c2[1] = 20;
      } else {
	c2[1] = 100;
      }
      if (!ps2SendPacket(pInfo,c2,2)) {
	if (!count--)
	  return TRUE;
	goto REDO;
      }
      c2[0] = 0xE8; /*232*/	/* set device resolution */
      if (pMse->resolution > 0) {
	if (pMse->resolution >= 200)
	  c2[1] = 3;
	else if (pMse->resolution >= 100)
	  c2[1] = 2;
	else if (pMse->resolution >= 50)
	  c2[1] = 1;
	else
	  c2[1] = 0;
      } else {
	c2[1] = 3; /* used to be 2, W. uses 3 */
      }
      if (!ps2SendPacket(pInfo,c2,2)) {
	if (!count--)
	  return TRUE;
	goto REDO;
      }
      usleep(30000);
      xf86FlushInput(pInfo->fd);
      if (!ps2EnableDataReporting(pInfo)) {
	xf86Msg(X_INFO, "%s: ps2EnableDataReporting: failed\n",
		pInfo->name);
	xf86FlushInput(pInfo->fd);
	if (!count--)
	  return TRUE;
	goto REDO;
      } else {
	xf86Msg(X_INFO, "%s: ps2EnableDataReporting: succeeded\n",
		pInfo->name);
      }
    }
#endif
  } else {
    if (paramlen > 0) {
      
      if (nd_mouse_send_packet(nd, param, paramlen) != 0) {
	MOUSE_DEBUG("Mouse initialization failed, protocol %d, tried to"
		   " write %d\n", proto, paramlen);
	return -SC_INVALID;
      }
      mouse_delay();
      // Xorg does not ack
    }
  }
  return 0;
}

static void nd_mouse_setProtocol(NexusDevice *nd, NexusOpenDevice *nod) {
  assert(nod->nd == nd);
  MouseContext *mctx = nod->odata;

  mouse_parse_disable();
  nd_set_protocol(nod->nd, mctx->protocol);
  mouse_parse_enable();
}

static void nd_mouse_flush(NexusDevice *nd) {
  // Flush the read queue
  struct device_mouse_ops *mops = nd->data;
  mops->tail = mops->head;
}

static int nd_mouse_read_helper(NexusDevice *nd, char *dest, int len, int do_peek) {
  // nd_mouse_read() uses the Nexus-layer queue. The Linux layer
  // aux_queue will go away
  struct device_mouse_ops *mops = nd->data;
  int read_len =
    min(len,
	(mops->tail - mops->head + MOUSE_RAW_DATA_LEN) % 
	MOUSE_RAW_DATA_LEN);
  int i;
  for(i=0; i < read_len; i++) {
    dest[i] = mops->raw_data[(mops->head + i) % MOUSE_RAW_DATA_LEN];
  }
  if(!do_peek) {
    mops->head = (mops->head + read_len) % MOUSE_RAW_DATA_LEN;
  }
  // MOUSE_DEBUG("(rl=%d/%d)", read_len, len);
  return read_len;
}

static int nd_mouse_read(NexusDevice *nd, char *dest, int len) {
  return nd_mouse_read_helper(nd, dest, len, 0);
}

static int nd_mouse_peek(NexusDevice *nd, char *dest, int len) {
  return nd_mouse_read_helper(nd, dest, len, 1);
}

static int nd_mouse_send_packet(NexusDevice *nd, const char *src, int len) {
  // Based on Xorg ps2SendPacket
  int i, j;
  unsigned char c;

  for (i = 0; i < len; i++) {
    for (j = 0; j < 10; j++) {
      nd_mouse_write(nd, src + i, 1);
      mouse_delay_with_ints();
      if (nd_mouse_read(nd,&c, 1) != 1) {
	MOUSE_DEBUG("could not recv from psaux @ %d/%d\n", i, len);
	goto ERR;
      }
      if (c == 0xFA) /* ACK */
	break;

      if (c == 0xFE) /* resend */
	continue;
	    

      if (c == 0xFC) /* error */ {
	MOUSE_DEBUG("psaux returned error at %d\n", i);
	goto ERR;
      }

#if 0
      /* Some mice accidently enter wrap mode during init */
      if (c == *(bytes + i)    /* wrap mode */
	  && (*(bytes + i) != 0xEC)) /* avoid recursion */
	ps2DisableWrapMode(pInfo);
#endif

      MOUSE_DEBUG("psaux unknown return value %02x", c);
      goto ERR;
    }
    if (j == 10) {
      MOUSE_DEBUG("psaux too many tries @ %d\n", i);
      goto ERR;
    }
  }
  return 0;
 ERR:
  return -1;
}

static int nd_mouse_write(NexusDevice *nd, const char *src, int len) {
  struct device_mouse_ops *mops = nd->data;
  return mops->write(nd, src, len);
}

// mouse_parse is not smart enough to detect synchronization / overflow errors!

// Returns true if successfully parsed a packet
static int mouse_parse(NexusDevice *nd, struct MouseEvent *mevent) {
 resync_retry: ;
  int num_bytes;
  unsigned char pBuf[4];
  unsigned char data2[4]; // separate scratch buffer for second read for sanity check

  struct device_mouse_ops *mops = nd->data;
  enum MouseProto proto = mops->protocol;
  const unsigned char *protoPara = proto_params[proto];
  assert(proto >= 0 && proto < MPROT_LAST);
  int packet_len = protoPara[4];

  memset(mevent, 0, sizeof(*mevent));
  int buttons = 0;
  short dx = 0, dy = 0, dz = 0;

  assert(packet_len <= sizeof(pBuf));

  // Try to read the packet size needed by this protocol
  num_bytes = nd_mouse_peek(nd, pBuf, packet_len);
  if(num_bytes < packet_len) {
    return 0;
  }

  // Resynchronize. Note that this is useless if the protocol is wrong!
  if((pBuf[0] & protoPara[0]) != protoPara[1]) {
    MOUSE_DEBUG("mouse sync lost!");
    // consume a byte, try again
    nd_mouse_read(nd, data2, 1);
    goto resync_retry;
  }
  // Consume these packets
  num_bytes = nd_mouse_read(nd, data2, packet_len);
  assert(num_bytes == packet_len && memcmp(pBuf, data2, packet_len) == 0);

  int reprocess_count = 0;
#define DO_REPROCESS()						\
  if(reprocess_count == 0) {					\
    reprocess_count++;						\
    goto REPROCESS;						\
  } else {							\
    MOUSE_DEBUG("Mouse tried reprocessing multiple times!\n");	\
  }

#define SWITCH_PROTO(NEW_PROTO)			\
      proto = mops->protocol = NEW_PROTO;			\
      protoPara = proto_params[proto];


 REPROCESS:
  switch(proto) {
  case MPROT_DEFAULT: // PROT_GENPS2 in Xorg
    buttons = (pBuf[0] & 0x04) >> 1 |       /* Middle */
      (pBuf[0] & 0x02) >> 1 |       /* Right */
      (pBuf[0] & 0x01) << 2;        /* Left */
    dx = (pBuf[0] & 0x10) ?    (int)pBuf[1]-256  :  (int)pBuf[1];
    dy = (pBuf[0] & 0x20) ?  -((int)pBuf[2]-256) : -(int)pBuf[2];
    break;
  case MPROT_IMPS2:
    // Process the common 1st 3 bytes
    // This is the PROT_IMPS2 / PROT_NETPS2 path from Xorg
    // Note that some other protocols do this differently
    buttons |= (pBuf[0] & 0x04) >> 1 |       /* Middle */
      (pBuf[0] & 0x02) >> 1 |       /* Right */
      (pBuf[0] & 0x01) << 2 |       /* Left */
      (pBuf[0] & 0x40) >> 3 |       /* button 4 */
      (pBuf[0] & 0x80) >> 3;        /* button 5 */
    dx = (pBuf[0] & 0x10) ?    pBuf[1]-256  :  pBuf[1];
    dy = (pBuf[0] & 0x20) ?  -(pBuf[2]-256) : -pBuf[2];
    /*
     * The next cast must be 'signed char' for platforms (like PPC)
     * where char defaults to unsigned.
     */
    dz = (signed char)(pBuf[3] | ((pBuf[3] & 0x08) ? 0xf8 : 0));
    if ((pBuf[3] & 0xf8) && ((pBuf[3] & 0xf8) != 0xf8)) {
      MOUSE_DEBUG("Warning: Mouse driver detected EXPPS2 mouse, but we're in IMPS2! Switching\n");
      SWITCH_PROTO(MPROT_EXPPS2);
      DO_REPROCESS();
    }
    break;
  case MPROT_EXPPS2:
    if(0 && pBuf[3] & 0xC0) { // This seems to cause problems with T43
      MOUSE_DEBUG("Warning: Mouse driver detected plain IMPS2, but we're in EXPPS2! Switching.\n");
      SWITCH_PROTO(MPROT_IMPS2);
      DO_REPROCESS();
    }
    buttons = (pBuf[0] & 0x04) >> 1 |       /* Middle */
      (pBuf[0] & 0x02) >> 1 |       /* Right */
      (pBuf[0] & 0x01) << 2 |       /* Left */
      (pBuf[3] & 0x10) >> 1 |       /* button 4 */
      (pBuf[3] & 0x20) >> 1;        /* button 5 */
    dx = (pBuf[0] & 0x10) ?    pBuf[1]-256  :  pBuf[1];
    dy = (pBuf[0] & 0x20) ?  -(pBuf[2]-256) : -pBuf[2];
#if 0
    // Xorg does the following with the 2nd mouse wheel
    if (pMse->negativeW != MSE_NOAXISMAP) {
      switch (pBuf[3] & 0x0f) {
      case 0x00:          break;
      case 0x01: dz =  1; break;
      case 0x02: dw =  1; break;
      case 0x0e: dw = -1; break;
      case 0x0f: dz = -1; break;
      default:
	xf86Msg(X_INFO,
		"Mouse autoprobe: Disabling secondary wheel\n");
	pMse->negativeW = pMse->positiveW = MSE_NOAXISMAP;
      }
    }
    if (pMse->negativeW == MSE_NOAXISMAP)
      dz = (pBuf[3]&0x08) ? (pBuf[3]&0x0f) - 16 : (pBuf[3]&0x0f);
#endif

    break;
  default:
    printk_red("Unsupported mouse proto %d!\n", proto);
    nexuspanic();
  }

  assert(buttons <= 0xff);
  mevent->dx = dx;
  mevent->dy = dy;
  mevent->dz = dz;
  mevent->buttons = buttons;
  return 1;
}

int nd_GetDeviceID(NexusDevice *nd)
{
    unsigned char u;
    unsigned char packet[] = { 0xf2 };

    mouse_delay();
    nd_mouse_flush(nd);
    if (nd_mouse_send_packet(nd, packet, sizeof(packet)) != 0) 
      return -1;
    while (1) {
      if (!nd_mouse_read(nd,&u, 1))
	return -1;
      if (u != 0xFA)
	break;
    }
    return (int) u;
}
