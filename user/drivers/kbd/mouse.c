#include <linux/kernel.h> // for min()
#include <asm/delay.h> // for udelay
#include <asm/param.h> // for HZ

#include <nexus/defs.h>
#include <nexus/syscall-defs.h>
#include <nexus/sema.h>
#include "mouse.h"

#define assert(X) do { if (!(X)) nexuspanic(); } while (0)

#if 0
#define MOUSE_DEBUG(...) printk_red(__VA_ARGS__)
#else
#define MOUSE_DEBUG(...)
#endif

// currently used mouse protocol
static int global_protocol = MPROT_DEFAULT;

// queue of scancodes
#define SCANCODE_QLEN 16
static unsigned char global_queue[SCANCODE_QLEN];
static int global_head, global_tail;

static int psaux_enable(void);

// Returns true if successfully parsed a packet
static int mouse_parse(struct MouseEvent *mevent);
static void nd_mouse_setProtocol(void);
static int nd_mouse_peek(char *dest, int len);
static int nd_mouse_read(char *dest, int len);
static int nd_mouse_send_packet(const char *src, int len);


/* mouse proto flags */
#define MPF_NONE		0x00
#define MPF_SAFE		0x01

static unsigned char proto_params[MPROT_LAST][8] = {
  [MPROT_DEFAULT]= {  0xc8, 0x08, 0x00, 0x00,  3,   0x00, 0x00, MPF_NONE },  /* genericPS/2 mouse*/
  [MPROT_IMPS2] 	= {  0x08, 0x08, 0x00, 0x00,  4,   0x00, 0xff, MPF_NONE },  /* IntelliMouse */
  [MPROT_EXPPS2]	= {  0x08, 0x08, 0x00, 0x00,  4,   0x00, 0xff, MPF_NONE },  /* Explorer */
};

#define RETRY_COUNT (8)

static void 
mouse_delay(void) 
{
  usleep(10000);
}

// handle the scancode and optionally notify waiting console
void mouse_handleScancode(unsigned char scancode) {
  struct MouseEvent *new_event;

  // append to scancode-queue
  global_queue[global_tail] = scancode; 
  global_tail = (global_tail + 1) % SCANCODE_QLEN; 

  while(1) {
    // Parse next packet according to protocol
    new_event = malloc(sizeof(struct MouseEvent));
    if (!mouse_parse(new_event))
      // incomplete packet, try parsing when more data arrives
      break;

    IPC_Send(default_mouse_port, new_event, sizeof(struct MouseEvent));
  }
}

static int psaux_enable(void) {
  // Send an enable device message. Xorg doesn't need this, but we do.
  unsigned char enable[] = { 0xf4 };
  if(nd_mouse_send_packet(enable, sizeof(enable)) != 0) {
    MOUSE_DEBUG("psaux_enable failed!\n");
    goto EXIT;
  }
  return 0;
 EXIT:
  return -1;
}

int nd_set_protocol(enum MouseProto proto) {
  MOUSE_DEBUG("setting protocol %d\n", proto);
  const char *param;
  int paramlen;
  int do_mse_init = 0;

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

  if(do_mse_init) {
    int count = RETRY_COUNT; // retry_count
  REDO:
    if (paramlen > 0) {
      if (nd_mouse_send_packet(param,paramlen) != 0) {
	mouse_delay();
	if (!count--) {
	  MOUSE_DEBUG("Protocol change retry count exceeded!\n");
	  return 0;
	}
	MOUSE_DEBUG("Redo protocol change\n");
	goto REDO;
      }
      // ps2GetDeviceID(pInfo);
      mouse_delay();
    }

    // Xorg PS2  speed , resolution, etc. modification. We re-invoke the Linux code
    psaux_set_default_params();
    mouse_delay();
    // we don't want to read any lingering junk from setting the parameters while we re-enable
    psaux_enable();
  } else {
    if (paramlen > 0) {
      
      if (nd_mouse_send_packet(param, paramlen) != 0) {
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

static void nd_mouse_setProtocol(void) {
  // not implemented
}

static int nd_mouse_read_helper(char *dest, int len, int do_peek) {
  int read_len =
    min(len,
	(global_tail - global_head + SCANCODE_QLEN) % 
	SCANCODE_QLEN);
  int i;
  for(i=0; i < read_len; i++) {
    dest[i] = global_queue[(global_head + i) % SCANCODE_QLEN];
  }
  if(!do_peek) {
    global_head = (global_head + read_len) % SCANCODE_QLEN;
  }
  return read_len;
}

static int nd_mouse_read(char *dest, int len) {
  return nd_mouse_read_helper(dest, len, 0);
}

static int nd_mouse_peek(char *dest, int len) {
  return nd_mouse_read_helper(dest, len, 1);
}

static int nd_mouse_send_packet(const char *src, int len) {
  // Based on Xorg ps2SendPacket
  int i, j;
  unsigned char c;

  for (i = 0; i < len; i++) {
    for (j = 0; j < 10; j++) {
      mousedev_write(src + i, 1);
      mouse_delay();
      if (nd_mouse_read(&c, 1) != 1) {
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

// mouse_parse is not smart enough to detect synchronization / overflow errors!

// Returns true if successfully parsed a packet
static int mouse_parse(struct MouseEvent *mevent) {
 resync_retry: ;
  int num_bytes;
  unsigned char pBuf[4];
  unsigned char data2[4]; // separate scratch buffer for second read for sanity check

  enum MouseProto proto = global_protocol;
  const unsigned char *protoPara = proto_params[proto];
  assert(proto >= 0 && proto < MPROT_LAST);
  int packet_len = protoPara[4];

  memset(mevent, 0, sizeof(*mevent));
  int buttons = 0;
  short dx = 0, dy = 0, dz = 0;

  assert(packet_len <= sizeof(pBuf));

  // Try to read the packet size needed by this protocol
  num_bytes = nd_mouse_peek(pBuf, packet_len);
  if (num_bytes < packet_len)
    return 0;  // not enough scancodes waiting for full packet

  // Resynchronize. Note that this is useless if the protocol is wrong!
  if((pBuf[0] & protoPara[0]) != protoPara[1]) {
    MOUSE_DEBUG("mouse sync lost!");
    // consume a byte, try again
    nd_mouse_read(data2, 1);
    goto resync_retry;
  }
  // Consume these packets
  num_bytes = nd_mouse_read(data2, packet_len);
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
      proto = global_protocol = NEW_PROTO;			\
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

int nd_GetDeviceID()
{
    unsigned char u;
    unsigned char packet[] = { 0xf2 };

    mouse_delay();
    if (nd_mouse_send_packet(packet, sizeof(packet)) != 0) 
      return -1;
    while (1) {
      if (!nd_mouse_read(&u, 1))
	return -1;
      if (u != 0xFA)
	break;
    }
    return (int) u;
}

