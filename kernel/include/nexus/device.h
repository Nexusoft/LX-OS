#ifndef __NEXUS_DEVICE_H__
#define __NEXUS_DEVICE_H__

#include <nexus/defs.h>
#include <nexus/mem.h>
#include <nexus/synch.h>
#include <nexus/thread.h>
#include <nexus/machineprimitives.h>
#include <nexus/udevice.h>
#include <nexus/fb.h>
#include <nexus/ipc.h>

#define IRQ_NONE (-1)

struct device_audio_ops {
  ssize_t (*read) (char *, size_t, loff_t *);
  ssize_t (*write) (const char *, size_t, loff_t *);
  int (*setrate) (int);
  int (*ioctl)(unsigned int cmd, unsigned long arg, Map *m);  
  void (*set_current_audio_buf)(void *a);
  void (*unset_current_audio_buf)(void);
  //int (*open) (struct inode *, struct file *);
  void *priv; 
};

struct device_video_ops {
	void (*putc)(int c, int ypos, int xpos);
	void (*clear)(void);
	int (*blit)(unsigned int width, unsigned int height, unsigned char *data);
	int (*blit_native)(unsigned int width, unsigned int height, unsigned char *data);

	int (*get_geometry)(struct FB_Info *info);
};

struct KBD_Data {
  IPD *ipd; // the active IPD that the top half (interrupt context) queued it for
  int code; // actual code
};

struct device_keyboard_ops {
	KBD_Data (*getch)(void);
};

#define MOUSE_RAW_DATA_LEN (2048)
struct device_mouse_ops {
	int (*write)(NexusDevice *nd, const char *data, int length);

	int protocol;
	// Circular queue of raw, uninterpreted data
	int head, tail; // tail >= head % MOUSE_RAW_DATA_LEN
	int curr_packet; // position of current packet;
	unsigned char raw_data[MOUSE_RAW_DATA_LEN];
};

int nexusdevice_is_user(NexusDevice *nd);

struct device_tpm_ops {
  int (*open) (void *, void *);
  ssize_t (*read) (void *, char *, size_t, loff_t *);
  ssize_t (*write) (void *, const char *, size_t, loff_t *);
  int (*ioctl) (void *, void *, unsigned int, unsigned long);
  int (*release) (void *, void *);
  void (*shutdown) (void);
};

typedef void (*focus_handler_t)(NexusOpenDevice *nod, int focus);
typedef int (*interrupt_handler_t)(int irq, NexusDevice *nd);

enum nexusdriver_domain {DRIVER_KERNEL, DRIVER_USER};

/* maintains per-device state, including data for the driver */
struct NexusDevice {
	QItem _link;

	int type;
  	enum nexusdriver_domain domain;
	const char *name;
	int irq;
	void *data; /* device-type specific: typically one of the struct *_ops from above */

	focus_handler_t focus_handler;	///< handler to change the console focus
	interrupt_handler_t interrupt_handler;
};

/* maintains per-instance state, such as playback buffers, etc. */
struct NexusOpenDevice {
	QItem _link;

	NexusDevice *nd;
	void *odata;
	IPD *ipd;
	int focused;
};

void dump_devices(void); // debugging

NexusDevice *nexus_register_device(int dt, char *name, int irq, void *data,
				   interrupt_handler_t interrupt_handler, 
				   focus_handler_t focus_handler, 
				   enum nexusdriver_domain domain);

NexusOpenDevice *nexus_open_device(NexusDevice *nd, void *odata);

void nexus_unregister_device(NexusDevice *nd);

NexusDevice *find_device(int dt, char *name);

void focus(IPD *ipd);
IPD *focus_current_ipd(void);
IPD *focus_current_ipd_special(void);
int is_focused(IPD *ipd);
void focus_next(void *ignored);
void focus_prev(void *ignored);
void add_focus(IPD *ipd);
void set_focus(NexusOpenDevice *nod);

/* return whether or not preemption is needed to deal with irq */
int deliver_irq(int irq);

#define IRQ_ENABLE 1
#define IRQ_DISABLE 0
#define IRQ_NOCHANGE -1
void set_user_interrupts(int irqcap, IPD *ipd, int user_irq_flag, int phys_irq_flag);
#define enable_user_enable_irq(a,b) set_user_interrupts(a,b,IRQ_ENABLE,IRQ_ENABLE)
#define enable_user_disable_irq(a,b) set_user_interrupts(a,b,IRQ_ENABLE,IRQ_DISABLE)
#define disable_user_enable_irq(a,b) set_user_interrupts(a,b,IRQ_DISABLE,IRQ_ENABLE)
#define disable_user_disable_irq(a,b) set_user_interrupts(a,b,IRQ_DISABLE,IRQ_DISABLE)
#define disable_user_intrs(a,b) set_user_interrupts(a,b,IRQ_DISABLE,IRQ_NOCHANGE)
#define enable_user_intrs(a,b) set_user_interrupts(a,b,IRQ_ENABLE,IRQ_NOCHANGE)

void netpoll(void *dev); // ???

extern int dbg_udriver;

/* These functions keep track of when to re-enable an irq line.
   irq_done should be called instead of enable_irq. */
void irq_dispatch(int irq);
void irq_done(int irq);

#endif
