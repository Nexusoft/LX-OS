/** NexusOS: device and console device kernel infrastructure */

#ifndef __NEXUS_DEVICE_H__
#define __NEXUS_DEVICE_H__

#include <nexus/defs.h>
#include <nexus/mem.h>
#include <nexus/synch.h>
#include <nexus/thread.h>
#include <nexus/machineprimitives.h>
#include <nexus/udevice.h>
#include <nexus/mouse.h>
#include <nexus/keyboard.h>
#include <nexus/fb.h>
#include <nexus/ipc.h>
#include <nexus/pci.h>

#define IRQ_NONE (-1)

struct device_video_ops {
	void (*putc)(int c, int ypos, int xpos);
	void (*clear)(void);
	int (*blit)(unsigned int width, unsigned int height, unsigned char *data);
	int (*blit_native)(unsigned int width, unsigned int height, unsigned char *data);

	int (*get_geometry)(struct FB_Info *info);
};

enum nexusdriver_domain {DRIVER_KERNEL, DRIVER_USER};

/** Register IRQ handler. Called automatically by nexus_register_device */
int  nxirq_get(int irq, int (*func)(void *), void *arg);
void nxirq_put(int irq);
void nxirq_done(int irq);
void nxirq_wait(int irq, int ack);
int  nxirq_wake(void *unused);

void nxirq_init(void);

/** Lookup registered irq handler and deliver interrupt.
    @return whether or not preemption is needed to deal with irq */
void nxirq_handle(int irq);


////////  console multiplexing

void kbd_start(void);

#define KBD_LINE_SIZE 256
struct nxconsolebuf {
	KbdMode mode;

	Sema sema;	///< block until a full line is ready (cooked mode)
	Sema mutex;
	
	int cur;	///< offset in buffer
	int lines;	///< number of \n's in buffer
	char buf[KBD_LINE_SIZE];
};

struct nxconsole {
  	QItem _link; // for console_queue

	int id;
	int foreground;	// boolean

	// interface
	int (*in)(struct nxconsole *console, char *buf, int len);
	int (*out)(struct nxconsole *console, const char *data, int len);
	int (*err)(struct nxconsole *console, const char *data, int len);

	int (*poll)(struct nxconsole *console);	///< data waiting on in?
	
	int (*mouse_read)(struct nxconsole *console, struct MouseEvent *dest);
	int mouse_port;

	// implementation for foreground tasks
	void *screen;
	struct nxconsolebuf *keyboard;

	// XXX support background tasks 
};

extern struct nxconsole *console_active;

struct nxconsole *console_new_foreground(const char *name, const char *sha1, 
					 int input, int output);

void console_right(void *);
void console_left(void *);
void console_set(struct nxconsole *console);


////////  console buffer

struct nxconsolebuf *consolebuf_new(void);
int consolebuf_read(struct nxconsolebuf *kb, char *dest, int size);
int consolebuf_setmode(struct nxconsolebuf *kb, KbdMode mode);
int consolebuf_poll(struct nxconsolebuf *kb);

#endif

