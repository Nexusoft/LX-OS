// linux/kernel/printk.c Copyright (C) 1991, 1992  Linus Torvalds
//
// wrapper for underlying keyboard devices, implements nexus kbd abstraction

#include <nexus/defs.h>
#include <nexus/ipd.h>
#include <nexus/device.h>
#include <nexus/kbd.h>
#include <nexus/thread.h>
#include <nexus/synch-inline.h>

#ifdef __NEXUSXEN__
#include <xen/xen.h>
#endif

#define KBD_LINE_SIZE 256

typedef struct KbdBuf {
	KbdMode mode;
	BasicThread *xen_irq_thread;

	int cur;
	Sema *sema;
	Sema *mutex;
	int available_line;
	char kbdbuf[KBD_LINE_SIZE];

	struct kbd_drv_context *ctx;
} KbdBuf;

static void kbd_init(NexusOpenDevice *nod, KbdMode mode);

int kbd_setmode(NexusOpenDevice *nod, KbdMode mode) {
	switch(mode) {
	case KBD_COOKED:
	case KBD_RARE:
	case KBD_RAW:
		kbd_init(nod, mode);
		return 0;
	default:
		printk_red("kbd_setmode(): unknown mode %d\n", mode);
		return -1;
	}
}

void kbd_set_xen_irq_thread(NexusOpenDevice *nod, BasicThread *t) {
	struct KbdBuf *kb = nod->odata;
	kb->xen_irq_thread = t;
}

KbdMode kbd_getmode(NexusOpenDevice *nod) {
	struct KbdBuf *kb = nod->odata;
	return kb->mode;
}

void kbd_getdata(NexusOpenDevice *nod, int *size, char *dest) {
	struct KbdBuf *kb = nod->odata;
	int blocking = kb->mode == KBD_COOKED;
	int line_oriented = kb->mode == KBD_COOKED;
	assert(*size > 0);

	if(blocking) {
		P(kb->sema);
	}
// XXX COOKED is broken: It simply grabs as much data as available,
// without regard to how many lines have been input since the last
// getline call. Subsequent calls will return partial lines, or
// nothing, instead of blocking.

	P(kb->mutex);
	int end = min(*size, kb->cur);
	int residue = kb->cur - end;
	if(line_oriented) {
		// Check to see if we will consume the full line
		if(end == kb->cur) {
			kb->available_line--;
		} else {
			// We haven't consumed the full line
			V(kb->sema);
		}
	}
	memcpy(dest, kb->kbdbuf, end);
	int i;
	for(i=0; i < residue; i++) {
		kb->kbdbuf[i] = kb->kbdbuf[end + i];
	}
	kb->cur = residue;
	V(kb->mutex);

	*size = end;
}

static void add_linebuff(NexusOpenDevice *nod, char ch) {
	struct KbdBuf *kb = nod->odata;
	int do_echo = kbd_getmode(nod) == KBD_COOKED;
	int signal_lines = kbd_getmode(nod) == KBD_COOKED;

	if(do_echo) {
		printk_user(nod->ipd, "%c", ch);
	}

	P(kb->mutex);
	assert(kb->cur <= (KBD_LINE_SIZE-1));
	if (kb->cur == (KBD_LINE_SIZE-1)) {
		printk_red("KBD: overflow in keyboard line buffer");
		//kb->cur = 0; // clear buffer ?
		V(kb->mutex);
		return;
	}

	kb->kbdbuf[kb->cur++]= ch;

	if(signal_lines) {
		if (ch == '\n'){
			kb->available_line++;		
			V(kb->sema);
		}
	}

	V(kb->mutex);
}

static void sub_linebuff(NexusOpenDevice *nod) {
	assert(kbd_getmode(nod) == KBD_COOKED);

	struct KbdBuf *kb = nod->odata;
	P(kb->mutex);
	if(kb->cur > 0 && kb->kbdbuf[kb->cur-1] != '\n') {
		kb->kbdbuf[--kb->cur]= '\0';
		print_backspace(nod->ipd);
	}
	V(kb->mutex);
}

static void kbd_process_input(NexusOpenDevice *nod, char ch) {
	struct KbdBuf *kb = nod->odata;
	//printk_color(0xaa772200, "(%d)", (int)ch);
	switch(kbd_getmode(nod)) {
	case KBD_COOKED:
		switch (ch) {
		case 127: /* backspace */
			sub_linebuff(nod);
			break;
		case '\r': /* turn into '\n' */
			add_linebuff(nod, '\n');
			break;
		default:
			add_linebuff(nod, ch);
			break;
		}
		break;
	case KBD_RAW:
	case KBD_RARE:
		// No additional character translation
		add_linebuff(nod, ch);
		break;
	default:
		printk_red("Unknown kb mode %d\n", 
			   kbd_getmode(nod));
		nexuspanic();
	}
#ifdef __NEXUSXEN__
	if(kb->xen_irq_thread != NULL) {
		thread_Xen_sendVIRQ(kb->xen_irq_thread,
				    VIRQ_CONSOLE);
	}
#endif
}

static int kbd_thread_helper(void *arg) {
	NexusDevice *nd = arg;
	struct device_keyboard_ops *ops = nd->data;
	for (;;) {
		KBD_Data data = ops->getch();
		IPD *ipd = focus_current_ipd();
		if (ipd == NULL) continue;
		NexusOpenDevice *nod = ipd_get_open_device(ipd, DEVICE_KEYBOARD, -1);
		if (!nod) continue;

		if(data.ipd != ipd) {
			// drop this on the floor, since the driver
			// used the translation mode in effect for the
			// old IPD
			continue;
		}
		kbd_process_input(nod, data.code);
	}

	// not reached
	return -1;
}

void kbd_start(NexusDevice *nd) {
	assert(nd->type == DEVICE_KEYBOARD);
	nexusthread_fork(kbd_thread_helper, nd);
}

int kbd_hasline(NexusOpenDevice *nod) {
	struct KbdBuf *kb = nod->odata;
	if(kbd_getmode(nod) != KBD_COOKED) {
		return kb->cur > 0;
	}

	int ret = 0;
	if(kb == NULL) {
		printk_red("kb is null");
	}
	P(kb->mutex);
	ret = kb->available_line;
	V(kb->mutex);
	return ret;
}

int kbd_hasdata(NexusOpenDevice *nod) {
	struct KbdBuf *kb = nod->odata;
	return kb->cur > 0;
}

static void kbd_focus_cleanup(NexusOpenDevice *nod) {
	if(kbd_getmode(nod) == KBD_RAW) {
		// alt release
		add_linebuff(nod, 0x80 | 0x38);
		// tab release
		add_linebuff(nod, 0x80 | 0x0f);
	}
}

NexusOpenDevice *kbd_new(NexusDevice *nd, IPD *ipd) {
	assert(nd->type == DEVICE_KEYBOARD);
	KbdBuf *kb = galloc(sizeof(KbdBuf));
	memset(kb, 0, sizeof(KbdBuf));
	kb->sema = sema_new();
	kb->mutex = sema_new();
	kb->xen_irq_thread = NULL;
	sema_initialize(kb->mutex, 1);

	NexusOpenDevice *nod = nexus_open_device(nd, kb);
	kb->ctx = kbd_drv_context_new();
	kbd_init(nod, KBD_COOKED);
	return nod;
}

static void kbd_init(NexusOpenDevice *nod, KbdMode mode) {
	struct KbdBuf *kb = nod->odata;
	kb->mode = mode;
	int num_awakened = sema_reinitialize(kb->sema, 0);
	if(num_awakened > 0) {
		printk_red("warning: kbd reinitialize (possibly due to mode switch) woke up %d keyboard waiters\n",
			   num_awakened);
	}
	kb->available_line = 0;
	kb->cur = 0;
	kbd_drv_context_change_mode(kb->ctx, 
				    nod->focused, mode);
}

void nexus_kbd_focus(NexusOpenDevice *nod, int focus) {
	struct KbdBuf *kb = nod->odata;
	if(focus) {
		kbd_drv_context_restore(kb->ctx);
		kbd_focus_cleanup(nod);
	} else {
		kbd_drv_context_save(kb->ctx);
		kbd_focus_cleanup(nod);
	}
}

