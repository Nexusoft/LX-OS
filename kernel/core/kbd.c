/** NexusOS: console buffer: a circular buffer that returns data in either 
                             character oriented RAW or
			     line oriented COOKED mode 
 */

#include <nexus/defs.h>
#include <nexus/ipd.h>
#include <nexus/user_compat.h>
#include <nexus/device.h>
#include <nexus/kbd.h>
#include <nexus/thread.h>
#include <nexus/synch-inline.h>
#include <nexus/syscall-defs.h>

static void 
consolebuf_reset(struct nxconsolebuf *kb, KbdMode mode) 
{
	kb->mode = mode;
	kb->lines = 0;
	kb->cur = 0;
}

struct nxconsolebuf *
consolebuf_new(void) 
{
	struct nxconsolebuf *kb;
	
	kb = gcalloc(1, sizeof(*kb));
	kb->sema = SEMA_INIT_KILLABLE;
	kb->mutex = SEMA_MUTEX_INIT;

	consolebuf_reset(kb, KBD_COOKED);
	return kb;
}

int 
consolebuf_setmode(struct nxconsolebuf *console, KbdMode mode) 
{
	switch (mode) {
		case KBD_COOKED:
		case KBD_RARE:
		case KBD_RAW:	consolebuf_reset(console, mode);
				return 0;
	}
			
	printk_red("[kbd] unknown mode %d\n", mode);
	return -1;
}

static void 
consolebuf_addline(struct nxconsolebuf *console, char ch) 
{
	// BUG workaround: shift+space can issue a \0 (XXX fix)
	if (ch == 0) 
		return;

	// handle overflow
	if (console->cur == KBD_LINE_SIZE - 1) {
		printk_red("[kbd] overflow\n");
		return;
	}
	
	// echo output
	if (console->mode == KBD_COOKED)
		printk_current("%c", ch);

	// add element
	P(&console->mutex);
	console->buf[console->cur++] = ch;

	// account for number of lines
	if (console->mode == KBD_COOKED) {
		if (ch == '\n') {
			console->lines++;		
			V(&console->sema);
		}
	}

	V(&console->mutex);
}

/** Remove last written character in current line in buffer (if any) */
static void 
consolebuf_subline(struct nxconsolebuf *console) 
{
	P(&console->mutex);
	if (console->cur > 0 && console->buf[console->cur - 1] != '\n') {
		console->buf[--console->cur]= 0;
		print_backspace();
	}
	V(&console->mutex);
}

/** Add a character to the buffer (or remove if backspace) */
static void 
consolebuf_append(struct nxconsolebuf *console, char ch) 
{
	switch (console->mode) {
	case KBD_COOKED:
		switch (ch) {
		case 127 : 	consolebuf_subline(console); break; /* backspace */
		case '\r':	consolebuf_addline(console, '\n'); break; /* convert to '\n' */
		default:	consolebuf_addline(console, ch); break;
		}
		break;
	case KBD_RAW:
	case KBD_RARE:
		consolebuf_addline(console, ch);
		break;
	default:
		nexuspanic();
	}
}

/** Read from console at most size bytes */
int 
consolebuf_read(struct nxconsolebuf *console, char *dest, int size) 
{
	int i, len;

	if (size <= 0)
		return 0;

	// wait until a full line is ready
	if (console->mode == KBD_COOKED)
		P(&console->sema);
	
	P(&console->mutex);
	if (console->mode == KBD_COOKED) {
		
		// search to endline or end of either buffer
		for (len = 0; len < size && len < console->cur; len++)
			if (console->buf[len] == '\n')
				break;

		// Check to see if we will consume the full line
		if (console->buf[len] == '\n') {
			console->lines--;
			len += 1; 
		}
		else
			// We haven't consumed the full line
			// don't block on next read
			V(&console->sema);
	}
	else {
		len = min(size, console->cur);
	}

	// transfer data
	// XXX use circular buffer to avoid 2nd copy
	if (len) {
		memcpy(dest, console->buf, len);
		memcpy(console->buf, console->buf + len, len);
		console->cur -= len;
	}
	
	V(&console->mutex);
	return len;
}

/** Return 1 if .._read will return without blocking or 0 otherwise */
int 
consolebuf_poll(struct nxconsolebuf *kb) 
{
	if (kb->mode == KBD_COOKED)
		return kb->lines ? 1 : 0;
	else
		return kb->cur > 0 ? 1 : 0;
}

////////  Keyboard specific user of consolebuf  ////////
//
// Nexus currently only supports one keyboard buffer
// all keyboards write to default_keyboard_port

/** Thread that blocks on input from keyboard driver */
static int 
kbd_thread(void *arg) 
{
	char character;
	int intlevel;

	// open port to which keyboard drivers write
	if (IPC_CreatePort(default_keyboard_port) != default_keyboard_port)
		nexuspanic();
	
	while (1) {

		// read a character
		if (IPC_Recv(default_keyboard_port, &character, 1) != 1) {
			printk("DEBUG: console rx failed\n");
			continue;
		}
		
		// forward to active console (if it allows input)
		if (console_active->keyboard)
			consolebuf_append(console_active->keyboard, character);
	}

	return -1;
}

static int 
mouse_thread(void *arg)
{
	struct MouseEvent *event;

	// open port to which mouse drivers write
	if (IPC_CreatePort(default_mouse_port) != default_mouse_port)
		nexuspanic();

	while (1) {
		event = gcalloc(1, sizeof(*event));

		// read a character
		if (IPC_Recv(default_mouse_port, event, sizeof(*event)) != sizeof(*event)) {
			printk("DEBUG: console rx failed\n");
			continue;
		}
		
		// forward to active console (if it allows input)
		if (console_active->mouse_port)
			IPC_Send(console_active->mouse_port, event, sizeof(*event));
	}

	return -1;
}

void 
kbd_start(void) 
{
	nexusthread_fork(kbd_thread, NULL);
	nexusthread_fork(mouse_thread, NULL);
}

