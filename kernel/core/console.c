/** NexusOS: Console */

#include <nexus/defs.h>
#include <nexus/device.h>
#include <nexus/queue.h>
#include <nexus/screen.h>
#include <nexus/kbd.h>
#include <nexus/user_compat.h>

/// currently active console
struct nxconsole *console_active;

/// queue of all open consoles
static Queue console_queue = QUEUE_EMPTY;

//// callback implementations

/// blocking read
static int
foreground_in(struct nxconsole *console, char *buf, int len)
{
	if (!console->keyboard)
		return -1;

	return consolebuf_read(console->keyboard, buf, len);
}

static int
foreground_out(struct nxconsole *console, const char *data, int len)
{
	return screen_print(console, data, len);
}

static int
foreground_err(struct nxconsole *console, const char *data, int len)
{
	return printk_red("%s\n", data);
}

static int
foreground_poll(struct nxconsole *console)
{
	return consolebuf_poll(console->keyboard);
}

static int 
foreground_mouse_read(struct nxconsole *console, struct MouseEvent *dest)
{
	if (!console->mouse_port)
		console->mouse_port = IPC_CreatePort(0);

	return IPC_Recv(console->mouse_port, dest, sizeof(struct MouseEvent)) / sizeof(struct MouseEvent);
}

//// create/delete/set console

/** Switch focus */
void 
console_set(struct nxconsole *console) 
{
	int intlevel;
	
	intlevel = disable_intr();
	
	if (console_active != console) {
		console_active = console;
		screen_refresh();
	}

	restore_intr(intlevel);
}

static struct nxconsole *
console_new(void)
{
	static int count;
	struct nxconsole *console;
	
	console = gcalloc(1, sizeof(*console));
	console->id = count++;
	
	return console;
}

/** Create a new virtual terminal */
struct nxconsole *
console_new_foreground(const char *name, const char *sha1, int input, int output)
{
	struct nxconsole *console;
	int lvl;

	console = console_new();

	// attach input
	if (input)
		console->keyboard = consolebuf_new();

	// attach output
	if (output)
		console->screen = screen_init(console->id, name, sha1);


	// attach callbacks (frontend interface)
	console->in   = foreground_in;
	console->out  = foreground_out;
	console->err  = foreground_err;
	console->poll = foreground_poll;

	console->mouse_read = foreground_mouse_read;

	// add to console queue
	lvl = disable_intr();
	queue_append(&console_queue, console);
	restore_intr(lvl);

	return console;
}

////  Console queue (all open pseudo terminals)

/** Switch focus to the right 
    @param ignored, because it is started as a separate thread */
void 
console_right(void *ignored) 
{
	struct nxconsole *console;
	
	// get next console (optionally wrap)
	console = queue_getnext(console_active);
	if (!console) 
		console = queue_gethead(&console_queue);

	if (console && console != console_active)
		console_set(console);
}

/** Switch focus to the left */
void 
console_left(void *ignored) 
{
	struct nxconsole *console, *alt;

	console = queue_getprev(console_active);
	if (!console) {
	  // Go to the tail of the queue
	  alt = queue_gethead(&console_queue);
	  assert(alt);
	  while (alt) {
	    console = alt;
	    alt = queue_getnext(alt);
	  }
	}
	
	if (console && console != console_active)
		console_set(console);
}

