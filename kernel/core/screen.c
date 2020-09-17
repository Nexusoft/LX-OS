/** NexusOS: a text console 
    enables line-by-line textual output

    combines a linux framebuffer (nxframebuffer_ops) with terminal history 
    derived from linux/kernel/printk.c	
 */

#include <nexus/defs.h>
#include <nexus/ipd.h>
#include <nexus/device.h>
#include <nexus/screen.h>
#include <nexus/thread-inline.h>

#define CONSWIDTH  128
#define CONSHEIGHT 48
#define NUM_TOPLINES (2)
#define TOPLINE (CONSWIDTH * NUM_TOPLINES)

#define NUMSCROLLSCREENS 40
#define SCROLLBUFSIZE (CONSWIDTH * CONSHEIGHT * NUMSCROLLSCREENS)

struct device_video_ops nxframebuffer_ops;

// multiline text buffer
struct nxframebuffer {
	unsigned int topbar[TOPLINE];
	int realx;
	unsigned int scrollbuffer[SCROLLBUFSIZE];
	int  scrollptr; /* index of latest char in scrollbuffer */
	unsigned int handle;
};

static int *colorize(int *dest, char *src, int color) {
	while (*src)
		*(dest++) = *(src++) | color;
	return dest;
}

/** Overdraw a red line between the kernel and app portions of the screen */
void
screen_redrawline(void)
{
	const int BRIGHT_MIN = 96;
	const int BRIGHT_MAX = 255;
	const int LINE_HEIGHT = 4;
	const int GRADIENT_SPEED = 1;
	static int bright_max;

	struct FB_Info info;
	char linecolor[4];
	char *redline_start, *curline_start;
	int i, j, cpuload;
#ifdef DO_HEARTBEAT
	int heartrate, heartrate_hz;
#endif
    	int pixel_off, pixel_size = 0;
    	int brightlen, bright_off;
	
	nxframebuffer_ops.get_geometry(&info);
	
	// calculate color
	// brightness fluctuates between 50 and 100% depending on CPU load
	cpuload = nexusthread_cpuload();
	if (cpuload >= 75) // increase (up to maximum)
		bright_max = min(info.bpp == 16 ? 0xe0 : 0xff, bright_max + 1);
	else if (cpuload < 25) // decrease (down to a minimum)
		bright_max = max(BRIGHT_MIN + 50, bright_max - 1);

	// length of brighest part
	brightlen = (info.xres * bright_max) / BRIGHT_MAX;
	brightlen >>= 2; // maximum of brightest is 25% of screen width
	bright_off = (info.xres - brightlen) / 2;

#ifdef DO_HEARTBEAT
	// periodic heartbeat (varies with load)
	heartrate = 50 + cpuload;
	heartrate_hz = (100 * HZ) / heartrate;
	if (!(nexustime % heartrate_hz))
		bright_max = min(BRIGHT_MAX, bright_max * 2);
#endif

	// set bpp
	pixel_size = info.bpp >> 3;
#ifdef RED_BAR
	pixel_off = (info.bpp == 16) ? 1 : 2; // byte that selects color
#else /* BLUE BAR */
	pixel_off = (info.bpp == 16) ? 0 : 0; // byte that selects color
#endif

    	// fill in color
	memset(linecolor, 0, sizeof(linecolor));

	// calculate geometry
 	redline_start = info.fb + 
	                ((NUM_TOPLINES * info.fontheight) - LINE_HEIGHT) * info.line_length;

	// for each vertical line
	for (i = 0; i < LINE_HEIGHT; i++) {
		curline_start = redline_start + i * info.line_length;
	  
	  	// for each horizontal pixel
		for (j = 0; j < info.xres; j++) {
			int max_off;	// offset in pixels from max.bright region
			int color;

			// calculate distance from region with maximal brightness:
			// to get color gradient
			if (j < bright_off)
			    max_off = bright_off - j;
			else if (j > bright_off + brightlen)
			    max_off = j - bright_off - brightlen;
			else
			    max_off = 0;

			linecolor[pixel_off] = max(BRIGHT_MIN, bright_max - (max_off >> GRADIENT_SPEED));
			memcpy(curline_start + (j * pixel_size), linecolor, pixel_size);
      		}
	}
}

// redraw the entire screen (used on console switch)
void 
screen_refresh(void) 
{
	struct nxframebuffer *sb = console_active->screen;
	int i, firstline;

	// clear screen
	nxframebuffer_ops.clear();

	// rewrite portion above line
	for (i = 0; i < TOPLINE; i++)
		nxframebuffer_ops.putc(sb->topbar[i], i / CONSWIDTH, i % CONSWIDTH);
	
	// rewrite portion below line
	firstline = (SCROLLBUFSIZE + sb->scrollptr - sb->realx) % SCROLLBUFSIZE;
	
	for(i = TOPLINE; i < CONSHEIGHT * CONSWIDTH; i++){
		if (i >= sb->realx) 
			nxframebuffer_ops.putc(' ', i / CONSWIDTH, i % CONSWIDTH);
		else 
			nxframebuffer_ops.putc(sb->scrollbuffer[(firstline + i) % SCROLLBUFSIZE],
				i / CONSWIDTH, i % CONSWIDTH);
	}

	// redraw line
	screen_redrawline();
}

// instantiate a screen using a framebuffer device
void *
screen_init(int console_id, const char *name, const char *sha1) 
{
	struct nxframebuffer *sb;
	char buf[100];
	int len, i;
	
	// print name and console number
	len = snprintf(buf, 99, "[%d] %s", console_id, name);
	buf[len] = 0;
	
	sb = gcalloc(1, sizeof(*sb));
	colorize(sb->topbar + CONSWIDTH - len, buf, BLUE);
	sb->realx = TOPLINE;

	// print sha1
	if (sha1) {
		for (i = 0; i < 20; i++)
			sprintf(buf + (i * 2), "%02x", sha1[i] & 0xff);
		buf[40] = 0;
		colorize(sb->topbar, buf, BLUE);
	}

	return sb;
}

static void scroll(struct nxconsole *console) {
	struct nxframebuffer *sb = console->screen;
	int i;

	int firstline = (SCROLLBUFSIZE + sb->scrollptr - ((CONSHEIGHT - 1) *CONSWIDTH)) % SCROLLBUFSIZE;
	for(i = TOPLINE; i < CONSHEIGHT * CONSWIDTH; i++){
		if(i >= (CONSHEIGHT - 1) * CONSWIDTH)
			sb->scrollbuffer[(firstline + i) % SCROLLBUFSIZE] = ' ';
		if (console == console_active)
			nxframebuffer_ops.putc(sb->scrollbuffer[(firstline + i) % SCROLLBUFSIZE],
					i / CONSWIDTH, i % CONSWIDTH);
	}

	sb->realx -= CONSWIDTH;  
}

static void newline(struct nxconsole *console) {
	struct nxframebuffer *sb = console->screen;
	int addedspace = CONSWIDTH - (sb->realx % CONSWIDTH); 

	sb->realx += addedspace;
	sb->scrollptr = (SCROLLBUFSIZE + sb->scrollptr + addedspace) % SCROLLBUFSIZE; 

	if (sb->realx/CONSWIDTH >= CONSHEIGHT) scroll(console);
}

static void cursorinc(struct nxconsole *console) {
	struct nxframebuffer *sb = console->screen;
	sb->realx++;
	sb->scrollptr = (sb->scrollptr + 1) % SCROLLBUFSIZE;

	if (sb->realx % CONSWIDTH == CONSWIDTH - 1) newline(console);
}

static void cursordec(struct nxframebuffer *sb) {
	sb->realx--;
	sb->scrollptr = (SCROLLBUFSIZE + sb->scrollptr - 1) % SCROLLBUFSIZE;
    	sb->scrollbuffer[sb->scrollptr]= ' ';
}

static void carriagereturn(struct nxframebuffer *sb) {
	sb->realx -= sb->realx % CONSWIDTH;
	sb->scrollptr = (SCROLLBUFSIZE + sb->scrollptr - (sb->scrollptr % CONSWIDTH)) % SCROLLBUFSIZE;
}

void screen_backspace(struct nxconsole *console) {
	struct nxframebuffer *sb = console->screen;

	cursordec(sb);
	if (console == console_active)
		nxframebuffer_ops.putc(' ', (sb->realx + 1)/CONSWIDTH, sb->realx % CONSWIDTH);
}

static void __screen_putc(struct nxconsole *console, int cc) {
	struct nxframebuffer *sb = console->screen;

	switch ((char)(cc & 0xff)) {
		case '\r':
			carriagereturn(sb);
			break;
		case '\n':
			newline(console);
			break;
		default:
			sb->scrollbuffer[sb->scrollptr] = cc;
			if (console == console_active)
				nxframebuffer_ops.putc(cc, (sb->realx + 1)/CONSWIDTH, sb->realx % CONSWIDTH);
			cursorinc(console);
	}
}

static inline int
__screen_print(struct nxconsole *console, const char *string, int len, 
	       unsigned int color)
{
	int intlevel, i;

	intlevel = disable_intr();
	for (i = 0; i < len; i++)
		__screen_putc(console, string[i] | (color & 0xffffff00) ); 
	restore_intr(intlevel);

	return len;
}

int 
screen_print(struct nxconsole *console, const char *string, int len)
{
	if (len < 0)
		return -1;

	return __screen_print(console, string, len, WHITE);
}

int 
screen_printf(struct nxconsole *console, const char *fmt, va_list args, 
	      unsigned int color) 
{
	char print_buf[1024];
	int len;

    	len = vsnprintf(print_buf, sizeof(print_buf), fmt, args);
	__screen_print(console, print_buf, len, color);
	return len;
}

int 
screen_blit(struct nxconsole *console, unsigned int width, unsigned int height,
	    unsigned char *data) 
{
	if (console != console_active) 
		return 0;
	nxframebuffer_ops.blit(width, height, data);
	return 0;
}

