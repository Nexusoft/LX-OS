// linux/kernel/printk.c Copyright (C) 1991, 1992  Linus Torvalds
//
// wrapper for underlying video devices, implements nexus screen abstraction

#include <nexus/defs.h>
#include <nexus/ipd.h>
#include <nexus/device.h>
#include <nexus/screen.h>
#include <nexus/thread-inline.h>
#include <nexus/tftp.h>

#define CONSWIDTH  128
#define CONSHEIGHT 48
#define NUM_TOPLINES (2)
#define TOPLINE (CONSWIDTH * NUM_TOPLINES)

#define NUMSCROLLSCREENS 40
#define SCROLLBUFSIZE (CONSWIDTH * CONSHEIGHT * NUMSCROLLSCREENS)

struct ScreenBuf {
	unsigned int topbar[TOPLINE];
	int realx;
	unsigned int scrollbuffer[SCROLLBUFSIZE];
	int  scrollptr; /* index of latest char in scrollbuffer */
	IPD *ipd;
	unsigned int handle;
	int notext;
};

static int *colorize(int *dest, char *src, int color) {
	while (*src)
		*(dest++) = *(src++) | color;
	return dest;
}

static void screen_focus_handler(NexusOpenDevice *nod, int focus) {
	// Check to see if there is a mapped frame buffer. This may
	// involve remapping entries in the current map if it has a
	// frame buffer mapped in.

	// Note that we explicitly force unmap and map of fb regions.
	// This is faster and cleaner than blindly calling
	// Map_activate() to get the map / unmap side effects.

	// Checks here are very paranoid because this code has a nasty
	// tendency to cause crashes on boot or when switching to root
	// shell, where map, ipd, curt might be in limbo
	int ipd_mapped = 0;
	IPD *ipd = nod->ipd;
	Map *m = NULL;
	if (unlikely(ipd != NULL)) {
		m = ipd->map;
		if (ipd_hasMappedFB(ipd))
			ipd_mapped = 1;
	}

	// Save BEFORE clearing
	if(ipd_mapped && !focus) {
		ipd_fb_save(ipd);
		// Revoke old IPD's mappings
		ipd_fb_remap(ipd, Map_getRoot(m), FB_MAP_MEM);
	}
	// Now that the screen is saved, we can redraw
	if (!focus) {
		struct device_video_ops *ops = nod->nd->data;
		ops->clear();
	} else {
		// draw top bar, and possibly text
		screen_refresh(nod);
	}
	// Restore AFTER refresh / clear
	if(ipd_mapped && focus) {
		ipd_fb_restore(ipd);
		// Restore new IPD's mappings. Harmless if new map is not one with fb mapped in
		ipd_fb_remap(ipd, Map_getRoot(m), FB_MAP_VIDEO);
	}
}


static void screen_dump_helper(IPD *ipd, char *filename){
  ScreenBuf *sb = ipd->screenbuf;
  if(sb == NULL)
    return;
  char *outbuf = (char *)galloc(SCROLLBUFSIZE);	    
  int i, offset;
  
  for(i = 0; i < SCROLLBUFSIZE; i++){
    int ch = (sb->scrollptr + i) % SCROLLBUFSIZE;
    assert(ch < SCROLLBUFSIZE);
    outbuf[i] = (char)sb->scrollbuffer[ch] & 0xff;
    if(outbuf[i] == 0)
      outbuf[i] = ' ';
  }

  for(offset = 0; offset < SCROLLBUFSIZE; offset++)
    if(outbuf[offset] != ' ')
      break;


  send_file(filename, outbuf+offset, SCROLLBUFSIZE-offset);
  gfree(outbuf);
}

void screen_dump(void *voidipd, void *ignore){
  IPD *ipd = (IPD *)voidipd;
  char filename[14];
  sprintf(filename, "screen.ipd%03d",ipd->id);
  printk_red("dumping screen to %s\n", filename);
  screen_dump_helper(ipd, filename);
}

IRQEventQueue *screen_dump_queue;
int screen_dump_initialized = 0;
int screen_dump_thread(void *ignore){
  assert(check_intr() == 1);
  printk_red("screen dump thread started\n");
  while(1){
    irq_event_consume(screen_dump_queue);
    ipd_iterate(screen_dump, NULL);
  }
}




// instantiate a screen using a framebuffer device
NexusOpenDevice *screen_init(NexusDevice *nd, IPD *ipd) {
	assert(ipd);
	assert(nd->type == DEVICE_VIDEO);
	if (!nd->focus_handler)
		nd->focus_handler = screen_focus_handler;

	ScreenBuf *sb = galloc(sizeof(ScreenBuf));
	memset(sb, 0, sizeof(ScreenBuf));

	char buf[100];

	// ipd name second row right
	snprintf(buf, sizeof(buf)-1, "%s", (ipd != NULL) ? ipd->name : "(NULL)");
	buf[sizeof(buf)-1] = 0;
	colorize(sb->topbar+CONSWIDTH-strlen(buf)-1, buf, BLUE);

	sb->realx = TOPLINE;
	sb->ipd = ipd;
	ipd->screenbuf = sb;

	return nexus_open_device(nd, sb);
}

void screen_set_print_state(NexusOpenDevice *nod, int enable) {
	ScreenBuf *sb = (ScreenBuf *)nod->odata;
	sb->notext = enable;
	// Keep the text in the scroll buffer
	// memset(sb->scrollbuffer, 0, SCROLLBUFSIZE);
	screen_refresh(nod);
}

void screen_refresh(NexusOpenDevice *nod) {
	int i;
	ScreenBuf *sb = (ScreenBuf *)nod->odata;
	struct device_video_ops *ops = nod->nd->data;

	if (!nod->focused) return;

	ops->clear();

	for (i = 0; i < TOPLINE; i++)
		ops->putc(sb->topbar[i], i / CONSWIDTH, i % CONSWIDTH);

	if (!sb->notext) {
		int firstline = (SCROLLBUFSIZE + sb->scrollptr - sb->realx) % SCROLLBUFSIZE;
		for(i = TOPLINE; i < CONSHEIGHT * CONSWIDTH; i++){
			if(i >= sb->realx) ops->putc(' ', i / CONSWIDTH, i % CONSWIDTH);
			else ops->putc(sb->scrollbuffer[(firstline + i) % SCROLLBUFSIZE],
					i / CONSWIDTH, i % CONSWIDTH);
		}
	}

	// Overdraw a red line between the kernel and app portions of the screen
	struct FB_Info info;
	ops->get_geometry(&info);

	// Line is underline (- 1) of the last line
	int thickness = 4;
	char *redline_start = info.fb + 
	  (NUM_TOPLINES * info.fontheight - thickness) * info.line_length;

	char clear_data[4] = { 0xff,0xff,0xff,0xff };
	int pixel_size = 0;
	switch(info.bpp) {
	case 16:
	  clear_data[0] = 0x00;
	  clear_data[1] = 0xe0;
	  pixel_size = 2;
	  break;
	case 24:
	  clear_data[0] = 0x00;
	  clear_data[1] = 0x00;
	  clear_data[2] = 0xff;
	  clear_data[3] = 0x00;
	  pixel_size = 3;
	  break;
	case 32:
	  clear_data[0] = 0x00;
	  clear_data[1] = 0x00;
	  clear_data[2] = 0xff;
	  clear_data[3] = 0x00;
	  pixel_size = 4;
	  break;
	default:
	  for(;;);
	  printk_red("unsupported bpp %d\n", info.bpp);
	  nexuspanic();
	}
	assert(pixel_size > 0 && pixel_size <= sizeof(clear_data));

	for(i=0; i < thickness; i++) {
	  int j;
	  char *line_start = redline_start + i * info.line_length;
	  for(j=0; j < info.xres; j++) {
	    memcpy(line_start + j * pixel_size, clear_data, pixel_size);
	  }
	}
}

static void scroll(NexusOpenDevice *nod) {
	int i;
	ScreenBuf *sb = (ScreenBuf *)nod->odata;
	struct device_video_ops *ops = nod->nd->data;

	if (sb->notext) return;

	int firstline = (SCROLLBUFSIZE + sb->scrollptr - ((CONSHEIGHT - 1) *CONSWIDTH)) % SCROLLBUFSIZE;
	for(i = TOPLINE; i < CONSHEIGHT * CONSWIDTH; i++){
		if(i >= (CONSHEIGHT - 1) * CONSWIDTH)
			sb->scrollbuffer[(firstline + i) % SCROLLBUFSIZE] = ' ';
		if (nod->focused)
			ops->putc(sb->scrollbuffer[(firstline + i) % SCROLLBUFSIZE],
					i / CONSWIDTH, i % CONSWIDTH);
	}

	sb->realx -= CONSWIDTH;  
}

static void newline(NexusOpenDevice *nod) {
	ScreenBuf *sb = (ScreenBuf *)nod->odata;
	int addedspace = CONSWIDTH - (sb->realx % CONSWIDTH); 

	sb->realx += addedspace;
	sb->scrollptr = (SCROLLBUFSIZE + sb->scrollptr + addedspace) % SCROLLBUFSIZE; 

	if (sb->realx/CONSWIDTH >= CONSHEIGHT) scroll(nod);
}

static void cursorinc(NexusOpenDevice *nod) {
	ScreenBuf *sb = (ScreenBuf *)nod->odata;
	sb->realx++;
	sb->scrollptr = (sb->scrollptr + 1) % SCROLLBUFSIZE;

	if (sb->realx % CONSWIDTH == CONSWIDTH - 1) newline(nod);
}

static void cursordec(NexusOpenDevice *nod) {
	ScreenBuf *sb = (ScreenBuf *)nod->odata;
	sb->realx--;
	sb->scrollptr = (SCROLLBUFSIZE + sb->scrollptr - 1) % SCROLLBUFSIZE;
    sb->scrollbuffer[sb->scrollptr]= ' ';
}

static void carriagereturn(NexusOpenDevice *nod) {
	ScreenBuf *sb = (ScreenBuf *)nod->odata;
	sb->realx -= sb->realx % CONSWIDTH;
	sb->scrollptr = (SCROLLBUFSIZE + sb->scrollptr - (sb->scrollptr % CONSWIDTH)) % SCROLLBUFSIZE;
}

void screen_backspace(NexusOpenDevice *nod) {
	ScreenBuf *sb = (ScreenBuf *)nod->odata;
	struct device_video_ops *ops = nod->nd->data;

    if (sb->notext) return;
    cursordec(nod);
	if (nod->focused)
		ops->putc(' ', (sb->realx + 1)/CONSWIDTH, sb->realx % CONSWIDTH);
}

static void __screen_putc(NexusOpenDevice *nod, int cc) {
	ScreenBuf *sb = (ScreenBuf *)nod->odata;
	struct device_video_ops *ops = nod->nd->data;
	char c = (char)(cc & 0xff);
	switch (c) {
		case '\r':
			carriagereturn(nod);
			break;
		case '\n':
			newline(nod);
			break;
		default:
			sb->scrollbuffer[sb->scrollptr] = cc;
			if (nod->focused)
				ops->putc(cc, (sb->realx + 1)/CONSWIDTH, sb->realx % CONSWIDTH);
			cursorinc(nod);
	}
}

int screen_putc(NexusOpenDevice *nod, char c, unsigned int color) {
	ScreenBuf *sb = (ScreenBuf *)nod->odata;

	if (sb->notext) return 0;

	int intlevel = disable_intr();
	//if (intlevel) color = 0xaaaa0000; // special color for when interrupts were disabled
	__screen_putc(nod, c | (color & 0xffffff00));
	restore_intr(intlevel);
	return 0;
}

static inline int
__screen_print(NexusOpenDevice *nod, const char *string, int len, 
	       unsigned int color)
{
	int intlevel, i;

	intlevel = disable_intr();
	for (i = 0; i < len; i++)
		__screen_putc(nod, string[i] | (color & 0xffffff00) ); 
	restore_intr(intlevel);

	return len;
}

int 
screen_print(NexusOpenDevice *nod, const char *string, int len)
{
	ScreenBuf *sb = (ScreenBuf *)nod->odata;
	
	if (sb->notext) 
		return 0;
	
	if (len < 0)
		return -1;

	return __screen_print(nod, string, len, WHITE);
}

int 
screen_printf(NexusOpenDevice *nod, const char *fmt, va_list args, 
	      unsigned int color) 
{
	ScreenBuf *sb = (ScreenBuf *)nod->odata;
	char print_buf[1024];
	int len;

	if (sb->notext) 
		return 0;

    	len = vsnprintf(print_buf, sizeof(print_buf), fmt, args);
	__screen_print(nod, print_buf, len, color);
	return len;
}

int screen_blit(NexusOpenDevice *nod, unsigned int width, unsigned int height,
		unsigned char *data) {
	struct device_video_ops *ops = nod->nd->data;
	if (!nod->focused) return 0;
	ops->blit(width, height, data);
	return 0;
}

int screen_blit_native(NexusOpenDevice *nod,
		       unsigned int width, unsigned int height,
		       unsigned char *data) {
	struct device_video_ops *ops = nod->nd->data;
	if (!nod->focused) return 0;
	ops->blit_native(width, height, data);
	return 0;
}

int screen_get_geometry(NexusOpenDevice *nod, struct FB_Info *info) {
  // Geometry access should with or without focus
  struct device_video_ops *ops = nod->nd->data;
  // Get the raw geometry
  ops->get_geometry(info);

  // Compute the number of lines to skip
  printk_green("info fontheight = %d, num toplines = %d", 
	       info->fontheight, NUM_TOPLINES);
  info->skip_ylength = info->fontheight * NUM_TOPLINES;
  return 0;
}

