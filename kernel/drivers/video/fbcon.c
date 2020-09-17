/** NexusOS: lowlevel framebuffer video.
    derived from linux/drivers/video/fbcon.c */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/delay.h>	/* MSch: for IRQ probe */
#include <linux/tty.h>
#include <linux/console.h>
#include <linux/string.h>
#include <linux/kd.h>
#include <linux/slab.h>
#include <linux/fb.h>
#include <linux/vt_kern.h>
#include <linux/selection.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/pm.h>

#include <asm/irq.h>
#include <asm/system.h>
#include <asm/uaccess.h>

#include "nexus_logo.h"

#include <video/fbcon.h>
#include <video/fbcon-mac.h>	/* for 6x11 font on mac */
#include <video/font.h>

#include <nexus/defs.h>
#include <nexus/device.h>
#include <nexus/synch.h>

#define SCREEN_WIDTH 1024
#define SCREEN_HEIGHT 768
#define SCREEN_BPP 3		// BYTES per pixel

extern void nexus_fbcon_cfb32_putc(int c, int yy, int xx, unsigned int fgcolor);
extern struct display *dandisp;

struct display_switch fbcon_dummy;
struct display fb_display[MAX_NR_CONSOLES];
static Sema blitlock = SEMA_MUTEX_INIT;

/** set a single pixel */
void nexus_fbcon_putc(int c, int ypos, int xpos) {
  int color = (c >> 8) & 0xffffff;
  if (!color) color = 0xaaaaaa; // a nice off-white
  nexus_fbcon_cfb32_putc(c, ypos, xpos, color);
}

/** clear entire screen */
void nexus_blit_clear(void) {
  struct display *p = dandisp;
  unsigned char *fb = p->screen_base;
  int bdepth = p->var.bits_per_pixel / 8;

  P(&blitlock);
  memset(fb, 0, SCREEN_WIDTH * SCREEN_HEIGHT * bdepth);
  V(&blitlock);
}

/** Blit a frame without bitdepth translation */
int nexus_blit_frame_native(unsigned int width, unsigned int height, unsigned char *data)
{
  struct display *p = dandisp;
  int depth = p->var.bits_per_pixel;
  int line = p->next_line;
  unsigned char *fb = p->screen_base;
  int bdepth = depth/8;
  int y1;
  int hoff = (SCREEN_HEIGHT - height)/ 2; 
  int woff = (SCREEN_WIDTH - width)/ 2; 
  
  if (!fb)
    return 0;

  P(&blitlock);
  for( y1 = 0; y1 < height; y1++ ) {
    memcpy(fb + (hoff + y1) * line + woff * bdepth,
	   data + y1 * width * bdepth, width * bdepth);
  }
  
  V(&blitlock);
  return 1;
}

static inline unsigned safe_shift(unsigned d,int n)
{
    if (n > 0)	// bitdepth is smaller than truecolor
	    return d >> n;
    else	// bitdepth is larger
	    return d << -n;
}

/** Blit a truecolor frame */
int nexus_blit_frame(unsigned int width, unsigned int height, unsigned char *data)
{
    struct display *p = dandisp;
    int depth = p->var.bits_per_pixel;
    int line = p->next_line;
    unsigned char *fb = p->screen_base;
    unsigned char *dst;
    int i, x1, y1, x, red, green, blue, hoff, woff;
    unsigned int val;		/* max. depth 32! */
    int bdepth = depth/8;


    // Return if the frame buffer is not mapped
    if (!fb)
	return 0;


    // Use native method if device depth is truecolor
    if (bdepth == 8)
	    return nexus_blit_frame_native(width, height, data);

    P(&blitlock);

    hoff = (SCREEN_HEIGHT - height)/ 2; 
    woff = (SCREEN_WIDTH - width)/ 2; 

    for( y1 = 0; y1 < height; y1++ ) {
      for( x1 = 0; x1 < width; x1++ ) {

	    // extract each color from truecolor image
	    blue  = data[(y1 * width * SCREEN_BPP) + (x1 * SCREEN_BPP) + 0];
	    green = data[(y1 * width * SCREEN_BPP) + (x1 * SCREEN_BPP) + 1];
	    red   = data[(y1 * width * SCREEN_BPP) + (x1 * SCREEN_BPP) + 2];

	    // shift all colors to match device color depth
	    dst = fb + (y1 + hoff) * line + (x1 + woff) * bdepth;
	    red   = safe_shift(red,   8 - p->var.red.length);
	    green = safe_shift(green, 8 - p->var.green.length);
	    blue  = safe_shift(blue,  8 - p->var.blue.length);
	    val   = (red << p->var.red.offset) | (green << p->var.green.offset) | (blue << p->var.blue.offset);

	    // write to device framebuffer
	    if (bdepth == 4 && !((long)dst & 3)) {
		/* Some cards require 32bit access */
		fb_writel (val, dst);
		dst += 4;
	    } else if (bdepth == 2 && !((long)dst & 1)) {
		/* others require 16bit access */
		fb_writew (val,dst);
		dst += 2;
	    } else {
#ifdef __LITTLE_ENDIAN
		for( i = 0; i < bdepth; ++i )
#else
		for( i = bdepth-1; i >= 0; --i )
#endif
		    fb_writeb (val >> (i*8), dst++);
	    }
	}
    }
    
    V(&blitlock);
    return 1;
}

static struct FB_Bitfield FB_Bitfield_from_linux(struct fb_bitfield bf) {
  assert(bf.msb_right == 0);
  return ( (struct FB_Bitfield) {
	.offset =  bf.offset,
	.length = bf.length, 
      });
}

int nexus_get_geometry(struct FB_Info *info) {
  struct display *p = dandisp;
  memset(info, 0, sizeof(*info));
  info->fb = p->screen_base;
  info->fontheight = NEXUS_FONTHEIGHT;
  info->xres = p->var.xres;
  info->yres = p->var.yres;
  info->width = p->var.width;
  info->height = p->var.height;
  info->line_length = p->line_length;
  info->bpp = p->var.bits_per_pixel;
  info->red = FB_Bitfield_from_linux(dandisp->var.red);
  info->green = FB_Bitfield_from_linux(dandisp->var.green);
  info->blue = FB_Bitfield_from_linux(dandisp->var.blue);
  return 0;
}

/** Show the logo sprite
    XXX convert into generic sprite blit operation */
int fbcon_show_logo(int x0, int y0)
{
    char *frame;
    int logo_top, logo_bottom, logo_left, logo_bpp, logo_width, logo_height, i;

    // sanity check input
    if (nexuslogo.height > SCREEN_HEIGHT || 
	nexuslogo.width > SCREEN_WIDTH || 
	nexuslogo.bytes_per_pixel != SCREEN_BPP) {
	printk("[video] sprite out of bounds\n");
    	return 0;
    }

    frame = gcalloc(1, SCREEN_HEIGHT * SCREEN_WIDTH * SCREEN_BPP);
    if (!frame)
	    return 0;

    // calculate offset to centerize sprite
    logo_top = (SCREEN_HEIGHT / 2) - nexuslogo.height / 2;
    logo_bottom = logo_top + nexuslogo.height - 1;
    logo_left = (SCREEN_WIDTH / 2) - nexuslogo.width / 2;

    // calculate max dimensions
    logo_width = min((int) SCREEN_WIDTH - logo_left, (int) nexuslogo.width);
    logo_height = min((int) SCREEN_HEIGHT - logo_top, (int) nexuslogo.height);
    logo_bpp = nexuslogo.bytes_per_pixel;

    // copy whole lines of the spire at once
    for (i = 0; i < logo_height; i++) 
    	memcpy(frame + ((logo_top + i) * SCREEN_WIDTH * SCREEN_BPP) + (logo_left * SCREEN_BPP),
               nexuslogo.pixel_data + (nexuslogo.width * i * logo_bpp), 
	       logo_width * logo_bpp);

    // show sprite
    nexus_blit_frame(SCREEN_WIDTH, SCREEN_HEIGHT, frame);

    gfree(frame);
    return 1;
}

struct device_video_ops nxframebuffer_ops = {
    putc:		nexus_fbcon_putc,
    clear:		nexus_blit_clear,
    blit:		nexus_blit_frame,
    blit_native:	nexus_blit_frame_native,
    get_geometry: 	nexus_get_geometry,
};

/** Prettyprint some device info 
    cannot do this in fbcon_init(), because screen is not yet up */
void fbcon_init_late(void)
{
    struct display *p = dandisp; /* draw to vt in foreground */
    char *type;

    if (p->var.bits_per_pixel < 4)
	    type = "Oldskool (rock on!)";
    else if (p->var.bits_per_pixel == 4)
	    type = "EGA";
    else if (p->var.bits_per_pixel == 8)
	    type = "VGA";
    else if (p->var.bits_per_pixel == 15 || p->var.bits_per_pixel == 16)
	    type = "Highcolor";
    else if (p->var.bits_per_pixel == 24)
	    type = "Truecolor";
    else if (p->var.bits_per_pixel > 24)
	    type = "Truecolor+";
    else
	    type = "Acid";

    printk("[video] initialized %s framebuffer\n", type);
}

