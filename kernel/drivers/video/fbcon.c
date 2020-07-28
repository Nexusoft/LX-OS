/*
 *  linux/drivers/video/fbcon.c -- Low level frame buffer based console driver
 *
 *	Copyright (C) 1995 Geert Uytterhoeven
 *
 *
 *  This file is based on the original Amiga console driver (amicon.c):
 *
 *	Copyright (C) 1993 Hamish Macdonald
 *			   Greg Harp
 *	Copyright (C) 1994 David Carter [carter@compsci.bristol.ac.uk]
 *
 *	      with work by William Rucklidge (wjr@cs.cornell.edu)
 *			   Geert Uytterhoeven
 *			   Jes Sorensen (jds@kom.auc.dk)
 *			   Martin Apel
 *
 *  and on the original Atari console driver (atacon.c):
 *
 *	Copyright (C) 1993 Bjoern Brauel
 *			   Roman Hodek
 *
 *	      with work by Guenther Kelleter
 *			   Martin Schaller
 *			   Andreas Schwab
 *
 *  Hardware cursor support added by Emmanuel Marty (core@ggi-project.org)
 *  Smart redraw scrolling, arbitrary font width support, 512char font support
 *  and software scrollback added by 
 *                         Jakub Jelinek (jj@ultra.linux.cz)
 *
 *  Random hacking by Martin Mares <mj@ucw.cz>
 *
 *	2001 - Documented with DocBook
 *	- Brad Douglas <brad@neruo.com>
 *
 *  The low level operations for the various display memory organizations are
 *  now in separate source files.
 *
 *  Currently the following organizations are supported:
 *
 *    o afb			Amiga bitplanes
 *    o cfb{2,4,8,16,24,32}	Packed pixels
 *    o ilbm			Amiga interleaved bitplanes
 *    o iplan2p[248]		Atari interleaved bitplanes
 *    o mfb			Monochrome
 *    o vga			VGA characters/attributes
 *
 *  To do:
 *
 *    - Implement 16 plane mode (iplan2p16)
 *
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of this archive for
 *  more details.
 */

#undef FBCONDEBUG

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
#ifdef CONFIG_AMIGA
#include <asm/amigahw.h>
#include <asm/amigaints.h>
#endif /* CONFIG_AMIGA */
#ifdef CONFIG_ATARI
#include <asm/atariints.h>
#endif
#ifdef CONFIG_MAC
#include <asm/macints.h>
#endif
#if defined(__mc68000__) || defined(CONFIG_APUS)
#include <asm/machdep.h>
#include <asm/setup.h>
#endif
#ifdef CONFIG_FBCON_VGA_PLANES
#include <asm/io.h>
#endif
#define INCLUDE_LINUX_LOGO_DATA
//#include <asm/linux_logo.h>

#include "nexus_logo.h"

#include <video/fbcon.h>
#include <video/fbcon-mac.h>	/* for 6x11 font on mac */
#include <video/font.h>

#include <nexus/defs.h>
#include <nexus/device.h>
#include <nexus/synch.h>

struct display_switch fbcon_dummy;

extern void nexus_fbcon_cfb32_putc(int c, int yy, int xx, unsigned int fgcolor);


//DAN: these config paramaters should be on from config but they may not be
//     so I am defining them here
#define CONFIG_FBCON_CFB16 1
#define CONFIG_FBCON_CFB24 1
#define CONFIG_FBCON_CFB32 1
#define CONFIG_FB_SBUS  1

#ifdef FBCONDEBUG
#  define DPRINTK(fmt, args...) printk(KERN_DEBUG "%s: " fmt, __FUNCTION__ , ## args)
#else
#  define DPRINTK(fmt, args...)
#endif

#define LOGO_H			80
#define LOGO_W			80
#define LOGO_LINE	(LOGO_W/8)

//static int smp_num_cpus = 1;

extern struct display *dandisp;
struct display fb_display[MAX_NR_CONSOLES];
char con2fb_map[MAX_NR_CONSOLES];
//DAN: static int logo_lines;
//DAN: static int logo_shown = -1;
/* Software scrollback */
int fbcon_softback_size = 32768;
//DAN: static unsigned long softback_buf, softback_curr;
//DAN: static unsigned long softback_in;
//DAN: static unsigned long softback_top, softback_end;
//DAN: static int softback_lines;

#define REFCOUNT(fd)	(((int *)(fd))[-1])
#define FNTSIZE(fd)	(((int *)(fd))[-2])
#define FNTCHARCNT(fd)	(((int *)(fd))[-3])
#define FNTSUM(fd)	(((int *)(fd))[-4])
#define FONT_EXTRA_WORDS 4

#define CM_SOFTBACK	(8)

#define advance_row(p, delta) (unsigned short *)((unsigned long)(p) + (delta) * conp->vc_size_row)

//DAN: static void fbcon_free_font(struct display *);
//DAN: static int fbcon_set_origin(struct vc_data *);

#ifdef CONFIG_PM
//DAN: static int pm_fbcon_request(struct pm_dev *dev, pm_request_t rqst, void *data);
//DAN: static struct pm_dev *pm_fbcon;
//DAN: static int fbcon_sleeping;
#endif

/*
 * Emmanuel: fbcon will now use a hardware cursor if the
 * low-level driver provides a non-NULL dispsw->cursor pointer,
 * in which case the hardware should do blinking, etc.
 *
 * if dispsw->cursor is NULL, use Atari alike software cursor
 */

static int cursor_drawn;

#define CURSOR_DRAW_DELAY		(1)

/* # VBL ints between cursor state changes */
#define ARM_CURSOR_BLINK_RATE		(10)
#define AMIGA_CURSOR_BLINK_RATE		(20)
#define ATARI_CURSOR_BLINK_RATE		(42)
#define MAC_CURSOR_BLINK_RATE		(32)
#define DEFAULT_CURSOR_BLINK_RATE	(20)

static int vbl_cursor_cnt;
//DAN: static int cursor_on;
//DAN: static int cursor_blink_rate;
static Sema *blitlock;


static inline void cursor_undrawn(void)
{
    vbl_cursor_cnt = 0;
    cursor_drawn = 0;
}


#define divides(a, b)	((!(a) || (b)%(a)) ? 0 : 1)


/*
 *  Interface used by the world
 */

const char *fbcon_startup(void);
//void fbcon_init(struct vc_data *conp, int init);

/*
 *  Internal routines
 */

static __inline__ int real_y(struct display *p, int ypos);
static __inline__ void updatescrollmode(struct display *p);
int fbcon_show_logo(int x0, int y0);

/**
 *	PROC_CONSOLE - find the attached tty or visible console
 *	@info: frame buffer info structure
 *
 *	Finds the tty attached to the process or visible console if
 *	the process is not directly attached to a tty (e.g. remote
 *	user) for device @info.
 *
 *	Returns -1 errno on error, or tty/visible console number
 *	on success.
 *
 */

#if 0
int PROC_CONSOLE(const struct fb_info *info)
{
        int fgc;

	if (info->display_fg == NULL)
		return -1;

        if (!current->tty ||
	    current->tty->driver.type != TTY_DRIVER_TYPE_CONSOLE ||
	    MINOR(current->tty->device) < 1)
		fgc = info->display_fg->vc_num;
	else
		fgc = MINOR(current->tty->device)-1;

	/* Does this virtual console belong to the specified fbdev? */
	if (fb_display[fgc].fb_info != info)
		return -1;

	return fgc;
}
#endif


/**
 *	set_all_vcs - set all virtual consoles to match
 *	@fbidx: frame buffer index (e.g. fb0, fb1, ...)
 *	@fb: frame buffer ops structure
 *	@var: frame buffer screen structure to set
 *	@info: frame buffer info structure
 *
 *	Set all virtual consoles to match screen info set in @var
 *	for device @info.
 *
 *	Returns negative errno on error, or zero on success.
 *
 */

#if 0
int set_all_vcs(int fbidx, struct fb_ops *fb, struct fb_var_screeninfo *var,
                struct fb_info *info)
{
    int unit, err;

    var->activate |= FB_ACTIVATE_TEST;
    err = fb->fb_set_var(var, PROC_CONSOLE(info), info);
    var->activate &= ~FB_ACTIVATE_TEST;
    if (err)
            return err;
    for (unit = 0; unit < MAX_NR_CONSOLES; unit++)
            if (fb_display[unit].conp && con2fb_map[unit] == fbidx)
                    fb->fb_set_var(var, unit, info);
    return 0;
}
#endif


/*
 *  Low Level Operations
 */

/* NOTE: fbcon cannot be __init: it may be called from take_over_console later */

static __inline__ void updatescrollmode(struct display *p)
{
    int m;
    if (p->scrollmode & __SCROLL_YFIXED)
    	return;
    if (divides(p->ywrapstep, fontheight(p)) &&
	divides(fontheight(p), p->var.yres_virtual))
	m = __SCROLL_YWRAP;
    else if (divides(p->ypanstep, fontheight(p)) &&
	     p->var.yres_virtual >= p->var.yres+fontheight(p))
	m = __SCROLL_YPAN;
    else if (p->scrollmode & __SCROLL_YNOMOVE)
    	m = __SCROLL_YREDRAW;
    else
	m = __SCROLL_YMOVE;
    p->scrollmode = (p->scrollmode & ~__SCROLL_YMASK) | m;
}

#define fontwidthvalid(p,w) ((p)->dispsw->fontwidthmask & FONTWIDTH(w))

/* ====================================================================== */

/*  fbcon_XXX routines - interface used by the world
 *
 *  This system is now divided into two levels because of complications
 *  caused by hardware scrolling. Top level functions:
 *
 *	fbcon_bmove(), fbcon_clear(), fbcon_putc()
 *
 *  handles y values in range [0, scr_height-1] that correspond to real
 *  screen positions. y_wrap shift means that first line of bitmap may be
 *  anywhere on this display. These functions convert lineoffsets to
 *  bitmap offsets and deal with the wrap-around case by splitting blits.
 *
 *	fbcon_bmove_physical_8()    -- These functions fast implementations
 *	fbcon_clear_physical_8()    -- of original fbcon_XXX fns.
 *	fbcon_putc_physical_8()	    -- (fontwidth != 8) may be added later
 *
 *  WARNING:
 *
 *  At the moment fbcon_putc() cannot blit across vertical wrap boundary
 *  Implies should only really hardware scroll in rows. Only reason for
 *  restriction is simplicity & efficiency at the moment.
 */

static __inline__ int real_y(struct display *p, int ypos)
{
    int rows = p->vrows;

    ypos += p->yscroll;
    return ypos < rows ? ypos : ypos-rows;
}

void nexus_fbcon_putc(int c, int ypos, int xpos){
  int color = (c >> 8) & 0xffffff;
  if (!color) color = 0xaaaaaa; // a nice off-white
  nexus_fbcon_cfb32_putc(c, ypos, xpos, color);
}

static inline unsigned safe_shift(unsigned d,int n)
{
    return n<0 ? d>>-n : d<<n;
}

#define SCREEN_WIDTH 1024
#define SCREEN_HEIGHT 768

void nexus_blit_clear(void){
  struct display *p = dandisp;
  unsigned char *fb = p->screen_base;
  int depth = p->var.bits_per_pixel;
  int bdepth = depth/8;
  P(blitlock);
  memset(fb, 0, SCREEN_WIDTH * SCREEN_HEIGHT * bdepth);
  V(blitlock);
}

// -------------------
int nexus_blit_frame(unsigned int width, unsigned int height, unsigned char *data)
{
  //struct display *p = &fb_display[fg_console]; /* draw to vt in foreground */
  struct display *p = dandisp;
    int depth = p->var.bits_per_pixel;
    int line = p->next_line;
    unsigned char *fb = p->screen_base;
    unsigned char *dst;
    int i, x1, y1, x;
    int done = 0;

    /* Return if the frame buffer is not mapped */
    if (!fb)
	return 0;

    P(blitlock);

#if 0
    if (p->fb_info->fbops->fb_rasterimg)
    	p->fb_info->fbops->fb_rasterimg(p->fb_info, 1);
#endif

    for (x = 0; x < smp_num_cpus * (width + 8) &&
    	 x < p->var.xres - (width + 8); x += (width + 8)) {

#if defined(CONFIG_FBCON_CFB16) || defined(CONFIG_FBCON_CFB24) || \
    defined(CONFIG_FBCON_CFB32) || defined(CONFIG_FB_SBUS)
	if ((depth % 8 == 0) && (p->visual == FB_VISUAL_TRUECOLOR)) {

	    /* Modes without color mapping, needs special data transformation... */
	    unsigned int val;		/* max. depth 32! */
	    int bdepth = depth/8;
	    unsigned char mask[9] = { 0,0x80,0xc0,0xe0,0xf0,0xf8,0xfc,0xfe,0xff };
	    unsigned char redmask, greenmask, bluemask;
	    int redshift, greenshift, blueshift;
		
	    /* Bug: Doesn't obey msb_right ... (who needs that?) */
	    redmask   = mask[p->var.red.length   < 8 ? p->var.red.length   : 8];
	    greenmask = mask[p->var.green.length < 8 ? p->var.green.length : 8];
	    bluemask  = mask[p->var.blue.length  < 8 ? p->var.blue.length  : 8];
	    redshift   = p->var.red.offset   - (8-p->var.red.length);
	    greenshift = p->var.green.offset - (8-p->var.green.length);
	    blueshift  = p->var.blue.offset  - (8-p->var.blue.length);

	    int hoff = (SCREEN_HEIGHT - height)/ 2; 
	    int woff = (SCREEN_WIDTH - width)/ 2; 

	    for( y1 = 0; y1 < height; y1++ ) {
	      for( x1 = 0; x1 < width; x1++ ) {
  		    
		    int blue   = data[y1 * width*3 + x1*3 + 0];
  		    int green = data[y1 * width*3 + x1*3 + 1];
  		    int red  = data[y1 * width*3 + x1*3 + 2];

		    //(10 + nexuslogo.width) * bdepth
		    dst = fb + (y1 + hoff) * line + (x1 + woff) * bdepth;
		    
		    val = safe_shift(red, redshift) | safe_shift(green, greenshift) | safe_shift(blue, blueshift);

		    if (bdepth == 4 && !((long)dst & 3)) {
			/* Some cards require 32bit access */
			fb_writel (val, dst);
			dst += 4;
		    } else if (bdepth == 2 && !((long)dst & 1)) {
			/* others require 16bit access */
			fb_writew (val,dst);
			dst +=2;
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
	    done = 1;
	}
#endif
    }
    
#if 0
    if (p->fb_info->fbops->fb_rasterimg)
    	p->fb_info->fbops->fb_rasterimg(p->fb_info, 0);
#endif
    /* Modes not yet supported: packed pixels with depth != 8 (does such a
     * thing exist in reality?) */

    //return done ? (height + fontheight(p) - 1) / fontheight(p) : 0 ;

    V(blitlock);
    return 1;
}

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
  /* Return if the frame buffer is not mapped */
  if (!fb)
    return 0;

  P(blitlock);

  for( y1 = 0; y1 < height; y1++ ) {
    memcpy(fb + (hoff + y1) * line + woff * bdepth,
	   data + y1 * width * bdepth, width * bdepth);
  }
  
  V(blitlock);
  return 0;
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
  if(0) {
    printk_red("Geometry is res=(%d,%d) size=(%d,%d)\n", 
	       info->xres, info->yres, info->width, info->height);
  }
  return 0;
}

#define egs_height 240
#define egs_width  320
//static unsigned char egs_bits[] = {
//#include "image"
//};

int __init nexus_frame(void)
{
  printk("nexus_frame no longer impemented\n");
#if 0
  //struct display *p = &fb_display[fg_console]; /* draw to vt in foreground */
  struct display *p = dandisp;
    int depth = p->var.bits_per_pixel;
    int line = p->next_line;
    unsigned char *fb = p->screen_base;
    unsigned char *dst;
    int i, x1, y1, x;
    int done = 0;

    /* Return if the frame buffer is not mapped */
    if (!fb)
	return 0;

    printk("p=0x%x, depth=%d, line=%d, fb=0x%x\n", (unsigned int)p, depth, line, (unsigned int)fb);
    printk("DAN: nexus_logo\n");

#if 0
    if (p->fb_info->fbops->fb_rasterimg)
    	p->fb_info->fbops->fb_rasterimg(p->fb_info, 1);
#endif

    for (x = 0; x < smp_num_cpus * (egs_width + 8) &&
    	 x < p->var.xres - (egs_width + 8); x += (egs_width + 8)) {

#if defined(CONFIG_FBCON_CFB16) || defined(CONFIG_FBCON_CFB24) || \
    defined(CONFIG_FBCON_CFB32) || defined(CONFIG_FB_SBUS)
	if ((depth % 8 == 0) && (p->visual == FB_VISUAL_TRUECOLOR)) {

	  printk("truecolor %d %d %d\n", depth, p->var.red.length, p->var.red.offset );
	    /* Modes without color mapping, needs special data transformation... */
	    unsigned int val;		/* max. depth 32! */
	    int bdepth = depth/8;
	    unsigned char mask[9] = { 0,0x80,0xc0,0xe0,0xf0,0xf8,0xfc,0xfe,0xff };
	    unsigned char redmask, greenmask, bluemask;
	    int redshift, greenshift, blueshift;
		
	    /* Bug: Doesn't obey msb_right ... (who needs that?) */
	    redmask   = mask[p->var.red.length   < 8 ? p->var.red.length   : 8];
	    greenmask = mask[p->var.green.length < 8 ? p->var.green.length : 8];
	    bluemask  = mask[p->var.blue.length  < 8 ? p->var.blue.length  : 8];
	    redshift   = p->var.red.offset   - (8-p->var.red.length);
	    greenshift = p->var.green.offset - (8-p->var.green.length);
	    blueshift  = p->var.blue.offset  - (8-p->var.blue.length);

	    for( y1 = 0; y1 < egs_height; y1++ ) {
	      for( x1 = 0; x1 < egs_width; x1++ ) {
  		    int blue   = egs_bits[y1 * egs_width*3 + x1*3 + 0];
  		    int green = egs_bits[y1 * egs_width*3 + x1*3 + 1];
  		    int red  = egs_bits[y1 * egs_width*3 + x1*3 + 2];

		    dst = fb + 100 * 3 + y1 * line + x1 * bdepth;

		    val = safe_shift(red, redshift) | safe_shift(green, greenshift) | safe_shift(blue, blueshift);

		    if (bdepth == 4 && !((long)dst & 3)) {
			/* Some cards require 32bit access */
			fb_writel (val, dst);
			dst += 4;
		    } else if (bdepth == 2 && !((long)dst & 1)) {
			/* others require 16bit access */
			fb_writew (val,dst);
			dst +=2;
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
	    done = 1;
	}
#endif
    }
#if 0    
    if (p->fb_info->fbops->fb_rasterimg)
    	p->fb_info->fbops->fb_rasterimg(p->fb_info, 0);
#endif
    /* Modes not yet supported: packed pixels with depth != 8 (does such a
     * thing exist in reality?) */

    //return done ? (egs_height + fontheight(p) - 1) / fontheight(p) : 0 ;
#endif
    return 1;

}



int __init fbcon_show_logo(int x0, int y0)
{
  //struct display *p = &fb_display[fg_console]; /* draw to vt in foreground */
  struct display *p = dandisp;

    int depth = p->var.bits_per_pixel;
    int line = p->next_line;
    unsigned char *fb = p->screen_base;
    unsigned char *dst;
    int i, x1, y1, r;
    int done = 0;

    /* Return if the frame buffer is not mapped */
    if (!fb)
	return 0;
	
#if 0
    if (p->fb_info->fbops->fb_rasterimg)
    	p->fb_info->fbops->fb_rasterimg(p->fb_info, 1);
#endif

    for (r = 0; r < smp_num_cpus * (egs_width + 8) &&
    	 r < p->var.xres - (egs_width + 8); r += (egs_width + 8)) { // what is this loop?

#if defined(CONFIG_FBCON_CFB16) || defined(CONFIG_FBCON_CFB24) || \
    defined(CONFIG_FBCON_CFB32) || defined(CONFIG_FB_SBUS)
	if ((depth % 8 == 0) && (p->visual == FB_VISUAL_TRUECOLOR)) {

	    /* Modes without color mapping, needs special data transformation... */
	    unsigned int val;		/* max. depth 32! */
	    int bdepth = depth/8;
	    unsigned char mask[9] = { 0,0x80,0xc0,0xe0,0xf0,0xf8,0xfc,0xfe,0xff };
	    unsigned char redmask, greenmask, bluemask;
	    int redshift, greenshift, blueshift;
		
	    /* Bug: Doesn't obey msb_right ... (who needs that?) */
	    redmask   = mask[p->var.red.length   < 8 ? p->var.red.length   : 8];
	    greenmask = mask[p->var.green.length < 8 ? p->var.green.length : 8];
	    bluemask  = mask[p->var.blue.length  < 8 ? p->var.blue.length  : 8];
	    redshift   = p->var.red.offset   - (8-p->var.red.length);
	    greenshift = p->var.green.offset - (8-p->var.green.length);
	    blueshift  = p->var.blue.offset  - (8-p->var.blue.length);

		int y_max = SCREEN_HEIGHT - nexuslogo.height;
		if (y0 < 0) y0 = y_max / 2;
		else y0 = y0 % y_max;

		int x_max = SCREEN_HEIGHT - nexuslogo.height;
		if (x0 < 0) x0 = x_max / 2;
		else x0 = x0 % x_max;

	    for( y1 = 0; y1 < nexuslogo.height; y1++ ) {
		for( x1 = 0; x1 < nexuslogo.width; x1++ ) {
  		    int blue   = nexuslogo.pixel_data[y1 * nexuslogo.width*3 + x1*3 + 0];
  		    int green = nexuslogo.pixel_data[y1 * nexuslogo.width*3 + x1*3 + 1];
  		    int red  = nexuslogo.pixel_data[y1 * nexuslogo.width*3 + x1*3 + 2];

		    dst = fb + (y0 + y1) * line + (x0+x1) * bdepth;

		    val = safe_shift(red, redshift) | safe_shift(green, greenshift) | safe_shift(blue, blueshift);

		    if (bdepth == 4 && !((long)dst & 3)) {
			/* Some cards require 32bit access */
			fb_writel (val, dst);
			dst += 4;
		    } else if (bdepth == 2 && !((long)dst & 1)) {
			/* others require 16bit access */
			fb_writew (val,dst);
			dst +=2;
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
	    done = 1;
	}
#endif
    }
    
#if 0
    if (p->fb_info->fbops->fb_rasterimg)
    	p->fb_info->fbops->fb_rasterimg(p->fb_info, 0);
#endif
    /* Modes not yet supported: packed pixels with depth != 8 (does such a
     * thing exist in reality?) */

    //return done ? (nexuslogo.height + fontheight(p) - 1) / fontheight(p) : 0 ;
    return 1;
}


// ------

#define egs2_width 80
#define egs2_height 80
static unsigned char egs2_bits[] = {
   0x00, 0x03, 0x00, 0x80, 0x03, 0x00, 0xe0, 0x01, 0x80, 0x01, 0x00, 0x0c,
   0x00, 0x00, 0x0e, 0x00, 0x3c, 0x00, 0xc0, 0x00, 0x00, 0x70, 0x00, 0x00,
   0xf8, 0xff, 0x03, 0x00, 0x30, 0x00, 0x00, 0xc0, 0x0f, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0xf8, 0x3f, 0x00, 0x00, 0x00, 0xf0,
   0x03, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xfe, 0xff, 0xff, 0x0f, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x07, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x40, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x40, 0x60, 0x00, 0x00, 0xf1, 0xff, 0x8f, 0x01, 0x00, 0x00,
   0x44, 0x40, 0x03, 0x00, 0x11, 0x00, 0x00, 0x03, 0x00, 0x00, 0xc6, 0x00,
   0x07, 0x00, 0x21, 0x00, 0x00, 0x06, 0x00, 0x2c, 0x82, 0x00, 0x07, 0x00,
   0x21, 0x00, 0x00, 0x04, 0x00, 0x24, 0x82, 0x00, 0x07, 0x00, 0x21, 0x00,
   0x00, 0x08, 0x00, 0x22, 0x02, 0x01, 0x0b, 0x00, 0x21, 0x00, 0x00, 0x10,
   0x00, 0x21, 0x02, 0x01, 0x0b, 0x00, 0x21, 0x00, 0x00, 0x10, 0x80, 0x21,
   0x02, 0x03, 0x13, 0x00, 0x21, 0x00, 0x00, 0x20, 0xc0, 0x20, 0x02, 0x02,
   0x33, 0x00, 0x21, 0x00, 0x00, 0x20, 0x40, 0x20, 0x04, 0x06, 0x63, 0x00,
   0x21, 0x00, 0x00, 0x40, 0x40, 0x20, 0x04, 0x04, 0xc3, 0x00, 0x21, 0x00,
   0x00, 0x40, 0x60, 0x20, 0x04, 0x04, 0x83, 0x00, 0x21, 0x00, 0x00, 0x40,
   0x20, 0x20, 0x04, 0x04, 0x83, 0x01, 0x41, 0x00, 0x00, 0x80, 0x30, 0x20,
   0x04, 0x04, 0x03, 0x01, 0x41, 0x00, 0x00, 0x80, 0x10, 0x20, 0x04, 0x08,
   0x03, 0x02, 0x41, 0x00, 0x00, 0x80, 0x10, 0x20, 0x04, 0x08, 0x03, 0x02,
   0x41, 0x00, 0x00, 0x00, 0x19, 0x20, 0x04, 0x08, 0x07, 0x04, 0x41, 0x00,
   0x00, 0x00, 0x09, 0x20, 0x04, 0x18, 0x05, 0x04, 0x41, 0x00, 0x03, 0x00,
   0x09, 0x60, 0x04, 0x10, 0x05, 0x0c, 0x81, 0xfc, 0x00, 0x00, 0x09, 0x40,
   0x04, 0x10, 0x05, 0x08, 0x81, 0x07, 0x00, 0x00, 0x09, 0x40, 0x04, 0x30,
   0x05, 0x08, 0x81, 0x00, 0x00, 0x00, 0x0a, 0x40, 0x04, 0x20, 0x05, 0x08,
   0x81, 0x00, 0x00, 0x00, 0x0a, 0x40, 0x04, 0x20, 0x05, 0x18, 0x01, 0x00,
   0x00, 0x00, 0x0a, 0x40, 0x04, 0x20, 0x05, 0x10, 0x81, 0x00, 0x00, 0x00,
   0x06, 0x40, 0x04, 0x20, 0x05, 0x10, 0x81, 0x00, 0x00, 0x00, 0x04, 0x40,
   0x04, 0x20, 0x05, 0x10, 0x81, 0x00, 0x00, 0x00, 0x04, 0x40, 0x04, 0x40,
   0x05, 0x10, 0x81, 0x00, 0x00, 0x00, 0x06, 0x40, 0x04, 0x40, 0x05, 0x10,
   0x81, 0x00, 0x00, 0x00, 0x06, 0x40, 0x04, 0x40, 0x05, 0x20, 0x81, 0x00,
   0x00, 0x00, 0x08, 0x40, 0x04, 0xc0, 0x05, 0x20, 0x81, 0x00, 0x00, 0x00,
   0x0b, 0x40, 0x08, 0x80, 0x05, 0x20, 0x81, 0x00, 0x00, 0x00, 0x09, 0x40,
   0x08, 0x80, 0x03, 0x60, 0x81, 0x00, 0x00, 0x00, 0x11, 0x40, 0x08, 0x80,
   0x03, 0x40, 0x81, 0x00, 0x00, 0x00, 0x11, 0x40, 0x10, 0x80, 0x03, 0x40,
   0x81, 0x00, 0x00, 0x80, 0x11, 0x40, 0x10, 0x81, 0x03, 0xc0, 0x81, 0x00,
   0x00, 0x80, 0x10, 0x40, 0x88, 0x81, 0x03, 0x80, 0x81, 0x00, 0x00, 0x80,
   0x20, 0xc0, 0x88, 0x80, 0x03, 0x80, 0x81, 0x00, 0x00, 0x80, 0x60, 0x80,
   0x88, 0xc0, 0x01, 0x80, 0x81, 0x00, 0x00, 0xc0, 0x40, 0x80, 0x88, 0x41,
   0x01, 0x80, 0x81, 0x00, 0x00, 0x40, 0x40, 0x80, 0x08, 0x63, 0x01, 0x80,
   0x81, 0x00, 0x00, 0x40, 0xc0, 0x80, 0x0c, 0x2c, 0x01, 0x80, 0x81, 0xfb,
   0x01, 0x40, 0x80, 0x80, 0x05, 0x38, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x43,
   0x80, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x80, 0x01,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x1f, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfa, 0xbb, 0x01, 0x00, 0x00,
   0x00, 0xfc, 0x02, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0x01, 0xe0, 0x0f,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x07, 0x20, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x30, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x20, 0x0c, 0x00, 0x00, 0xee, 0xde, 0xfb, 0x06, 0x00, 0x00, 0x40,
   0x04, 0x00, 0x40, 0x01, 0x00, 0x00, 0xd8, 0x0d, 0x00, 0xe0, 0x02, 0x00,
   0x28, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x01, 0x80, 0x02, 0x00, 0x06, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x0e, 0x80, 0x03, 0xc0, 0x01, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x38, 0x80, 0x01, 0x20, 0x00, 0xe0, 0xff, 0x0f, 0x00, 0x00,
   0x60, 0x80, 0x00, 0x0c, 0x00, 0x18, 0x00, 0xf0, 0x07, 0x00, 0x80, 0x00,
   0x00, 0x02, 0x00, 0x06, 0x00, 0x00, 0x38, 0x00, 0x00, 0x03, 0x00, 0x03,
   0x00, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x80, 0x01, 0xc0, 0x00,
   0x00, 0x00, 0xc0, 0x00, 0x00, 0x0c, 0xc0, 0x00, 0x30, 0x00, 0x00, 0x00,
   0x80, 0x01, 0x00, 0x18, 0x60, 0x00, 0x08, 0x00, 0x80, 0x7f, 0x00, 0x03,
   0x00, 0x10, 0x30, 0x00, 0x04, 0x00, 0x78, 0xc0, 0x00, 0x06, 0x00, 0x20,
   0x18, 0x00, 0x03, 0x80, 0x07, 0x80, 0x00, 0x0c, 0x00, 0x60, 0x0c, 0xc0,
   0x01, 0xc0, 0x00, 0x00, 0x01, 0x38, 0x00, 0xc0};

int __init nexus_logo(void)
{
  //struct display *p = &fb_display[fg_console]; /* draw to vt in foreground */
  struct display *p = dandisp; /* draw to vt in foreground */
  
  printk("p=0x%p\n", p);
  
  int depth = p->var.bits_per_pixel;
  int line = p->next_line;
  unsigned char *fb = p->screen_base;
  unsigned char *logo;
  unsigned char *dst;
  int i, x1, y1, x;
  int logo_depth, done = 0;

    /* Return if the frame buffer is not mapped */
    if (!fb)
	return 0;
	
    printk("DAN: nexus_logo fb=0x%p\n", fb);

    logo = egs2_bits;
    logo_depth = 1;
    
#if 0
    if (p->fb_info->fbops->fb_rasterimg)
    	p->fb_info->fbops->fb_rasterimg(p->fb_info, 1);
#endif 

    for (x = 0; x < smp_num_cpus * (LOGO_W + 8) &&
    	 x < p->var.xres - (LOGO_W + 8); x += (LOGO_W + 8)) {

#if defined(CONFIG_FBCON_CFB16) || defined(CONFIG_FBCON_CFB24) || \
    defined(CONFIG_FBCON_CFB32) || defined(CONFIG_FB_SBUS)
	if ((depth % 8 == 0) && (p->visual == FB_VISUAL_TRUECOLOR)) {

	  printk("truecolor\n");
	    /* Modes without color mapping, needs special data transformation... */
	    unsigned int val;		/* max. depth 32! */
	    int bdepth = depth/8;
	    unsigned char mask[9] = { 0,0x80,0xc0,0xe0,0xf0,0xf8,0xfc,0xfe,0xff };
	    unsigned char redmask, greenmask, bluemask;
	    int redshift, greenshift, blueshift;
		
	    /* Bug: Doesn't obey msb_right ... (who needs that?) */
	    redmask   = mask[p->var.red.length   < 8 ? p->var.red.length   : 8];
	    greenmask = mask[p->var.green.length < 8 ? p->var.green.length : 8];
	    bluemask  = mask[p->var.blue.length  < 8 ? p->var.blue.length  : 8];
	    redshift   = p->var.red.offset   - (8-p->var.red.length);
	    greenshift = p->var.green.offset - (8-p->var.green.length);
	    blueshift  = p->var.blue.offset  - (8-p->var.blue.length);

	    for( y1 = 0; y1 < egs2_height; y1++ ) {
		dst = fb + y1*line + x*bdepth;
		for( x1 = 0; x1 < egs2_width; x1++ ) {
  		    int byte = egs2_bits[y1 * egs2_width / 8 + x1/8];
		    int biton = byte & (1<<(x1%8));

		    if(biton)
		      val = safe_shift(255, redshift) | safe_shift(255, greenshift) | safe_shift(255, blueshift);
		    else 
		      val = safe_shift(0, redshift) | safe_shift(0, greenshift) | safe_shift(0, blueshift);
		    if (bdepth == 4 && !((long)dst & 3)) {
			/* Some cards require 32bit access */
			fb_writel (val, dst);
			dst += 4;
		    } else if (bdepth == 2 && !((long)dst & 1)) {
			/* others require 16bit access */
			fb_writew (val,dst);
			dst +=2;
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
	    done = 1;
	}
#endif

    }
#if 0    
    if (p->fb_info->fbops->fb_rasterimg)
    	p->fb_info->fbops->fb_rasterimg(p->fb_info, 0);
#endif
    /* Modes not yet supported: packed pixels with depth != 8 (does such a
     * thing exist in reality?) */

    //return done ? (LOGO_H + fontheight(p) - 1) / fontheight(p) : 0 ;
    return done ? (LOGO_H + 16 - 1) / 16 : 0 ;
}

static struct device_video_ops fb_ops = {
    putc:	nexus_fbcon_putc,
    clear:	nexus_blit_clear,
    blit:	nexus_blit_frame,
    blit_native:	nexus_blit_frame_native,
    get_geometry: nexus_get_geometry,
};

void fbcon_init(void) {
  blitlock = sema_new();
  sema_initialize(blitlock, 1);
  nexus_register_device(DEVICE_VIDEO, "fb", IRQ_NONE, &fb_ops, NULL, NULL,
			DRIVER_KERNEL);
}



/*
 *  Visible symbols for modules
 */

MODULE_LICENSE("GPL");
