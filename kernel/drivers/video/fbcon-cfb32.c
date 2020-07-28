/*
 *  linux/drivers/video/cfb32.c -- Low level frame buffer operations for 32 bpp
 *				   truecolor packed pixels
 *
 *	Created 28 Dec 1997 by Geert Uytterhoeven
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of this archive for
 *  more details.
 */

#include <linux/module.h>
#include <linux/tty.h>
#include <linux/console.h>
#include <linux/string.h>
#include <linux/fb.h>

#include <video/fbcon.h>
#include <video/fbcon-cfb32.h>
#include <video/font.h>

#include <nexus/log.h>

extern struct fbcon_font_desc font_vga_8x16;
extern struct fbcon_font_desc fixed_8x16;
extern struct fbcon_font_desc terminus_8x16;

/** select font */
#define CURFONT font_vga_8x16

extern struct display *dandisp;
    /*
     *  32 bpp packed pixels
     */

void fbcon_cfb32_setup(struct display *p)
{
    p->next_line = p->line_length ? p->line_length : p->var.xres_virtual<<2;
    p->next_plane = 0;
}

void fbcon_cfb32_bmove(struct display *p, int sy, int sx, int dy, int dx,
		       int height, int width)
{
    int bytes = p->next_line, linesize = bytes * fontheight(p), rows;
    u8 *src, *dst;

    if (sx == 0 && dx == 0 && width * fontwidth(p) * 4 == bytes) {
	fb_memmove(p->screen_base + dy * linesize,
		  p->screen_base + sy * linesize,
		  height * linesize);
	return;
    }
    if (fontwidthlog(p)) {
	sx <<= fontwidthlog(p)+2;
	dx <<= fontwidthlog(p)+2;
	width <<= fontwidthlog(p)+2;
    } else {
	sx *= fontwidth(p)*4;
	dx *= fontwidth(p)*4;
	width *= fontwidth(p)*4;
    }
    if (dy < sy || (dy == sy && dx < sx)) {
	src = p->screen_base + sy * linesize + sx;
	dst = p->screen_base + dy * linesize + dx;
	for (rows = height * fontheight(p); rows--;) {
	    fb_memmove(dst, src, width);
	    src += bytes;
	    dst += bytes;
	}
    } else {
	src = p->screen_base + (sy+height) * linesize + sx - bytes;
	dst = p->screen_base + (dy+height) * linesize + dx - bytes;
	for (rows = height * fontheight(p); rows--;) {
	    fb_memmove(dst, src, width);
	    src -= bytes;
	    dst -= bytes;
	}
    }
}

static inline void rectfill(u8 *dest, int width, int height, u32 data,
			    int linesize)
{
    int i;

    while (height-- > 0) {
	u32 *p = (u32 *)dest;
	for (i = 0; i < width/4; i++) {
	    fb_writel(data, p++);
	    fb_writel(data, p++);
	    fb_writel(data, p++);
	    fb_writel(data, p++);
	}
	if (width & 2) {
	    fb_writel(data, p++);
	    fb_writel(data, p++);
	}
	if (width & 1)
	    fb_writel(data, p++);
	dest += linesize;
    }
}

void fbcon_cfb32_clear(struct vc_data *conp, struct display *p, int sy, int sx,
		       int height, int width)
{
    u8 *dest;
    int bytes = p->next_line, lines = height * fontheight(p);
    u32 bgx;

    dest = p->screen_base + sy * fontheight(p) * bytes + sx * fontwidth(p) * 4;

    bgx = ((u32 *)p->dispsw_data)[attr_bgcol_ec(p, conp)];

    width *= fontwidth(p)/4;
    if (width * 16 == bytes)
	rectfill(dest, lines * width * 4, 1, bgx, bytes);
    else
	rectfill(dest, width * 4, lines, bgx, bytes);
}

#if defined(__BIG_ENDIAN)
#define convert4to3(in1, in2, in3, in4, out1, out2, out3) \
    do { \
        out1 = (in1<<8)  | (in2>>16); \
        out2 = (in2<<16) | (in3>>8); \
        out3 = (in3<<24) | in4; \
    } while (0)
#elif defined(__LITTLE_ENDIAN)
#define convert4to3(in1, in2, in3, in4, out1, out2, out3) \
    do { \
        out1 = in1       | (in2<<24); \
        out2 = (in2>> 8) | (in3<<16); \
        out3 = (in3>>16) | (in4<< 8); \
    } while (0)
#else
#error FIXME: No endianness??
#endif

static inline void store4pixels(u32 d1, u32 d2, u32 d3, u32 d4, u32 *dest)
{
    u32 o1, o2, o3;
    convert4to3(d1, d2, d3, d4, o1, o2, o3);
    fb_writel (o1, dest++);
    fb_writel (o2, dest++);
    fb_writel (o3, dest);
}

static u32 tab_cfb16[] = {
#if defined(__BIG_ENDIAN)
    0x00000000, 0x0000ffff, 0xffff0000, 0xffffffff
#elif defined(__LITTLE_ENDIAN)
    0x00000000, 0xffff0000, 0x0000ffff, 0xffffffff
#else
#error FIXME: No endianness??
#endif
};

void fbcon_cfb16_putc(int c, int yy, int xx, unsigned int fgcolor)
{
    u8 *dest, *cdat, bits;
    struct display *p = dandisp;
    int bytes = p->next_line, rows;
    u32 eorx, fgx, bgx;

    unsigned char charmask = 0xff;
    int fontheight = NEXUS_FONTHEIGHT;
    int fontwidth = NEXUS_FONTWIDTH;
    unsigned char *fontdata = CURFONT.data;

    dest = p->screen_base + yy * fontheight * bytes + xx * fontwidth * 2;

#if 0
    fgx = 0xffffffff;
#endif
    // XXX: May not work with endianness change
    // 16-23 	=> 11-15
    // 8-15 		=> 5-10
    // 0-7 		=> 0-4
    u32 one = 
      ((fgcolor >> 8) & (0x1f << 11)) |
      ((fgcolor >> 5) & (0x3f << 5)) |
      ((fgcolor >> 3) & (0x1f));

    fgx = (one << 16) | one;
    bgx = 0;
    eorx = fgx ^ bgx;

    switch (fontwidth) {
#if 0
    case 4:
#endif
    case 8:
	cdat = fontdata + (c & charmask) * fontheight;
	for (rows = fontheight; rows--; dest += bytes) {
	    bits = *cdat++;
	    fb_writel((tab_cfb16[bits >> 6] & eorx) ^ bgx, dest);
	    fb_writel((tab_cfb16[bits >> 4 & 3] & eorx) ^ bgx, dest+4);
	    if (fontwidth == 8) {
		fb_writel((tab_cfb16[bits >> 2 & 3] & eorx) ^ bgx, dest+8);
		fb_writel((tab_cfb16[bits & 3] & eorx) ^ bgx, dest+12);
	    }
	}
	break;
#if 0
    case 12:
    case 16:
	cdat = p->fontdata + ((c & p->charmask) * fontheight(p) << 1);
	for (rows = fontheight(p); rows--; dest += bytes) {
	    bits = *cdat++;
	    fb_writel((tab_cfb16[bits >> 6] & eorx) ^ bgx, dest);
	    fb_writel((tab_cfb16[bits >> 4 & 3] & eorx) ^ bgx, dest+4);
	    fb_writel((tab_cfb16[bits >> 2 & 3] & eorx) ^ bgx, dest+8);
	    fb_writel((tab_cfb16[bits & 3] & eorx) ^ bgx, dest+12);
	    bits = *cdat++;
	    fb_writel((tab_cfb16[bits >> 6] & eorx) ^ bgx, dest+16);
	    fb_writel((tab_cfb16[bits >> 4 & 3] & eorx) ^ bgx, dest+20);
	    if (fontwidth(p) == 16) {
		fb_writel((tab_cfb16[bits >> 2 & 3] & eorx) ^ bgx, dest+24);
		fb_writel((tab_cfb16[bits & 3] & eorx) ^ bgx, dest+28);
	    }
	}
	break;
#endif
    }
}

void fbcon_cfb24_putc(int c, int yy, int xx, unsigned int fgcolor){
    u8 *dest, *cdat, bits;
    struct display *p = dandisp;
    int bytes = p->next_line, rows;
    u32 eorx, fgx, bgx, d1, d2, d3, d4;

    unsigned char *fontdata = CURFONT.data;
    unsigned char charmask = 0xff;
    int fontheight = NEXUS_FONTHEIGHT;
    int fontwidth = NEXUS_FONTWIDTH;

    dest = p->screen_base + yy * fontheight * bytes + xx * fontwidth * 3;
    if (fontwidth <= 8)
        cdat = fontdata + (c & charmask) * fontheight;
    else
        cdat = fontdata + ((c & charmask) * fontheight << 1);

    //fgx = ((u32 *)p->dispsw_data)[attr_fgcol(p, c)];
    //bgx = ((u32 *)p->dispsw_data)[attr_bgcol(p, c)];
    //fgx = 0xaaaaaa;
    fgx = fgcolor;
    bgx = 0x0;
    eorx = fgx ^ bgx;

    for (rows = fontheight; rows--; dest += bytes) {
        bits = *cdat++;
        d1 = (-(bits >> 7) & eorx) ^ bgx;
        d2 = (-(bits >> 6 & 1) & eorx) ^ bgx;
        d3 = (-(bits >> 5 & 1) & eorx) ^ bgx;
        d4 = (-(bits >> 4 & 1) & eorx) ^ bgx;
        store4pixels(d1, d2, d3, d4, (u32 *)dest);
        if (fontwidth < 8)
            continue;
        d1 = (-(bits >> 3 & 1) & eorx) ^ bgx;
        d2 = (-(bits >> 2 & 1) & eorx) ^ bgx;
        d3 = (-(bits >> 1 & 1) & eorx) ^ bgx;
        d4 = (-(bits & 1) & eorx) ^ bgx;
        store4pixels(d1, d2, d3, d4, (u32 *)(dest+12));
        if (fontwidth < 12)
            continue;
        bits = *cdat++;
        d1 = (-(bits >> 7) & eorx) ^ bgx;
        d2 = (-(bits >> 6 & 1) & eorx) ^ bgx;
        d3 = (-(bits >> 5 & 1) & eorx) ^ bgx;
        d4 = (-(bits >> 4 & 1) & eorx) ^ bgx;
        store4pixels(d1, d2, d3, d4, (u32 *)(dest+24));
        if (fontwidth < 16)
            continue;
        d1 = (-(bits >> 3 & 1) & eorx) ^ bgx;
        d2 = (-(bits >> 2 & 1) & eorx) ^ bgx;
        d3 = (-(bits >> 1 & 1) & eorx) ^ bgx;
        d4 = (-(bits & 1) & eorx) ^ bgx;
        store4pixels(d1, d2, d3, d4, (u32 *)(dest+36));
    }
}

void nexus_fbcon_cfb32_putc(int c, int yy, int xx, unsigned int fgcolor)
{
    u8 *dest, *cdat, bits;
    int rows;
    u32 eorx, fgx, bgx, *pt;

    struct display *p = dandisp;

    if (p->var.bits_per_pixel == 24){
      fbcon_cfb24_putc(c, yy, xx, fgcolor);
      return;
    }

    if (p->var.bits_per_pixel == 16){
      fbcon_cfb16_putc(c, yy, xx, fgcolor);
      return;
    }

    int fontheight = 16;
    int fontwidth = 8;
    unsigned char *screen_base = p->screen_base;
    unsigned char *fontdata = CURFONT.data;
    unsigned char charmask = 0xff;
    //fgx = 0xaaaaaa;
    fgx = fgcolor;
    //fgx = 0xffffff;
    bgx = 0x0;

    int bytes = p->next_line;
    
    //nexuslog("B%d", bytes);

    //nexuslog("ncreen_base=0x%x ny=%d nytes=%d nx=%d ", screen_base, yy, bytes, xx);
    if (fontwidth <= 8)
	cdat = fontdata + (c & charmask) * fontheight;
    else
	cdat = fontdata + ((c & charmask) * fontheight << 1);
    eorx = fgx ^ bgx;

    //nexuslog("screen_base=0x%x charmask=0x%x fgx=0x%x bgx=0x%x fontheight=%d fontwidth=%d fontdata=0x%x", screen_base, charmask, fgx, bgx, fontheight, fontwidth, fontdata);
    //nexuslog("neorx=0x%x ndest", eorx);
    //nexuslog("ndest=0x%x ncdat=0x%x", dest, cdat);

    /* in case the card has 16 bit depth */
#if 0
    dest = screen_base + yy * fontheight * bytes + xx * fontwidth * 2;
    for (rows = fontheight; rows--; dest += bytes) {
	bits = *cdat++;
	pt16 = (u16 *) dest;
	//nexuslog("B%dP%d", cdat,dest);
    	fb_writew((-(bits >> 7) & eorx) ^ bgx, pt16++);
	fb_writew((-(bits >> 6 & 1) & eorx) ^ bgx, pt16++);
	fb_writew((-(bits >> 5 & 1) & eorx) ^ bgx, pt16++);
	fb_writew((-(bits >> 4 & 1) & eorx) ^ bgx, pt16++);
	if (fontwidth < 8)
	    continue;
	fb_writew((-(bits >> 3 & 1) & eorx) ^ bgx, pt16++);
	fb_writew((-(bits >> 2 & 1) & eorx) ^ bgx, pt16++);
	fb_writew((-(bits >> 1 & 1) & eorx) ^ bgx, pt16++);
	fb_writew((-(bits & 1) & eorx) ^ bgx, pt16++);
	if (fontwidth < 12)
	    continue;
	bits = *cdat++;
	fb_writew((-(bits >> 7) & eorx) ^ bgx, pt16++);
	fb_writew((-(bits >> 6 & 1) & eorx) ^ bgx, pt16++);
	fb_writew((-(bits >> 5 & 1) & eorx) ^ bgx, pt16++);
	fb_writew((-(bits >> 4 & 1) & eorx) ^ bgx, pt16++);
	if (fontwidth < 16)
	    continue;
	fb_writew((-(bits >> 3 & 1) & eorx) ^ bgx, pt16++);
	fb_writew((-(bits >> 2 & 1) & eorx) ^ bgx, pt16++);
	fb_writew((-(bits >> 1 & 1) & eorx) ^ bgx, pt16++);
	fb_writew((-(bits & 1) & eorx) ^ bgx, pt16++);
    }
#endif

#if 1
    dest = screen_base + yy * fontheight * bytes + xx * fontwidth * 4;
    for (rows = fontheight; rows--; dest += bytes) {
	bits = *cdat++;
	pt = (u32 *) dest;
	//nexuslog("B%dP%d", cdat,dest);
    	fb_writel((-(bits >> 7) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 6 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 5 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 4 & 1) & eorx) ^ bgx, pt++);
	if (fontwidth < 8)
	    continue;
	fb_writel((-(bits >> 3 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 2 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 1 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits & 1) & eorx) ^ bgx, pt++);
	if (fontwidth < 12)
	    continue;
	bits = *cdat++;
	fb_writel((-(bits >> 7) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 6 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 5 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 4 & 1) & eorx) ^ bgx, pt++);
	if (fontwidth < 16)
	    continue;
	fb_writel((-(bits >> 3 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 2 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 1 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits & 1) & eorx) ^ bgx, pt++);
    }
#endif
}

#if 0
void fbcon_cfb32_putc(struct vc_data *conp, struct display *p, int c, int yy,
		      int xx)
{
    u8 *dest, *cdat, bits;
    int bytes = p->next_line, rows;
    u32 eorx, fgx, bgx, *pt;
    int nbytes;
    u32 nfgx, nbgx;

    int fontheight = 16;
    int fontwidth = 8;
    unsigned char *screen_base = 0xe0000000;
    unsigned char *fontdata = CURFONT.data;
    unsigned char charmask = 0xff;
    nfgx = 0xaaaaaa;
    nbgx = 0x0;
    nbytes = 4096;

    dest = p->screen_base + yy * fontheight(p) * bytes + xx * fontwidth(p) * 4;

    if (fontwidth(p) <= 8)
	cdat = p->fontdata + (c & p->charmask) * fontheight(p);
    else
	cdat = p->fontdata + ((c & p->charmask) * fontheight(p) << 1);
    fgx = ((u32 *)p->dispsw_data)[attr_fgcol(p, c)];
    bgx = ((u32 *)p->dispsw_data)[attr_bgcol(p, c)];
    eorx = fgx ^ bgx;

    if (screen_base != p->screen_base)
      nexuslog("screenbase ");
    else if (fontheight != fontheight(p))
      nexuslog("fontheight ");
    else if (fontwidth != fontwidth(p))
      nexuslog("fontwidth ");
    else if (fontdata != p->fontdata)
      nexuslog("fontdata 0x%x 0x%x ", fontdata, p->fontdata);
    else if (charmask != p->charmask)
      nexuslog("charmask ");
    else if (nfgx != fgx)
      nexuslog("fgx ");
    else if (nbgx != bgx)
      nexuslog("bgx ");
    else if (nbytes != bytes)
      nexuslog("bytes ");

    //nexuslog("screen_base=0x%x yy=%d bytes=%d xx=%d ", p->screen_base, yy, bytes, xx);

    //nexuslog("next_line=%d screen_base=0x%x charmask=0x%x fgx=0x%x bgx=0x%x eorx=0x%x fontheight=%d fontwidth=%d fontdata=0x%x dispsw_data=0x%x ", p->next_line, p->screen_base, p->charmask, fgx, bgx, eorx, fontheight(p), fontwidth(p), p->fontdata, p->dispsw_data);
    //if ((fgx != 0xaaaaaa) || (bgx != 0))
    //nexuslog("fgx=0x%x bgx=0x%x", fgx, bgx);
    //nexuslog("dest=0x%x cdat=0x%x", dest, cdat);

    for (rows = fontheight(p); rows--; dest += bytes) {
	bits = *cdat++;
	pt = (u32 *) dest;
	fb_writel((-(bits >> 7) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 6 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 5 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 4 & 1) & eorx) ^ bgx, pt++);
	if (fontwidth(p) < 8)
	    continue;
	fb_writel((-(bits >> 3 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 2 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 1 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits & 1) & eorx) ^ bgx, pt++);
	if (fontwidth(p) < 12)
	    continue;
	bits = *cdat++;
	fb_writel((-(bits >> 7) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 6 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 5 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 4 & 1) & eorx) ^ bgx, pt++);
	if (fontwidth(p) < 16)
	    continue;
	fb_writel((-(bits >> 3 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 2 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 1 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits & 1) & eorx) ^ bgx, pt++);
    }
}
#endif

#if 1
void fbcon_cfb32_putc(struct vc_data *conp, struct display *p, int c, int yy,
		      int xx)
{
    u8 *dest, *cdat, bits;
    int bytes = p->next_line, rows;
    u32 eorx, fgx, bgx, *pt;

    dest = p->screen_base + yy * fontheight(p) * bytes + xx * fontwidth(p) * 4;
    nexuslog("screen_base=0x%x yy=%d bytes=%d xx=%d ", p->screen_base, yy, bytes, xx);

    if (fontwidth(p) <= 8)
	cdat = p->fontdata + (c & p->charmask) * fontheight(p);
    else
	cdat = p->fontdata + ((c & p->charmask) * fontheight(p) << 1);
    fgx = ((u32 *)p->dispsw_data)[attr_fgcol(p, c)];
    bgx = ((u32 *)p->dispsw_data)[attr_bgcol(p, c)];
    eorx = fgx ^ bgx;

    //nexuslog("next_line=%d screen_base=0x%x charmask=0x%x fgx=0x%x bgx=0x%x eorx=0x%x fontheight=%d fontwidth=%d fontdata=0x%x dispsw_data=0x%x ", p->next_line, p->screen_base, p->charmask, fgx, bgx, eorx, fontheight(p), fontwidth(p), p->fontdata, p->dispsw_data);
    //if ((fgx != 0xaaaaaa) || (bgx != 0))
    //nexuslog("fgx=0x%x bgx=0x%x", fgx, bgx);
    //nexuslog("dest=0x%x cdat=0x%x", dest, cdat);

    for (rows = fontheight(p); rows--; dest += bytes) {
	bits = *cdat++;
	pt = (u32 *) dest;
	fb_writel((-(bits >> 7) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 6 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 5 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 4 & 1) & eorx) ^ bgx, pt++);
	if (fontwidth(p) < 8)
	    continue;
	fb_writel((-(bits >> 3 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 2 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 1 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits & 1) & eorx) ^ bgx, pt++);
	if (fontwidth(p) < 12)
	    continue;
	bits = *cdat++;
	fb_writel((-(bits >> 7) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 6 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 5 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 4 & 1) & eorx) ^ bgx, pt++);
	if (fontwidth(p) < 16)
	    continue;
	fb_writel((-(bits >> 3 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 2 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits >> 1 & 1) & eorx) ^ bgx, pt++);
	fb_writel((-(bits & 1) & eorx) ^ bgx, pt++);
    }
}
#endif
void fbcon_cfb32_putcs(struct vc_data *conp, struct display *p,
		       const unsigned short *s, int count, int yy, int xx)
{
    u8 *cdat, *dest, *dest0, bits;
    u16 c;
    int rows, bytes = p->next_line;
    u32 eorx, fgx, bgx, *pt;

    dest0 = p->screen_base + yy * fontheight(p) * bytes + xx * fontwidth(p) * 4;
    c = scr_readw(s);
    fgx = ((u32 *)p->dispsw_data)[attr_fgcol(p, c)];
    bgx = ((u32 *)p->dispsw_data)[attr_bgcol(p, c)];
    eorx = fgx ^ bgx;
    while (count--) {
	c = scr_readw(s++) & p->charmask;
	if (fontwidth(p) <= 8)
	    cdat = p->fontdata + c * fontheight(p);
	else
	    cdat = p->fontdata + (c * fontheight(p) << 1);
	for (rows = fontheight(p), dest = dest0; rows--; dest += bytes) {
	    bits = *cdat++;
	    pt = (u32 *) dest;
	    fb_writel((-(bits >> 7) & eorx) ^ bgx, pt++);
	    fb_writel((-(bits >> 6 & 1) & eorx) ^ bgx, pt++);
	    fb_writel((-(bits >> 5 & 1) & eorx) ^ bgx, pt++);
	    fb_writel((-(bits >> 4 & 1) & eorx) ^ bgx, pt++);
	    if (fontwidth(p) < 8)
		continue;
	    fb_writel((-(bits >> 3 & 1) & eorx) ^ bgx, pt++);
	    fb_writel((-(bits >> 2 & 1) & eorx) ^ bgx, pt++);
	    fb_writel((-(bits >> 1 & 1) & eorx) ^ bgx, pt++);
	    fb_writel((-(bits & 1) & eorx) ^ bgx, pt++);
	    if (fontwidth(p) < 12)
		continue;
	    bits = *cdat++;
	    fb_writel((-(bits >> 7) & eorx) ^ bgx, pt++);
	    fb_writel((-(bits >> 6 & 1) & eorx) ^ bgx, pt++);
	    fb_writel((-(bits >> 5 & 1) & eorx) ^ bgx, pt++);
	    fb_writel((-(bits >> 4 & 1) & eorx) ^ bgx, pt++);
	    if (fontwidth(p) < 16)
		continue;
	    fb_writel((-(bits >> 3 & 1) & eorx) ^ bgx, pt++);
	    fb_writel((-(bits >> 2 & 1) & eorx) ^ bgx, pt++);
	    fb_writel((-(bits >> 1 & 1) & eorx) ^ bgx, pt++);
	    fb_writel((-(bits & 1) & eorx) ^ bgx, pt++);
	}
	dest0 += fontwidth(p)*4;
    }
}

void fbcon_cfb32_revc(struct display *p, int xx, int yy)
{
    u8 *dest;
    int bytes = p->next_line, rows;

    dest = p->screen_base + yy * fontheight(p) * bytes + xx * fontwidth(p) * 4;
    for (rows = fontheight(p); rows--; dest += bytes) {
	switch (fontwidth(p)) {
	case 16:
	    fb_writel(fb_readl(dest+(4*12)) ^ 0xffffffff, dest+(4*12));
	    fb_writel(fb_readl(dest+(4*13)) ^ 0xffffffff, dest+(4*13));
	    fb_writel(fb_readl(dest+(4*14)) ^ 0xffffffff, dest+(4*14));
	    fb_writel(fb_readl(dest+(4*15)) ^ 0xffffffff, dest+(4*15));
	    /* FALL THROUGH */
	case 12:
	    fb_writel(fb_readl(dest+(4*8)) ^ 0xffffffff, dest+(4*8));
	    fb_writel(fb_readl(dest+(4*9)) ^ 0xffffffff, dest+(4*9));
	    fb_writel(fb_readl(dest+(4*10)) ^ 0xffffffff, dest+(4*10));
	    fb_writel(fb_readl(dest+(4*11)) ^ 0xffffffff, dest+(4*11));
	    /* FALL THROUGH */
	case 8:
	    fb_writel(fb_readl(dest+(4*4)) ^ 0xffffffff, dest+(4*4));
	    fb_writel(fb_readl(dest+(4*5)) ^ 0xffffffff, dest+(4*5));
	    fb_writel(fb_readl(dest+(4*6)) ^ 0xffffffff, dest+(4*6));
	    fb_writel(fb_readl(dest+(4*7)) ^ 0xffffffff, dest+(4*7));
	    /* FALL THROUGH */
	case 4:
	    fb_writel(fb_readl(dest+(4*0)) ^ 0xffffffff, dest+(4*0));
	    fb_writel(fb_readl(dest+(4*1)) ^ 0xffffffff, dest+(4*1));
	    fb_writel(fb_readl(dest+(4*2)) ^ 0xffffffff, dest+(4*2));
	    fb_writel(fb_readl(dest+(4*3)) ^ 0xffffffff, dest+(4*3));
	    /* FALL THROUGH */
	}
    }
}

void fbcon_cfb32_clear_margins(struct vc_data *conp, struct display *p,
			       int bottom_only)
{
    int bytes = p->next_line;
    u32 bgx;

    unsigned int right_start = conp->vc_cols*fontwidth(p);
    unsigned int bottom_start = conp->vc_rows*fontheight(p);
    unsigned int right_width, bottom_width;

    bgx = ((u32 *)p->dispsw_data)[attr_bgcol_ec(p, conp)];

    if (!bottom_only && (right_width = p->var.xres-right_start))
	rectfill(p->screen_base+right_start*4, right_width,
		 p->var.yres_virtual, bgx, bytes);
    if ((bottom_width = p->var.yres-bottom_start))
	rectfill(p->screen_base+(p->var.yoffset+bottom_start)*bytes,
		 right_start, bottom_width, bgx, bytes);
}


    /*
     *  `switch' for the low level operations
     */

struct display_switch fbcon_cfb32 = {
    setup:		fbcon_cfb32_setup,
    bmove:		fbcon_cfb32_bmove,
    clear:		fbcon_cfb32_clear,
    putc:		fbcon_cfb32_putc,
    putcs:		fbcon_cfb32_putcs,
    revc:		fbcon_cfb32_revc,
    clear_margins:	fbcon_cfb32_clear_margins,
    fontwidthmask:	FONTWIDTH(4)|FONTWIDTH(8)|FONTWIDTH(12)|FONTWIDTH(16)
};


#ifdef MODULE
MODULE_LICENSE("GPL");

int init_module(void)
{
    return 0;
}

void cleanup_module(void)
{}
#endif /* MODULE */


    /*
     *  Visible symbols for modules
     */

EXPORT_SYMBOL(fbcon_cfb32);
EXPORT_SYMBOL(fbcon_cfb32_setup);
EXPORT_SYMBOL(fbcon_cfb32_bmove);
EXPORT_SYMBOL(fbcon_cfb32_clear);
EXPORT_SYMBOL(fbcon_cfb32_putc);
EXPORT_SYMBOL(fbcon_cfb32_putcs);
EXPORT_SYMBOL(fbcon_cfb32_revc);
EXPORT_SYMBOL(fbcon_cfb32_clear_margins);
