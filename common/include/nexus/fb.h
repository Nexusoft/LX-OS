#ifndef _NEXUS_FB_H_
#define _NEXUS_FB_H_

struct FB_Bitfield { // Like Linux's "fb_bitfield"
  int offset;
  int length;
};

struct FB_Info {
  char *fb; // The frame buffer

  int fontheight;
  int skip_ylength; // number of lines reserved for Nexus

  // Frame buffer geometry, excluding Nexus portion
  int xres, yres; // Number of horizontal and vertical pixels
  int width, height; // size of the device in mm

  int line_length; // The amount to add to move from (x,y) to (x,y+1), in bytes
  int bpp; // in bits

  struct FB_Bitfield red;
  struct FB_Bitfield green;
  struct FB_Bitfield blue;
};

#define FB_AREA_LENGTH (0x400000)

#endif // _NEXUS_FB_H_
