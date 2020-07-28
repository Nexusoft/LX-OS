#include <stdio.h>
#include <stdlib.h>
#include <nexus/Console.interface.h>

extern unsigned int printhandle;

static void FB_Bitfield_print(struct FB_Bitfield bf) {
  printf("offset=%d length=%d", bf.offset, bf.length);
}

int main(int argc, char **argv) {
  struct FB_Info info;
  volatile char *frame_buf = (char *)(16 * 0x400000);
  int rv = Console_MapFrameBuffer(printhandle, frame_buf, &info);
  if(rv != 0) {
    printf("Console_Map error!\n");
    return -1;
  }
  printf("Geometry: res=(%d,%d) size=(%d,%d) line_length=%d, bpp=%d\n", 
	 info.xres, info.yres, info.width, info.height, 
	 info.line_length, info.bpp);
  printf("Red "); FB_Bitfield_print(info.red); printf("\n");
  printf("Green "); FB_Bitfield_print(info.green); printf("\n");
  printf("Blue "); FB_Bitfield_print(info.blue); printf("\n");

  frame_buf = info.fb;
  printf("Frame buf real start is %p", frame_buf);
  // const int bottom_line = (info.yres - 1) * info.line_length;
  const int bottom_line = (info.yres / 4) * info.line_length;
  while(1) {
    memset(frame_buf, 0x80, info.line_length * 10);
    memset(frame_buf + bottom_line, 0xff, info.line_length * 10);
    usleep(100000);
    memset(frame_buf, 0xff, info.line_length * 10);
    memset(frame_buf + bottom_line, 0x80, info.line_length * 10);
    usleep(100000);
    break;
  }
  while(1) {
    sleep(1);
  }
}
