/** NexusOS: minimal test of console:mouse interface */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <nexus/rdtsc.h>
#include <nexus/kshmem.h>
#include <nexus/Console.interface.h>

#define RUNTIME (60)
#define WIDTH	1024
#define HEIGHT	768
#define BPP	3

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

/** print a black screen with a cursor */
static int
mouse_printcursor(int dx, int dy, unsigned char cursor)
{
#define PIXEL_R(REGION, X, Y)	(REGION[((WIDTH * Y) + X) * BPP])
#define PIXEL_G(REGION, X, Y)	(REGION[(((WIDTH * Y) + X) * BPP) + 1])
#define PIXEL_B(REGION, X, Y)	(REGION[(((WIDTH * Y) + X) * BPP) + 2])

	static int x = WIDTH / 2, y = HEIGHT / 2;
	int horiz, vert;
	char *frame;

	// update cursor
	if (dx < 10)
		x = max(10, x + dx);
	else
		x = min(WIDTH - 10, x + dx);
	if (dy < 10)
		y = max(10, y + dy);
	else
		y = min(HEIGHT - 10, y + dy);

	// create frame
	frame = calloc(1, WIDTH * HEIGHT * BPP);
	for (horiz = x - 4; horiz <= x + 4; horiz++)
		for (vert = y - 3; vert <= y + 3; vert++) {
			PIXEL_R(frame, horiz, vert) = cursor & 1 ? 0 : 0xff;
			PIXEL_G(frame, horiz, vert) = cursor & 2 ? 0 : 0xff;
			PIXEL_B(frame, horiz, vert) = cursor & 4 ? 0 : 0xff;
		}

	// update frame
	Console_Blit_Frame(frame, WIDTH, HEIGHT);
	free(frame);

	return 0;
}

int main(int argc, char **argv) {
  struct MouseEvent event;
  uint64_t tend;
  
  printf("[mouse] testing mouse movement for %d seconds\n", RUNTIME);

  tend = rdtsc64() + (RUNTIME * NXCLOCK_RATE);
  while (rdtsc64() < tend) {

	  // read event
	  if (Console_Mouse_Read(&event) < 0) {
		  fprintf(stderr, "[mouse] fewer events than expected\n");
		  return 1;
	  }

	  // print event
	  mouse_printcursor(event.dx, event.dy, event.buttons);
  }

  printf("[mouse] OK. test succeeded\n");
  return 0;
}

