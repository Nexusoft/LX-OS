#include <stdio.h>
#include <nexus/Console.interface.h>

int main(int argc, char **argv) {
  int mousehandle = Console_Mouse_Init();
  int print_limit = 10;
  printf("Mouse handle %d\n", mousehandle);
  while(print_limit >= 0) {
    int rv = Console_Mouse_Poll(mousehandle);
    printf("mouse_poll() returned %d\n", rv);

#define NUM_EVENTS (4)
    struct MouseEvent events[NUM_EVENTS];
    int num_read = Console_Mouse_Read(mousehandle, events, NUM_EVENTS);
    printf("Read %d: ", num_read);

    int i;
    for(i=0; i < num_read; i++) {
      printf("[%d]: dx=%d dy=%d dz=%d buttons=%02x,", i, 
	     events[i].dx, events[i].dy, events[i].dz, events[i].buttons);
    }
    printf("\n");
  }
  return 0;
}
