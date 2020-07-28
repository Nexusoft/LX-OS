#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>

#include <nexus/IPC.interface.h>
#include "InterposeEventDriver.interface.h"
#include <nexus/Tap.interface.h>
#include "TapNotificationHandler.interface.h"

#include <nexus/hashtable.h>
#include <nexus/vector.h>
#include <nexus/sema.h>

#include "all-null.h"

#include <unistd.h>

int g_event_port_handle;
extern int g_notification_port_handle;
int g_wrap_pattern;
int do_sanity_checks = 0;

static void *event_thread_handler(void *ctx);
static void *notification_thread_handler(void *ctx);

#define NUM_THREADS (16)
pthread_t event_thread[NUM_THREADS];
pthread_t notification_thread[NUM_THREADS];

VetoCheckMode veto_check_mode = NO_CHECK;
int saw_veto = 0, num_vetoes = 0;

int main(int argc, char **argv) {
  Port_Num server_port;
  g_event_port_handle = IPC_CreatePort(&server_port);
  InterposeEventDriver_setServerTarget(g_event_port_handle);
  TapNotificationHandler_serverInit(); // allocate g_notification_port_handle

  int i;
  for(i=0; i < NUM_THREADS; i++) {
      int rv0 = pthread_create(&notification_thread[i], NULL,
			      notification_thread_handler, (void *)i);
      if(rv0 != 0) {
	printf("error forking notification thread!\n");
	exit(-1);
      }
      int rv1 = pthread_create(&event_thread[i], NULL,
			  event_thread_handler, (void *)i);
      if(rv1 != 0) {
	printf("error forking event thread!\n");
	exit(-1);
      }
      printf("notify = %lu, event = %lu\n", notification_thread[i], event_thread[i]);
  }

  printf("Using event channel %d, notification channel %d\n",
	 g_event_port_handle, g_notification_port_handle);
  // bind to global

  char pattern_str[128];
  if(argc == 1) {
    sprintf(pattern_str, "ALL");
  } else {
    assert(argc >= 2);
    int target_ipd_id = atoi(argv[1]);
    sprintf(pattern_str, "Wrap(%d)", target_ipd_id);
    if(argc >= 3) {
      int mode = atoi(argv[2]);
      switch(mode) {
      case 0:
	veto_check_mode = NO_VETOES;
	printf("Veto mode \"no vetoes\"\n");
	break;
      case 1:
	veto_check_mode = HAS_VETO;
	printf("Veto mode \"has vetoes\"\n");
	break;
      default:
	printf("Unknown veto mode %d\n", mode);
	exit(-1);
      }
    }
  }
  g_wrap_pattern = 
    Tap_AddPattern(pattern_str, g_event_port_handle, g_notification_port_handle);
  printf("AddPattern(%s) => %d\n", pattern_str, g_wrap_pattern);

  while(1) {
    if(1) {
      char line[80];
      fgets(line, sizeof(line), stdin);
      printf("Stats: %d calls, %d transfers\n", call_count, transfer_count);
    } else {
      sleep(60);
    }
  }
}

static void *event_thread_handler(void *ctx) {
  while(1) {
    InterposeEventDriver_processNextCommand();
  }
}

static void *notification_thread_handler(void *ctx) {
  while(1) {
    TapNotificationHandler_processNextCommand();
  }
}

