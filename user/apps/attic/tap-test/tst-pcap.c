#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>

#include <nexus/IPC.interface.h>
#include "PcapInterposeEventDriver.interface.h"
#include <nexus/Tap.interface.h>
#include "TapNotificationHandler.interface.h"

#include <nexus/hashtable.h>
#include <nexus/vector.h>
#include <nexus/sema.h>

#include "all-null.h"
#include <nexus/netcomp.h>

#include <unistd.h>

int g_event_port_handle;
extern int g_notification_port_handle;
int do_sanity_checks = 0;

static void *event_thread_handler(void *ctx);
static void *notification_thread_handler(void *ctx);
static void *async_handler(void *ctx);

#define NUM_THREADS (16)
pthread_t event_thread[NUM_THREADS];
pthread_t notification_thread[NUM_THREADS];

pthread_t async_thread;

VetoCheckMode veto_check_mode = NO_CHECK;
int saw_veto = 0, num_vetoes = 0;

int main(int argc, char **argv) {
  printf("PCAP test not synchronized with PNIC/VNIC update for Xen and e1000\n");
  assert(0);
  Port_Num server_port;
  g_event_port_handle = IPC_CreatePort(&server_port);
  PcapInterposeEventDriver_setServerTarget(g_event_port_handle);
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
  pthread_create(&async_thread, NULL, async_handler, NULL);

  printf("Using event channel %d, notification channel %d\n",
	 g_event_port_handle, g_notification_port_handle);
  // bind to global

  char pattern_str[128];
  if(argc < 2) {
    goto print_usage;
  }
  if(strcmp(argv[1], "vm") == 0) {
    if(argc < 3) {
      goto print_usage;
    }
    IPD_ID vm_vnic = atoi(argv[2]);
    sprintf(pattern_str, "Wrap(%d)", vm_vnic);
    int wrap_pattern = 
      Tap_AddPattern(pattern_str, g_event_port_handle, g_notification_port_handle);
    printf("AddPattern(%s) => %d\n", pattern_str, wrap_pattern);
  } else if(strcmp(argv[1], "pnic") == 0) {
    if(argc < 3) {
      goto print_usage;
    }
    IPD_ID pnic = atoi(argv[2]);
    sprintf(pattern_str, "Wrap(%d)", pnic);
    int wrap_pattern = 
      Tap_AddPattern(pattern_str, g_event_port_handle, g_notification_port_handle);
    printf("AddPattern(%s) => %d\n", pattern_str, wrap_pattern);
  } else {
  print_usage:
    printf("Usage tst-pcap {vm <vm vnic #> | pnic <pnic #>}\n");
    exit(-1);
  }

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
    PcapInterposeEventDriver_processNextCommand();
  }
}

static void *notification_thread_handler(void *ctx) {
  while(1) {
    TapNotificationHandler_processNextCommand();
  }
}

static void *async_handler(void *ctx) {
  while(1) {
    PcapInterposeEventDriver_processNextCommand_ext(SERVERPROCESSOR_ASYNC_AUTO_DONE, DEFAULT_PROCESSOR_HANDLE, ((ServerProcessorData ) { }));
  }
}
