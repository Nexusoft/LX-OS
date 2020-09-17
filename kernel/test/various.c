/** NexusOS: small set of regression tests. 
 
    These are called from the unittest framework in test.c */

#include <nexus/defs.h>
#include <nexus/clock.h>
#include <nexus/thread.h>
#include <nexus/ipc.h>
#include <nexus/synch.h>
#include <nexus/transfer.h>
#include <nexus/user_compat.h>

#ifndef NDEBUG
int
ipcpoll_unittest(void)
{
	char *in, out[2];
	int portnum;
	
	portnum = IPC_CreatePort(0);
	
	if (ipc_poll(portnum, IPC_READ)) {
		printkx(PK_IPC, PK_WARN, "[ipc] return ready without data\n");
		return -1;
	}

	in = gcalloc(1, 1);
	if (IPC_Send(portnum, in, 1)) {
		printkx(PK_IPC, PK_WARN, "[ipc] send failed\n");
		return -1;
	}
	
	if (!ipc_poll(portnum, IPC_READ)) {
		printkx(PK_IPC, PK_WARN, "[ipc] return not ready with data\n");
		return -1;
	}

	if (IPC_Recv(portnum, out, 2) != 1) {
		printkx(PK_IPC, PK_WARN, "[ipc] recv failed\n");
		return -1;
	}

	IPC_DestroyPort(portnum);
	return 0;
}

/** Test thread scheduling */
int 
run_thread_test(void) 
{
  int term0 = 0;
  int term1 = 0;
 
  // nested function: worker thread
  int threadtesthelper(void *arg) 
  {
    int i;

    for (i = 0; i < 100; i++) {
      nexusthread_yield();
    }

    swap((int *) arg, 1);
    return 0;
  }

  nexusthread_fork(threadtesthelper, (int *) &term0); 
  nexusthread_fork(threadtesthelper, (int *) &term1); 
  
  while (atomic_get(&term0) == 0 ||
	 atomic_get(&term1) == 0)
    nexusthread_yield();
  
  return 0;
}

/** Test thread creation and deletion */
int
run_thread_spawn_test(void)
{
#define SPAWN_COUNT 100
  Sema spawn_sema;
  int i;

  // child: wake parent
  int spawn_child(void *arg)
  {
    V(&spawn_sema);
    return 0;
  }

  // spawn a number of children
  spawn_sema = SEMA_INIT_KILLABLE;
  for (i = 0; i < SPAWN_COUNT; i++) {
    // occasionally force yield, to simulate concurrency
    if (!(i % 10))
      nexusthread_yield();
    nexusthread_fork(spawn_child, NULL);
  }
  
  // wait
  for (i = 0; i < SPAWN_COUNT; i++)
    P(&spawn_sema);

  return 0;
}

int run_sema_pingpong_test(void) {
#define RUNS 10
  Sema a, b;
  int done1, done2, j;

  // nested function: worker 1
  int sema_thread1(void *arg) 
  {
    int i;

    for (i = 0; i < RUNS; i++) {
	P(&a);
    	V(&b);
    }
 
    swap(&done1, 1);
    return 0;
  }

  // nested function: worker 2
  int sema_thread2(void *arg) 
  {
    int i;

    for (i = 0; i < RUNS; i++) {
    	V(&a);
	P(&b);
    }
  
      swap(&done2, 1);
      return 0;
  }

  a = SEMA_INIT_KILLABLE;
  b = SEMA_INIT_KILLABLE;
  done1 = 0;
  done2 = 0;

  nexusthread_fork(sema_thread1, NULL);
  nexusthread_fork(sema_thread2, NULL);

  while (!done1 || !done2)
    nexusthread_yield();
	    
  return 0;
}
#endif

