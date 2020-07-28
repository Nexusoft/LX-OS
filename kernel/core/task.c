/** Nexus OS: background threads to assign code that has to run at a
              convenient time and with interrupts enabled. */

#include <linux/skbuff.h>
#include <nexus/ipc.h>
#include <nexus/task.h>
#include <nexus/synch-inline.h>

#define NUM_TASK_THREADS (1)
#define MAX_TASK_QUEUE (100)

typedef struct Task {
  int present;
  TaskFunc func;
  TaskArg arg;
} Task;

/** main task queue */
static Task task_queue[MAX_TASK_QUEUE];
static int task_queue_insert_idx;
static unsigned int task_queue_remove_idx;
static Sema task_queue_sema = SEMA_INIT;

/** schedule something to run at a safe point, out of interrupt context */
void 
task_sched(TaskFunc func, TaskArg arg) 
{
  assert(check_intr() == 0);
  assert(task_queue[task_queue_insert_idx].present == 0); /* watch for full queue */

  Task *newtask = &task_queue[task_queue_insert_idx];
  newtask->present = 1;
  newtask->func = func;
  newtask->arg = arg;
  task_queue_insert_idx = (task_queue_insert_idx + 1) % MAX_TASK_QUEUE;
  
  V(&task_queue_sema);
}

/* background thread waiting on tasks */
static int 
do_tasks(void *ignoredarg)
{
  while(1) {
    P(&task_queue_sema);

    /* atomically increment the idx and tell me what it was */
    int idx = atomic_get_and_addto((int *) &task_queue_remove_idx, 1);
    assert(idx < 0xffffffff); /* watch for wraparound */
    idx %= MAX_TASK_QUEUE;

    Task *task = &task_queue[idx];
    TaskFunc func = task->func;
    TaskArg arg = task->arg;

    /* now the entry can be overwritten */
    task->present = 0;

    /* do the task */
    func(arg);
  }

  return -1;
}


void task_init(void)
{
	int i;

	for(i = 0; i < NUM_TASK_THREADS; i++) 
		nexusthread_fork(do_tasks, NULL);
}

