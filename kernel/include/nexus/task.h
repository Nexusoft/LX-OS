#ifndef __TASK_H__
#define __TASK_H__

typedef void (*TaskFunc)(void *arg);
typedef void * TaskArg;

void task_sched(TaskFunc func, TaskArg arg);
void task_init(void);

#endif

