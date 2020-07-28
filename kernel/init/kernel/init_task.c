// Leftover cruft from linux init_task. We might be able to do away with this...

#ifndef INIT_TASK_SIZE
# define INIT_TASK_SIZE	8192 // 2048*sizeof(long)
#endif

unsigned long init_task_union[INIT_TASK_SIZE/sizeof(long)]
	__attribute__((__section__(".data.init_task")));
