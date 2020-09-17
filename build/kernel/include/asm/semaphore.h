#ifndef _I386_SEMAPHORE_H
#define _I386_SEMAPHORE_H

//#include <linux/linkage.h>

#ifdef __NEXUSKERNEL__

// nexus has its own locks
#include <nexus/synch.h>
#include <nexus/defs.h>
#include <nexus/synch-inline.h>

struct semaphore {
	Sema s;
};

#define DECLARE_MUTEX(name)  struct semaphore name = { SEMA_MUTEX_INIT }
#define DECLARE_MUTEX_LOCKED(name) struct semaphore name = { SEMA_INIT }

static inline void sema_init(struct semaphore *sem, int val) {
	sema_initialize(&(sem->s), val);
}
static inline void init_MUTEX (struct semaphore *sem)
{
	sema_initialize(&(sem->s), 1);
}
static inline void init_MUTEX_LOCKED (struct semaphore *sem)
{
	sema_initialize(&(sem->s), 0);
}

static inline void down(struct semaphore *sem)
{
	P(&(sem->s));
}
static inline void up(struct semaphore *sem)
{
	V(&(sem->s));
}

#endif
#endif
