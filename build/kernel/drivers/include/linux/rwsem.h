#ifndef _LINUX_RWSEM_H
#define _LINUX_RWSEM_H

// nexus has its own locking
#include <nexus/synch.h>

struct rw_semaphore {
	struct Sema *s;
};

#define DECLARE_RWSEM(sem)	struct rw_semaphore sem
#define INIT_RWSEM(sem)		do { (sem)->s = sema_new_mutex(); } while (0)

#define down_read(sem)		do { P((sem)->s); } while (0)
#undef down_read_trylock
#define up_read(sem)		do { V((sem)->s); } while (0)

#define down_write(sem)		do { P((sem)->s); } while (0)
#undef down_write_trylock
#define up_write(sem)		do { V((sem)->s); } while (0)

#endif // _LINUX_RWSEM_H
