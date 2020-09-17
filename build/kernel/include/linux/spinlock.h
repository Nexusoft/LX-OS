#ifndef __LINUX_SPINLOCK_H
#define __LINUX_SPINLOCK_H

#include <asm/system.h>

/*
 * These are the generic versions of the spinlocks and read-write
 * locks..
 */
#define spin_lock_irqsave(lock, flags)		do { local_irq_save(flags);       spin_lock(lock); } while (0)
#define spin_lock_irq(lock)			do { local_irq_disable();         spin_lock(lock); } while (0)
#define spin_lock_bh(lock)			do { local_bh_disable();          spin_lock(lock); } while (0)

#define read_lock_irqsave(lock, flags)		do { local_irq_save(flags);       read_lock(lock); } while (0)
#define read_lock_irq(lock)			do { local_irq_disable();         read_lock(lock); } while (0)
#define read_lock_bh(lock)			do { local_bh_disable();          read_lock(lock); } while (0)

#define write_lock_irqsave(lock, flags)		do { local_irq_save(flags);      write_lock(lock); } while (0)
#define write_lock_irq(lock)			do { local_irq_disable();        write_lock(lock); } while (0)
#define write_lock_bh(lock)			do { local_bh_disable();         write_lock(lock); } while (0)

#define spin_unlock_irqrestore(lock, flags)	do { spin_unlock(lock);  local_irq_restore(flags); } while (0)
#define spin_unlock_irq(lock)			do { spin_unlock(lock);  local_irq_enable();       } while (0)
#define spin_unlock_bh(lock)			do { spin_unlock(lock);  local_bh_enable();        } while (0)

#define read_unlock_irqrestore(lock, flags)	do { read_unlock(lock);  local_irq_restore(flags); } while (0)
#define read_unlock_irq(lock)			do { read_unlock(lock);  local_irq_enable();       } while (0)
#define read_unlock_bh(lock)			do { read_unlock(lock);  local_bh_enable();        } while (0)

#define write_unlock_irqrestore(lock, flags)	do { write_unlock(lock); local_irq_restore(flags); } while (0)
#define write_unlock_irq(lock)			do { write_unlock(lock); local_irq_enable();       } while (0)
#define write_unlock_bh(lock)			do { write_unlock(lock); local_bh_enable();        } while (0)
#define spin_trylock_bh(lock)			({ int __r; local_bh_disable();\
						__r = spin_trylock(lock);      \
						if (!__r) local_bh_enable();   \
						__r; })

#include <linux/stringify.h>

#define LOCK_SECTION_NAME			\
	".text.lock." __stringify(KBUILD_BASENAME)

#define LOCK_SECTION_START(extra)		\
	".subsection 1\n\t"			\
	extra					\
	".ifndef " LOCK_SECTION_NAME "\n\t"	\
	LOCK_SECTION_NAME ":\n\t"		\
	".endif\n\t"

#define LOCK_SECTION_END			\
	".previous\n\t"

#ifdef CONFIG_SMP
#error No smp implementation currently. Sorry.
#else

#define atomic_dec_and_lock(atomic,lock) atomic_dec_and_test(atomic)
#define ATOMIC_DEC_AND_LOCK

typedef struct { } spinlock_t;
#define SPIN_LOCK_UNLOCKED (spinlock_t) { }

#define spin_lock_init(lock)	do { } while(0)
#define spin_lock(lock)			(void)(lock) /* Not "unused variable". */
#define spin_is_locked(lock)	(0)
#define spin_trylock(lock)		({1; })
#define spin_unlock_wait(lock)	do { } while(0)
#define spin_unlock(lock)		do { } while(0)


typedef struct { } rwlock_t;
#define RW_LOCK_UNLOCKED (rwlock_t) { }

#define rwlock_init(lock)		do { } while(0)
#define read_lock(lock)			(void)(lock) /* Not "unused variable". */
#define read_unlock(lock)		do { } while(0)
#define write_lock(lock)		(void)(lock) /* Not "unused variable". */
#define write_unlock(lock)		do { } while(0)

typedef struct {
    spinlock_t lock;
} spinlock_cacheline_t;

#endif /* !CONFIG_SMP */

#endif /* __LINUX_SPINLOCK_H */
