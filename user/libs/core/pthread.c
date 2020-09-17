/** Nexus OS: Implementation of pthreads */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <semaphore.h>
#include <sys/time.h>

#include <nexus/tls.h>
#include <nexus/defs.h>
#include <nexus/queue.h>
#include <nexus/types.h>
#include <nexus/sema.h>
#include <nexus/rdtsc.h>
#include <nexus/kshmem.h>
#include <nexus/pthread-nexus.h>
#include <nexus/pthread-private.h>

#include <nexus/Mem.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>

#define DEFAULT_BASE (0x90020000)

/// communicate thread information from parent to child 
struct ThreadSpec {
  void *(*start_routine)(void *);
  void *arg;
  struct PThread_Stack stack;
  pthread_attr_t attr;
};

unsigned long __thread_default_stack_size = 32 * PAGESIZE;
unsigned long __thread_global_stack_base = DEFAULT_BASE;
unsigned long __thread_global_stack_limit = DEFAULT_BASE + 0x10000000;
static int stack_off;

static __thread PThread threadtcb;

////////  simple support functions  ////////

static inline uint32_t 
roundup(uint32_t input, uint32_t size) 
{
  return ((input + size - 1) / size) * size;
}

static inline uint32_t 
page_rounddown(uint32_t input) 
{
  return input & ~(PAGESIZE - 1);
}


////////  thread add/get  ////////

pthread_t 
pthread_self(void)
{
	return threadtcb.threadid;
}

int 
pthread_equal (pthread_t __thread1, pthread_t __thread2) 
{
	return (unlikely(__thread1 == __thread2)) ? 1 : 0;
}

pthread_t 
pthread_threadid(PThread *p)
{ 
	return p->threadid; 
}

struct PThread *
pthread_get_my_tcb(void) 
{
	return &threadtcb;
}


////////  initialization  ////////

pthread_attr_t defaultattr = {
  PTHREAD_CREATE_JOINABLE,
  SCHED_OTHER,
  {0},
  PTHREAD_EXPLICIT_SCHED,
  PTHREAD_SCOPE_SYSTEM,
  0,
  0,
  0,
  0,
};

static void 
pthread_attr_init_or_default(pthread_attr_t *dest, const pthread_attr_t *template) 
{
	if (!template)
		memcpy(dest, &defaultattr, sizeof(pthread_attr_t));
	else
		memcpy(dest, template, sizeof(pthread_attr_t));
}

int 
pthread_attr_init(pthread_attr_t *attr)
{
	memcpy(attr, &defaultattr, sizeof(pthread_attr_t));
	return 0;
}


////////  process control  ////////


int
pthread_yield(void)
{
	Thread_Yield();
	return 0;
}

////////  forking  ////////

struct ThreadSpec thread_main;

static void 
pthread_init_new(PThread *new, struct ThreadSpec *spec) 
{
	memset(new, 0, sizeof(PThread));

	new->threadid = Thread_GetID();
	new->canceltype = PTHREAD_CANCEL_DEFERRED;
	new->cancelstate = PTHREAD_CANCEL_ENABLE;
	
	new->attr = spec->attr;
	new->stack = spec->stack;
}

static int 
fork_post_tls(void *arg) 
{
  struct ThreadSpec fork_spec = *(struct ThreadSpec *) arg;
  
  pthread_init_new(pthread_get_my_tcb(), &fork_spec);
  if (arg == &thread_main)
    return 0;

  free(arg);

  // call user code. afterwards pthread_exit will run
  return (int) fork_spec.start_routine(fork_spec.arg);
}

static void pthread_exit_auto(void *unused);

static void 
fork_pre_tls(void *arg) 
{
  // We need to do pthread_exit() as a continuation, because it
  // needs to be called before the TLS is deallocated.
  // By the time tls_setup_and_start() returns, the TLS is gone, and
  // pthread_exit() will fail.
  tls_setup_and_start(fork_post_tls, (uint32_t) arg, 0, pthread_exit_auto);

  // not reached 
  assert(0);
}

void pthread_init_main(unsigned int stackbase)
{
#ifndef NDEBUG
  // Sema and CondVar's are hidden inside char[48] variables in pthreadtypes.h
  assert(sizeof(CondVar) <= 48 - sizeof(int));
  assert(sizeof(Sema) <= 48 - sizeof(int));
#endif

  // initialize main thread
  fork_post_tls((void *) &thread_main);
}

int 
pthread_create(pthread_t *thread, const pthread_attr_t *attr, 
	       void *(*start_routine)(void *), void *arg)
{
  unsigned long new_stack_v[3];
  unsigned long stack_hint, stack_len, stack_end;
  struct ThreadSpec *spec;
  int i, num_pages, ret, off;

  // XXX Band-aid for RACE CONDITION on thread creation
  //     I only see this when starting >20 threads and only noticed it
  //     on my last day in the lab. XXX create a real solution
  //
  //     To reproduce: start guard on boot without debug options
  Thread_Yield();

  // find a memory region for the new stack
  off = atomic_get_and_addto(&stack_off, 1);
  num_pages = roundup(__thread_default_stack_size, PAGESIZE) / PAGESIZE;
  
  // set pointers
  stack_len  = __thread_default_stack_size + PAGESIZE;
  stack_hint = __thread_global_stack_base + (stack_len * off); 
  stack_end  = stack_hint + stack_len;
  if (stack_end > __thread_global_stack_limit) {
    fprintf(stderr, "[pthread] create: out of stack space\n");
    abort();
  }

  spec = calloc(1, sizeof(struct ThreadSpec)); // freed in .._init_main
  spec->start_routine = start_routine;
  spec->arg = arg;
  pthread_attr_init_or_default(&spec->attr, attr);

  // setup the new stack
  spec->stack.first_page = stack_hint + PAGESIZE;
  spec->stack.num_pages = num_pages;

  // construct the initial values on the current stack, to be copied by kernel
  new_stack_v[0] = 0; // location of return address if this was a regular call
  new_stack_v[1] = (unsigned int) spec;
  new_stack_v[2] = 0;
  const int INITIAL_STACK_SIZE = 12;

  // fork
  ret = Thread_Fork(fork_pre_tls, (void*) spec->stack.first_page, 
      	            num_pages, new_stack_v, INITIAL_STACK_SIZE);

  if (ret < 0) {
    fprintf(stderr, "[pthread] create: fork failed\n");
    free(spec);
    abort();
  }

  *thread = ret;
  return 0;
}

void 
pthread_exit(void *retval) 
{
  // XXX make value_ptr available to pthread_join (implement pthread_join)
  
  //Mem_FreePages(threadtcb.stack_first_page, threadtcb.stack.num_pages);
  
  Thread_ExitThread();

  // never reached
  assert(0);
  exit(-1); // suppress gcc noreturn warning
}

// called if thread exits without calling pthread_exit(..)
void
pthread_exit_auto(void *unused)
{
  pthread_exit(NULL);
}

////////  mutex  ////////

/** After static initialization, pthreads hold a NULL pointer to a Nexus 
    semaphore. Prior to each sema access, call this function to see if a 
    sema exists. If not, it adds one.
 
    This is obviously slow, but was the shortest way to get a sema cleanly
    into uclibc's headers. XXX speed up */
static void
pthread_mutex_initnexus(pthread_mutex_t *mutex)
{
	// XXX switch to a separate lock per mutex
	static int init_spinlock;

	spinlock_ex(&init_spinlock, "pthread init mutex");
	if (unlikely(!mutex->sema)) {
		mutex->sema = sema_new();
		sema_set(mutex->sema, 1);  // it's a mutex
	}
	spinunlock(&init_spinlock);
}

int
pthread_mutexattr_init(pthread_mutexattr_t *attr)
{
	memset(attr, 0, sizeof(*attr));
	return 0;
}

int
pthread_mutexattr_destroy(pthread_mutexattr_t *attr)
{
	return 0;
}

int
pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int pshared)
{
	if (pshared == PTHREAD_PROCESS_SHARED) {
		// fprintf(stderr, "warning: trying to make a mutex shared\n");
		// causes crash, don't: return ENOTSUP;
	}

	return 0;
}

int 
pthread_mutexattr_settype(pthread_mutexattr_t *attr, int kind)
{
#if 0
	attr->__mutexkind = kind;
	return 0;
#else
	// warning: unhandled mutex attribute);
	return 0;
#endif
}

int
pthread_mutexattr_gettype(const pthread_mutexattr_t *attr, int *kind)
{
	*kind = attr->__mutexkind;
	return 0;
}

int 
pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *attr) 
{
	*m = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
	if (attr) {
		// warning: unhandled mutex attribute
	}

	// nexus specific fields
	pthread_mutex_initnexus(m);
	m->owner = 0;

	return 0;
}

#if 0
static int 
finish_locking(pthread_mutex_t *m) 
{
	switch(m->__m_kind) {
	case PTHREAD_MUTEX_TIMED_NP:		P(m->sema); return 0; ///< causes deadlocks
	case PTHREAD_MUTEX_RECURSIVE_NP:	m->__m_count++; return 0;
	case PTHREAD_MUTEX_ERRORCHECK_NP:	return EDEADLK;
	default:				return 0;
	}
}
#endif

// XXX clearly, switch to a lock per mutex
static int big_mutex_lock;

// does not support all locktypes XXX fix
int 
pthread_mutex_lock(pthread_mutex_t *mutex)
{
	pthread_t me = pthread_self();

	if (!mutex)
		return EINVAL;

	pthread_mutex_initnexus(mutex);

	// this simple mutex does NOT allow recursive locking
	if (mutex->owner == me)	{
		fprintf(stderr, "RECURSIVE lock detected. unimplemented\n");
		Thread_Exit(1, 0, 0);
	}

	P(mutex->sema);
  	
	spinlock_ex(&big_mutex_lock, "pt biglock");
	mutex->owner = me;
  	spinunlock(&big_mutex_lock);

	return 0;
}

int 
pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	pthread_t me = pthread_self();
	 
  	spinlock_ex(&big_mutex_lock, "pt biglock");
	if (mutex->owner) {
 	 	spinunlock(&big_mutex_lock);
		return EBUSY;
	}

	mutex->owner = me;
  	spinunlock(&big_mutex_lock);
	return 0;
}

int 
pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	if (unlikely(!mutex))
		return EINVAL;

	pthread_mutex_initnexus(mutex);
  	spinlock_ex(&big_mutex_lock, "pt biglock");
	mutex->owner = 0;
	spinunlock(&big_mutex_lock);
	V_nexus(mutex->sema);
	return 0;
}

int 
pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	if (!mutex)
		return EINVAL;

	if (mutex->__m_count)
		return EINVAL;

	assert(mutex->sema);
	sema_destroy(mutex->sema);
	return 0;
}


////////  thread cancel/join  ////////

int 
pthread_cancel(pthread_t thread) 
{
	// unimplemented
	return ESRCH;
}

int 
pthread_setcancelstate(int state, int *oldstate)
{
#ifndef NDEBUG
  if ((state != PTHREAD_CANCEL_ENABLE) && (state != PTHREAD_CANCEL_DISABLE))
    return EINVAL;
#endif

  if (oldstate)
    *oldstate = pthread_get_my_tcb()->cancelstate;

  pthread_get_my_tcb()->cancelstate = state;
  return 0;
}
                                                                               
int 
pthread_setcanceltype(int type, int *oldtype)
{
#ifndef NDEBUG
  if((type != PTHREAD_CANCEL_DEFERRED) && (type != PTHREAD_CANCEL_ASYNCHRONOUS))
    return EINVAL;
#endif

  if (oldtype)
    *oldtype = pthread_get_my_tcb()->canceltype;

  pthread_get_my_tcb()->canceltype = type;
  return 0;
}

void pthread_testcancel(void)
{
  if (pthread_get_my_tcb()->cancelreq != 1)
    return;

  if (pthread_get_my_tcb()->cancelstate == PTHREAD_CANCEL_ENABLE)
    exit(0);
}

int 
pthread_join(pthread_t th, void **thread_return) 
{
  printf("unimplemented function %s called\n", __FUNCTION__); 
  return 0;
}

Sema once_mutex = SEMA_MUTEX_INIT;

int pthread_once (pthread_once_t *once_control,
		  void (*init_routine) (void)) {
  /* XXX Depending on whether the LOCK_IN_ONCE_T is defined use a
     global lock variable or one which is part of the pthread_once_t
     object.  */
  if (*once_control == PTHREAD_ONCE_INIT)
    {
      P(&once_mutex);

      /* XXX This implementation is not complete.  It doesn't take
         cancelation and fork into account.  */
      if (*once_control == PTHREAD_ONCE_INIT)
        {
          init_routine ();

          *once_control = !PTHREAD_ONCE_INIT;
        }

      V_nexus(&once_mutex);
    }

  return 0;
}


////////  condition variables  ////////

/** See pthread_mutex_initnexus */
static void
pthread_cond_initnexus(pthread_cond_t *cond)
{
	static int lock;

	spinlock_ex(&lock, "pthread init cond");
	if (unlikely(!cond->condvar))
		cond->condvar = CondVar_new();
	spinunlock(&lock);
}

int 
pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *cond_attr) 
{
	if (cond_attr) {
		// warning: unhandled condvar attribute
	}

	*cond = (pthread_cond_t) PTHREAD_COND_INITIALIZER;
	pthread_cond_initnexus(cond);

	return 0;
}

int 
pthread_cond_destroy(pthread_cond_t *cond) 
{
	if (cond->condvar)
		CondVar_del(cond->condvar);

	// see .._mutex_destroy for why do not destroy the condvar itself

	return 0;
}

int 
pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) 
{
	pthread_cond_initnexus(cond);
	CondVar_wait(cond->condvar, mutex->sema);
	return 0;
}

int 
pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
		       const struct timespec *abstime)
{
	struct timeval tv;
	uint64_t tsc;
	int usecs;

	pthread_cond_initnexus(cond);
	
	// translate abstime to usecs
	gettimeofday(&tv, NULL);
	usecs = (abstime->tv_sec * 1000 * 1000) + (abstime->tv_nsec / 1000);
	usecs -= (1000 * 1000 * tv.tv_sec) + tv.tv_usec;

	if (!CondVar_timedwait(cond->condvar, mutex->sema, usecs)) // timeout
		return ETIMEDOUT;
	else
		return 0;
}

int 
pthread_cond_signal(pthread_cond_t *cond) 
{
	pthread_cond_initnexus(cond);
	CondVar_signal(cond->condvar);
	return 0;
}

int
pthread_cond_broadcast (pthread_cond_t *cond) 
{
	pthread_cond_initnexus(cond);
	CondVar_broadcast(cond->condvar);
	return 0;
}

/** stub: no functionality implemented */
int 
pthread_condattr_init(pthread_condattr_t *attr)
{
	memset(attr, 0, sizeof(*attr));
	return 0;
}

/** stub: no functionality implemented */
int
pthread_condattr_destroy(pthread_condattr_t *attr)
{
	return 0;
}

int
pthread_condattr_setpshared(pthread_condattr_t *attr, int pshared)
{
	if (pshared == PTHREAD_PROCESS_SHARED) {
		// fprintf(stderr, "warning: trying to make a mutex shared\n");
		// causes crash, don't: return ENOTSUP;
	}

	return 0;
}


////////  keys (unsupported)  ////////

int
pthread_key_create(pthread_key_t *key, void (*dtor) (void *)) 
{
  printf("pthread_key_create!!!\n");
  return -1;
}

int 
pthread_key_delete (pthread_key_t __key) 
{
  printf("pthread_key_delete!!!\n");
  return -1;
}


////////  semaphores  ////////

static inline Sema *
from_unix_sem(sem_t *sem) 
{
	return *(Sema **) sem;
}

int 
sem_init(sem_t *sem, int pshared, unsigned int value) 
{
	Sema *nexus_sem;

	if (pshared) {
		fprintf(stderr, "[pthread] unimplemented: sem_init pshared\n");
		return -1; // not implemented
	}

	nexus_sem = sema_new();
	sema_set(nexus_sem, value);

	*(Sema **)sem = nexus_sem; 
	return 0;
}

int 
sem_wait(sem_t *sem) 
{
	P(from_unix_sem(sem));
	return 0;
}

int
sem_trywait(sem_t *sem)
{
	if (P_try(from_unix_sem(sem))) {
		errno = EAGAIN;
		return -1;
	}
	else
		return 0;
}

int 
sem_post(sem_t *sem) 
{
	V_nexus(from_unix_sem(sem));
	return 0;
}

int 
sem_destroy(sem_t *sem) 
{
	sema_destroy(from_unix_sem(sem));
	return 0;
}


////////  unimplemented  ////////

int 
pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize)
{
	// XXX support configurable stack sizesa

	return 0;
}

int 
pthread_attr_destroy(pthread_attr_t *attr)
{
	// noop: probably leaks memory

	return 0;
}

int
pthread_attr_setscope(pthread_attr_t *attr, int contentionscope)
{
	return 0;
}

int
pthread_detach(pthread_t thread)
{
	// noop: will leak memory

	return 0;
}

/** warning: applications that expect this to work 
    may start to act odd if it does not */
int pthread_sigmask(int how, const sigset_t *set, sigset_t *oset)
{
	if (oset) {
		fprintf(stderr, "%s does not support output\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	return 0;
}

int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate)
{
	return 0;
}


