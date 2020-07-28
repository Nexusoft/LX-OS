/** Nexus OS: Implementation of pthreads */

#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
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
#include <nexus/pthread-nexus.h>
#include <nexus/pthread-private.h>

#include <nexus/Mem.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>

#define DEFAULT_BASE (0x90020000)
#define MAXTHREADNO 500

/// communicate thread information from parent to child 
struct ThreadSpec {
  void *(*start_routine)(void *);
  void *arg;
  struct PThread_Stack stack;
  pthread_attr_t attr;
};

static Sema stack_mutex = SEMA_MUTEX_INIT; // Protects stack allocation

uint32_t __thread_default_stack_size = 64 * PAGESIZE;
uint32_t __thread_global_stack_base = DEFAULT_BASE;
uint32_t __thread_global_stack_limit = DEFAULT_BASE + 0x10000000;
static int stack_off;

/// lookup table for pthread metadata
//  XXX: sparse structure wastes memory, replace with extensible hashtable
//static PThread threadtable[MAXTHREADNO];
static PThread __thread threadtcb;

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
	pthread_t ret;

	ret = Thread_GetID();
	assert(ret < MAXTHREADNO);
	return ret;
}

int 
pthread_equal (pthread_t __thread1, pthread_t __thread2) 
{
	return (__thread1 == __thread2) ? 1 : 0;
}

pthread_t 
pthread_threadid(PThread *p)
{ 
	return p->threadid; 
}

struct PThread *
pthread_get_my_tcb(void) 
{
	int thread_id = pthread_self();
	assert(thread_id >= 0 && thread_id < 200);
	return &threadtcb; //&threadtable[thread_id];
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

  // main doesn't have a start routine; we just return to it.
  // main has a statically allocated stack
  if (arg == &thread_main)
    return 0;

  free(arg);

  // call user code. afterwards pthread_exit will run
  return (int) fork_spec.start_routine(fork_spec.arg);
}

static void 
fork_pre_tls(void *arg) 
{
  // We need to do pthread_exit() as a continuation, because it
  // needs to be called before the TLS is deallocated.
  // By the time tls_setup_and_start() returns, the TLS is gone, and
  // pthread_exit() will fail.
  tls_setup_and_start(fork_post_tls, (uint32_t) arg, 0, pthread_exit);

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
  unsigned long stack_hint, stack_end;
  struct ThreadSpec *spec;
  int i, num_pages, ret;

  num_pages = roundup(__thread_default_stack_size, PAGESIZE) / PAGESIZE;

  // XXX It would be nice to allocate ThreadSpec on the stack, but that
  // makes it difficult to let the kernel allocate the piggyback the
  // stack allocation with the thread creation. This forkspec will be
  // freed in fork_post_tls()
  spec = calloc(1, sizeof(struct ThreadSpec));
  spec->start_routine = start_routine;
  spec->arg = arg;
  pthread_attr_init_or_default(&spec->attr, attr);

  // find a memory region for the new stack
  P(&stack_mutex);
  stack_hint = __thread_global_stack_base + 
               ((__thread_default_stack_size + PAGESIZE) * stack_off); 
  stack_end = stack_hint + __thread_default_stack_size + PAGESIZE;
  if (stack_end > __thread_global_stack_limit) {
    fprintf(stderr, "Out of stack space\n");
    return -ENOMEM;
  }
  stack_off++;
  V_nexus(&stack_mutex);

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
    free(spec);
    return -EAGAIN;
  }

  *thread = ret;
  return 0;
}

void 
pthread_exit(void *retval) 
{
  uint32_t first_page, npages;
  
  first_page = pthread_get_my_tcb()->stack.first_page,
  npages = pthread_get_my_tcb()->stack.num_pages;

  Thread_Exit((uint32_t) retval, first_page, npages);

  // never reached
  assert(0);
  exit(-1); // suppress gcc noreturn warning
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

	spinlock(&init_spinlock);
	if (unlikely(!mutex->sema)) {
		mutex->sema = sema_new();
		sema_set(mutex->sema, 1);  // it's a mutex
	}
	spinunlock(&init_spinlock);
}

int 
pthread_mutexattr_settype(pthread_mutexattr_t *attr, int kind)
{
	attr->__mutexkind = kind;
	return 0;
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
	if (attr)
		m->__m_kind = attr->__mutexkind;

	// nexus specific fields
	pthread_mutex_initnexus(m);
	m->owner = 0;

	return 0;
}

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

// XXX clearly, switch to a lock per mutex
static int big_mutex_lock;

int 
pthread_mutex_lock(pthread_mutex_t *mutex)
{
	pthread_t me = pthread_self();

	if (!mutex)
		return EINVAL;

	pthread_mutex_initnexus(mutex);
#if 0
  P((Sema *)&m->lock);
  if(m->owner != me) {
    // locked, wait until released
    V_nexus((Sema *)&m->lock);
    P((Sema *)&m->mutex);
    P((Sema *)&m->lock);
    m->owner = me;
    m->count++;
    V_nexus((Sema *)&m->lock);
    return 0;
  }

  int rv = finish_locking(m);
  V_nexus((Sema *)&m->lock);
  return rv;
#else // HACKY shortcut. XXX remove

	// this simple mutex does NOT allow recursive locking
	if (mutex->owner == me)	{
		printf("RECURSIVE lock detected. unimplemented\n");
		Thread_Exit(1, 0, 0);
	}

	P(mutex->sema);
  	spinlock(&big_mutex_lock);
	mutex->owner = me;
  	spinunlock(&big_mutex_lock);

	return 0;
#endif
}

int 
pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	pthread_t me = pthread_self();
#if 0
  if(m == NULL)
    return EINVAL;

  P((Sema *) &m->lock);
  int rv;
  if(m->owner == 0 || m->owner == me) {
    // unlocked
    rv = finish_locking(m);
  } else {
    // already locked
    rv = EBUSY;
  }
  V_nexus((Sema *)&m->lock);

  return rv;
#else // HACKY shortcut. XXX remove
	 
  	spinlock(&big_mutex_lock);
	if (mutex->owner) {
 	 	spinunlock(&big_mutex_lock);
		return EBUSY;
	}

	mutex->owner = me;
  	spinunlock(&big_mutex_lock);
	return 0;
#endif
}

int 
pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	if (unlikely(!mutex))
		return EINVAL;

	pthread_mutex_initnexus(mutex);

#if 0

  if(m == NULL)
    return EINVAL;

  P((Sema *)&m->lock);
  switch(m->attr.__mutexkind){
  case PTHREAD_MUTEX_TIMED_NP:
    m->count = 0;
    m->owner = 0;
    V_nexus((Sema *)&m->mutex);
    V_nexus((Sema *)&m->lock);
    return 0;
    break;
  case PTHREAD_MUTEX_RECURSIVE_NP:
    if(--m->count == 0){
      m->owner =0;
      V_nexus((Sema *)&m->mutex);
    }
    V_nexus((Sema *)&m->lock);
    return 0;    
    break;
  case PTHREAD_MUTEX_ERRORCHECK_NP:
    if(m->owner == me){
      m->count = 0;
      m->owner = 0;
      V_nexus((Sema *)&m->mutex);
      V_nexus((Sema *)&m->lock);
      return 0;
    }
    V_nexus((Sema *)&m->lock);
    return EPERM;
    break;
  }
  V_nexus((Sema *)&m->lock);
  return 0;
#else // HACKY shortcut. XXX remove
  	spinlock(&big_mutex_lock);
	mutex->owner = 0;
	spinunlock(&big_mutex_lock);
	V_nexus(mutex->sema);
	return 0;
#endif
}

int 
pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	if (!mutex)
		return EINVAL;

	if (mutex->__m_count)
		return EINVAL;

	sema_destroy(mutex->sema);

	// memory leak: we cannot free the object, because destroy must
	// succeed also on statically allocated mutexes (mutices?)
	//free(mutex);
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

	spinlock(&lock);
	if (unlikely(!cond->condvar)) {
		cond->condvar = malloc(sizeof(CondVar));
		*(CondVar *) cond->condvar = (CondVar) CONDVAR_INIT;
	}
	spinunlock(&lock);
}

int 
pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *cond_attr) 
{
	if (cond_attr) {
		printf("[thread] unsupported condvar attribute\n");
		Thread_Exit(1, 0, 0);
	}

	*cond = (pthread_cond_t) PTHREAD_COND_INITIALIZER;
	pthread_cond_initnexus(cond);

	return 0;
}

int 
pthread_cond_destroy(pthread_cond_t *cond) 
{
	if (cond->condvar)
		free(cond->condvar);

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
	
	// XXX do this in the kernel to save a kernelmode switch
	gettimeofday(&tv, NULL);
	usecs = (abstime->tv_sec * 1000000) + (abstime->tv_nsec / 1000);
	usecs -= (1000 * 1000 * tv.tv_sec) + tv.tv_usec;

	tsc = rdtsc64();
	if (!CondVar_timedwait(cond->condvar, mutex->sema, usecs)) { // timeout
	 	tsc = rdtsc64() - tsc;
		tsc /= 3000;
//		printf("timeout. %llu usecs passed. %d requested\n", tsc, usecs);
		return ETIMEDOUT;
	}
	return 0;
}

int 
pthread_cond_signal(pthread_cond_t *cond) 
{
	CondVar_signal(cond->condvar);
	return 0;
}

int
pthread_cond_broadcast (pthread_cond_t *cond) 
{
	CondVar_broadcast(cond->condvar);
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

static Sema *
from_unix_sem(sem_t *sem) 
{
	return *(Sema **) sem;
}

int 
sem_init(sem_t *sem, int pshared, unsigned int value) 
{
	Sema *nexus_sem;

	if (pshared)
		return -1; // not implemented
	
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

