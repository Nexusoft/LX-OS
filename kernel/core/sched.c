/** NexusOS: CPU scheduler */

#include <nexus/defs.h>
#include <nexus/profiler.h>
#include <nexus/thread.h>
#include <nexus/thread-private.h>
#include <nexus/rdtsc.h>

/// Number of accounts. The number of isolated slots is
//  naturally limited by the number of preemptions per second
#define SCHED_ACCOUNT_COUNT 		(HZ / SCHED_PREEMPTION_QUANTUM)
#define SCHED_ACCOUNT_BESTEFFORT	(0)

/// Independent queues. 
//  Each process belongs to exactly one queue.
//  If no queue is explicitly specified, the best effort queue is used.
static Queue nxsched_accounts[SCHED_ACCOUNT_COUNT];
/// mapping of quantum onto queue
//  a NULL value maps onto the best effort queue 
static Queue *quantum_map[SCHED_ACCOUNT_COUNT];

uint64_t cycles_idleloop;	// DEBUG XXX REMOVE 

inline void
nxsched_idleloop(void)
{
	extern uint64_t sched_idle;
	int preempt;

	preempt = disable_preemption();
	cycles_idleloop = rdtsc64();
	restore_intr(0);
	nexusthread_idle();
	disable_intr();
	cycles_idleloop = rdtsc64() - cycles_idleloop;
	sched_idle += cycles_idleloop;
	restore_preemption(preempt);
}

/** Select a thread from an account */
static inline BasicThread *
nxsched_schedule_account(Queue *q)
{
	BasicThread *new;

	assert(check_intr() == 0);
	new = queue_dequeue(q);

	assert(!new || (new->schedstate == RUNNABLE && new->scheduled == 1 && !new->blocksema));
	return new;
}

/** Main CPU Scheduler
 
    Invariants:
      - called with interrupts disabled
      - new thread will not be on any run queue
 */
BasicThread * 
nxsched_schedule(void) 
{
	BasicThread *new;
	Queue *account;
	unsigned long quantum;

	assert(check_intr() == 0);

#if NXCONFIG_CPU_QUOTA
	// lookup account by timeslice
	quantum = nexustime;
        quantum	/= SCHED_PREEMPTION_QUANTUM;	// div(# ticks per q) => q
	quantum %= SCHED_ACCOUNT_COUNT;
	account = quantum_map[quantum];
	if (!account)
#endif
		account = &nxsched_accounts[SCHED_ACCOUNT_BESTEFFORT];

	// try to schedule a task from the active account
	// XXX if none is runnable, allow from other accounts
	while ((new = nxsched_schedule_account(account)) == NULL) 
		nxsched_idleloop();

	new->scheduled = 0; // just popped from queue
	return new;					
}

void
nxsched_enqueue(BasicThread *t, int interrupt, int at_front)
{
	// sanity checks
	assert(check_intr() == 0);
	assert(t->schedstate == RUNNABLE);
	assert(!t->scheduled);
	assert(t->next == NULL && t->prev == NULL);

	// warning: at front may lead to starvation of other threads
  	if (at_front)
    		queue_prepend(&nxsched_accounts[t->ipd->account], t);
  	else
    		queue_append(&nxsched_accounts[t->ipd->account], t);

	t->scheduled = 1;
}

/** Remove thread from runqueue
    Warning: Only removes from the currently assigned account's queue. */
void
nxsched_dequeue(BasicThread *t)
{
	assert(check_intr() == 0);
#if NXCONFIG_CPU_QUOTA
	assert(t);
	assert(t->ipd);
	queue_delete(&nxsched_accounts[t->ipd->account], t);
#else
	queue_delete(&nxsched_accounts[SCHED_ACCOUNT_BESTEFFORT], t);
#endif
	t->scheduled = 0;
}

/** Attach process ipd to the given account.
    This is a privileged operation, as it effects resource control reservations

    @param account is any reserved cycles account, or 0 for best effort */
int
nxsched_process_setaccount(IPD *ipd, int account)
{
	if (!ipd || account >= SCHED_ACCOUNT_COUNT)
		return -1;
	
	ipd->account = account;
	return 0;
}

/** Attach an account to a CPU timeslice
    This is a privileged operation, as it effects resource control reservations
 */
int
nxsched_quantum_setaccount(int quantum, int account)
{
	if (quantum < 0 || 
	    account < 0 ||
	    quantum >= SCHED_ACCOUNT_COUNT ||
	    account >= SCHED_ACCOUNT_COUNT)
		return -1;

	// quanta are granted to accounts until reboot 
	// (to avoid invalidation of attestations)
	if (quantum_map[quantum] && 
	    quantum_map[quantum] != &nxsched_accounts[account]) {
		printkx(PK_THREAD, PK_WARN, "[sched] account override denied\n");
		return -1;
	}

	quantum_map[quantum] = &nxsched_accounts[account];
	return 0;
}

/** Return account holder of this quantum */
int
nxsched_quantum_getaccount(int quantum)
{
	if (quantum < 0 || 
	    quantum >= SCHED_ACCOUNT_COUNT)
		return -1;
	
	if (!quantum_map[quantum])
		return 0;

	return quantum_map[quantum] - &nxsched_accounts[0];
}

