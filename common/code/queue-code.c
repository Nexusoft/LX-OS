#include <nexus/defs.h>		// for nxcompat_...
#include <nexus/queue.h>	// to keep definitions are consistent
#ifdef __NEXUSKERNEL__
#include <nexus/synch-inline.h>
#else
#include <nexus/sema.h>
#ifndef V
#define V(lock) V_nexus(lock)
#endif
#endif

// note: this code exists in both userspace and kernelspace
// do not use any includes in this file (to keep the dependency
// checking easy)

/* queue */

Queue *queue_new() {
  Queue *q = (Queue *) nxcompat_alloc(sizeof(Queue));
  q->head = NULL;
  q->tail = NULL;
  q->len = 0;
  return q;
}

void queue_initialize(Queue *q)
{
  q->head = NULL;
  q->tail = NULL;
  q->len = 0;
}

int queue_prepend(Queue *q, void *item) {
  QItem *newitem = (QItem *)item;

  if (q == NULL)
    return -1;

  newitem->next = NULL;
  newitem->prev = NULL;

  if (q->head){
    newitem->next = q->head;
    q->head->prev = newitem;
    q->head = newitem;
  }else{
    q->head = newitem;
    q->tail = newitem;
  }
  ++q->len;
  return 0;
}

int queue_iterate(Queue *q, PFany f, void *arg) {
  QItem *ptr;
  int ret = 0;
  for(ptr = q->head; ptr != NULL; ptr = ptr->next) {
    ret |= f(ptr, arg);
  }
  return ret;
}

void *queue_find(Queue *q, PFany f, void *arg) {
  QItem *ptr;
  for(ptr = q->head; ptr != NULL; ptr = ptr->next)
    if (f(ptr, arg)) return ptr;
  return NULL;
}

int queue_dealloc(Queue *q) {
  // do nothing
  return 0;
}

int queue_destroy(Queue *q) {
  if(q->head) nxcompat_printf("Freeing a non-empty queue!!!!\n");
  nxcompat_free(q);
  return 0;
}

int queue_length(Queue *q) {
  return q->len;
}

static int ptr_eq(void *ptr, void *tomatch){
  if(ptr == tomatch)
    return 1;
  return 0;
}

void *queue_find_eq(Queue *q, void *item){
  return queue_find(q, ptr_eq, item);
}

int queue_delete(Queue *q, void *item) {
  QItem *ptr = (QItem *)item;

  if(queue_find(q, ptr_eq, ptr) == NULL)
    return -1;

  if(ptr->next) {
    ptr->next->prev = ptr->prev;
  }
  if(ptr->prev) {
    ptr->prev->next = ptr->next;
  }
  if(q->head == ptr)
    q->head = ptr->next;
  if(q->tail == ptr)
    q->tail = ptr->prev;
  ptr->next = NULL;
  ptr->prev = NULL;
  q->len--;
  return 0;
}

void queue_dump(Queue *q) {
  QItem *ptr;
  int i = 0;

  for (ptr = q->head; ptr != NULL; ptr = ptr->next) {
    nxcompat_printf("Queue item %d: 0x%x\n", ++i, (unsigned int) ptr);
    if (i > 5) {
      nxcompat_printf(" ... and %d or so additional items\n", (q->len-5));
      break;
    }
  }
}

void *queue_gethead(Queue *q) {
	return (void *)q->head;
}

void *queue_getnext(void *ptr) {
	return ((QItem *)ptr)->next;
}

void *queue_getprev(void *ptr) {
	return ((QItem *)ptr)->prev;
}

/* UQueue: a queue that accepts void * as elements
 
   This structure is threadsafe, because it uses a mutex internally.
   As a result, it may not be used in interrupt context.

   XXX: add the equivalent of trylock_get that falls through if a lock is taken
        and add interrupt safe uqueue_enqueue_int(..) and friends
 */

struct UQItem {
  struct UQItem *next;
  struct UQItem *prev;
  void *data;
};

struct UQueue {
  struct UQItem *next;
  struct UQItem *prev;
  int len;
  Sema mutex;
};

struct UQueue *uqueue_new(void) {
  struct UQueue *rv;
  
  rv = nxcompat_calloc(1, sizeof(*rv));
  
  rv->next = (struct UQItem *)rv;
  rv->prev = (struct UQItem *)rv;
  rv->mutex = SEMA_MUTEX_INIT;

  return rv;
}

/** Add an item to the queue */
void 
uqueue_enqueue(struct UQueue *q, void *data) 
{
	struct UQItem *e;

	e = nxcompat_alloc(sizeof(*e));
	e->data = data;

// we cannot use P/V in interrupt context, 
// but on uniprocessors don't need it either
#ifdef __NEXUSKERNEL__
	if (!nexusthread_in_interrupt(nexusthread_self())) 
		P(&q->mutex);
#endif
	e->next = (struct UQItem *) q;
	e->prev = q->prev;
	q->prev->next = e;
	q->prev = e;

	q->len++;

#ifdef __NEXUSKERNEL__
	if (!nexusthread_in_interrupt(nexusthread_self())) 
		V(&q->mutex);
#endif
}

/** Show the first item in the queue or NULL if the queue is empty */
void *
uqueue_peek(struct UQueue *q)
{
	if (!q || !q->next)
		return NULL;

	return q->next->data;
}

/** Break a queue to remove an item and reconnect the neighbours */
static void *
__uqueue_extract(struct UQueue *q, struct UQItem *cur)
{
	void *data;

	cur->next->prev = cur->prev;
	cur->prev->next = cur->next;
	q->len--;

	data = cur->data;
	nxcompat_free(cur);
	return data;
}

/** Remove the next element from the queue */
void *
uqueue_dequeue(struct UQueue *q) 
{
	void *data;

	if (q->next == (struct UQItem *) q)
	  return NULL;

#ifdef __NEXUSKERNEL__
	if (!nexusthread_in_interrupt(nexusthread_self())) 
		P(&q->mutex);
#endif
	data = __uqueue_extract(q, q->next);
#ifdef __NEXUSKERNEL__
	if (!nexusthread_in_interrupt(nexusthread_self())) 
		V(&q->mutex);
#endif

	return data;
}

/** Remove a specific element from the queue */
void 
uqueue_delete(struct UQueue *q, void *data)
{
	struct UQItem *cur;
	
#ifdef __NEXUSKERNEL__
	BUG_ON_INTERRUPT();
#endif

	P(&q->mutex);
	for (cur = q->next; cur != (struct UQItem *) q; cur = cur->next) {
		if (cur->data == data) {
			__uqueue_extract(q, cur);
			break;
		}
	}
	V(&q->mutex);
}

int 
uqueue_len(struct UQueue *q) 
{
	return q->len;
}

void 
uqueue_destroy(struct UQueue *q) 
{
	while (q->len > 0)
		uqueue_dequeue(q);

	P(&q->mutex);
	nxcompat_free(q);
}

/** Calls f for each data item in the hashtable. 
    Does NOT point to the UQueue element itself */
void
uqueue_iterate(UQueue *q, PFany f, void *arg) 
{
	struct UQItem *cur;
	
	cur = q->next;
	do {
		f(cur->data, arg);
		cur = cur->next;
	} while (cur != (struct UQItem*) q);
}

int 
uqueue_unittest(void)
{
	struct UQueue *q;
	void *a, *b, *c, *ret;
	int count;

	a = (void *) 0x1;
	b = (void *) 0x2;
	c = (void *) 0x3;
	q = uqueue_new();

	// test enqueue and len
	uqueue_enqueue(q, a);
	uqueue_enqueue(q, b);
	assert(q->len == 2);
	assert(uqueue_len(q) == q->len);

	// test dequeue
	ret = uqueue_dequeue(q);
	assert (ret == a);

	// test iterator
	int 
	uqueue_iterator(void *data, void *unused) 
	{
		count++;
		return 0;
	}

	count = 0;
	uqueue_iterate(q, uqueue_iterator, NULL);
	assert(q->len == 1);

	// test delete
	uqueue_enqueue(q, a);
	uqueue_enqueue(q, c);
	uqueue_delete(q, a);
	assert(q->len == 2);
	ret = uqueue_dequeue(q);
	assert(ret == b);

	uqueue_destroy(q);
	return 0;
}

