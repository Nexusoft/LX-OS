/** NexusOS: standard queue datastructure */

#include <nexus/defs.h>		// for nxcompat_...
#include <nexus/queue.h>	// to keep definitions are consistent
#include <nexus/machine-structs.h>
#ifdef __NEXUSKERNEL__
#include <nexus/synch-inline.h>
#else
#include <nexus/sema.h>
#ifndef V
#define V(lock) V_nexus(lock)
#endif
#endif

void 
queue_initialize(Queue *q)
{
  q->head = NULL;
  q->tail = NULL;
  q->len = 0;
}

Queue *
queue_new() 
{
  Queue *q = (Queue *) nxcompat_alloc(sizeof(Queue));
  queue_initialize(q);
  return q;
}

void
queue_insert(Queue *q, void *_item, int at_head)
{
  QItem *item = _item;

#ifdef __NEXUSKERNEL__
  assert(check_intr() == 0);
#endif
  assert(q && item);
  assert(!item->next && !item->prev);
  assert(q->len || (!q->head && !q->tail));
  
  if (!q->len) {
    q->head = q->tail = item;
  }
  else {
    if (at_head) {
      item->next = q->head;
      q->head->prev = item;
      q->head = item;
    }
    else {
      item->prev = q->tail;
      q->tail->next = item;
      q->tail = item;
    }
  }

  q->len++;
}

/* Remove the entry at the head of the tail
   @return the item on success or NULL if the queue is empty */ 
void * 
queue_dequeue(Queue *q) 
{
  QItem *item;
  
#ifdef __NEXUSKERNEL__
  assert(check_intr() == 0);
#endif
  
  item = queue_gethead(q);
  if (item) {

    if (item->next) {
      q->head = item->next;
      q->head->prev = NULL;
    }
    else {
      q->head = q->tail = NULL;
    }

    item->next = item->prev = NULL;
    assert(q->len || (!q->head && !q->tail));
    
    q->len--;
  }

  return item;  
}

/** Remove a specific element from the queue */
void 
queue_delete(Queue *q, void *_item) 
{
  QItem *item;

#ifdef __NEXUSKERNEL__
  assert(check_intr() == 0);
#endif
  
  for (item = q->head; item; item = item->next) {
    if (item == _item) {
      // remove from neighboring items
      if (item->next) item->next->prev = item->prev;
      if (item->prev) item->prev->next = item->next;
      // remove from head/tail
      if (q->head == item) q->head = item->next;
      if (q->tail == item) q->tail = item->prev;
      // isolate item
      item->next = item->prev = NULL;
      q->len--;
      break;
    }
  }
}

void 
queue_iterate(Queue *q, PFany f, void *arg)
{
	struct filter_rule *first, *item;

	first = queue_gethead(q);
	if (!first)
		return;

	item = first;
	do {
		if (f(item, arg))
			break;
		item = queue_getnext(item);
	} while (item && item != first);
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
  struct UQItem *cache;	///< optimization: cache a single item for quick reuse
};

struct UQueue *uqueue_new(void) {
  struct UQueue *rv;
  
  rv = nxcompat_calloc(1, sizeof(*rv));
  
  rv->next = (struct UQItem *)rv;
  rv->prev = (struct UQItem *)rv;
  rv->mutex = SEMA_MUTEX_INIT;

  return rv;
}

void
uqueue_enqueue_nolock(struct UQueue *q, void *data)
{
	struct UQItem *e;

	// acquire list elem. try cache first
	if (q->cache) {
		e = q->cache;
		q->cache = NULL;
	}
	else
		// XXX if ints disabled: BUG: malloc may want to sleep
		e = nxcompat_alloc(sizeof(*e));
	
	// add data
	e->data = data;

	// append to list
	e->next = (struct UQItem *) q;
	e->prev = q->prev;
	q->prev->next = e;
	q->prev = e;

	q->len++;
}

/** Add an item to the queue */
void 
uqueue_enqueue(struct UQueue *q, void *data) 
{
// we cannot use P/V in interrupt context, 
// but on uniprocessors don't need it either
#ifdef __NEXUSKERNEL__
	if (check_intr() != 0)
		P(&q->mutex);
#endif
	uqueue_enqueue_nolock(q, data);
#ifdef __NEXUSKERNEL__
	if (check_intr() != 0)
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

static void *
__uqueue_dequeue_specific(struct UQueue *q, struct UQItem *cur)
{
	void *data;
	
	// remove elem from list
	cur->next->prev = cur->prev;
	cur->prev->next = cur->next;
	q->len--;

	data = cur->data;

	// release list elem (put in cache if room)
	if (!q->cache)
		q->cache = cur;
	else
		nxcompat_free(cur);

	return data;
}

/** Break a queue to remove an item and reconnect the neighbours */
void *
uqueue_dequeue_nolock(struct UQueue *q)
{
	struct UQItem *cur;

	cur = q->next;
	if (cur == (struct UQItem *) q)
	  return NULL;

	return __uqueue_dequeue_specific(q, cur);
}

/** Remove the next element from the queue */
void *
uqueue_dequeue(struct UQueue *q) 
{
	void *data;

#ifdef __NEXUSKERNEL__
	if (check_intr() != 0)
		P(&q->mutex);
#endif
	data = uqueue_dequeue_nolock(q);
#ifdef __NEXUSKERNEL__
	if (check_intr() != 0)
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
	if (check_intr() != 0)
		P(&q->mutex);
#endif

	for (cur = q->next; cur != (struct UQItem *) q; cur = cur->next) {
		if (cur->data == data) {
			__uqueue_dequeue_specific(q, cur);
			break;
		}
	}

#ifdef __NEXUSKERNEL__
	if (check_intr() != 0)
		V(&q->mutex);
#endif
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

#ifdef __NEXUSKERNEL__
	P(&q->mutex);
#else
	P(&q->mutex);
#endif
	nxcompat_free(q);
}

/** Calls f for each data item in the hashtable 
    OR until f returns a nonzero value
    Does NOT point to the UQueue element itself */
void
uqueue_iterate(UQueue *q, PFany f, void *arg) 
{
	struct UQItem *cur;
	
	cur = q->next;
	do {
		if (f(cur->data, arg))
			break;
		cur = cur->next;
	} while (cur != (struct UQItem*) q);
}

int 
uqueue_unittest(void)
{
	struct UQueue *q;
	void *a, *b, *c, *ret;
	int intlevel, count;

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

