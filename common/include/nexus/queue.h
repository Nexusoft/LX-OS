/** NexusOS: queue datastructure */

#ifndef _NEXUS_QUEUE_H_
#define _NEXUS_QUEUE_H_

#include <nexus/commontypedefs.h>
#include <nexus/machine-structs.h>

/* queue: doubly linked list
 *
 * queue-able structures must reserve a "next" and a "prev" pointer
 * as the FIRST two words of the struct to queue without malloc. */

struct QItem {
  struct QItem *next;
  struct QItem *prev;
};

struct Queue {
  QItem *head;
  QItem *tail;
  int len;
};

#define QUEUE_EMPTY { NULL, NULL, 0 }

typedef int (*PFany)(void *item, void *arg);

static inline void *queue_gethead(Queue *q)  { return (void *)q->head; }
static inline void *queue_getnext(void *ptr) { return ((QItem *)ptr)->next; }
static inline void *queue_getprev(void *ptr) { return ((QItem *)ptr)->prev; }
static inline int queue_length(Queue *q)     { return atomic_get(&q->len); }

Queue *queue_new(void);
void queue_initialize(Queue *);

// dequeue
void *queue_dequeue(Queue *q);
void  queue_delete(Queue *, void *);

// enqueue
void queue_insert(Queue *q, void *_item, int at_head);
#define queue_append(q, item)	queue_insert(q, item, 0)
#define queue_prepend(q, item)	queue_insert(q, item, 1)

void queue_iterate(Queue *q, PFany f, void *arg);

/* uqueue: DEPRECATED doubly linked queue, with per-node allocation */

UQueue *uqueue_new(void);

void   uqueue_enqueue(UQueue *q, void *data);
void   uqueue_enqueue_nolock(struct UQueue *q, void *data);

void * uqueue_dequeue(UQueue *q);
void * uqueue_dequeue_nolock(UQueue *q);

int    uqueue_len(UQueue *q);
void * uqueue_peek(struct UQueue *q);
void   uqueue_destroy(UQueue *q);
void   uqueue_delete(UQueue *q, void *data);
void   uqueue_iterate(UQueue *q, PFany f, void *arg);

int    uqueue_unittest(void);

#endif

