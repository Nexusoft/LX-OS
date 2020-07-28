/*
 * Generic queue manipulation functions.
 * Two versions:
 *   queue  -- doubly linked list without per-node allocation
 *   uqueue -- doubly linked list with per-node allocation
 *
 * Todo: combine these.
 */

#ifndef _NEXUS_QUEUE_H_
#define _NEXUS_QUEUE_H_

#include <assert.h>

/*
 * queue: doubly linked queue, with no per-node allocation
 *
 * WARNING: All 'queue'-able structs must reserve a "next" and a "prev"
 * pointer as the first two words of the struct. This enables us to queue
 * items without having to call malloc.
 */

#define LINK_PARENT(T,Y,V)					\
  ((T *)((char *)(V) - (char *)&((T *)0)->Y))

typedef struct QItem {
  struct QItem *next;
  struct QItem *prev;
} QItem;

typedef struct Queue{
  QItem *head;
  QItem *tail;
  int len;
} Queue;

typedef int (*PFany)(void *item, void *arg);

/*
 * Return an empty queue. On error returns NULL.
 */
extern Queue *queue_new(void);

/*
 * Initialize an already-allocated queue.
 */
extern void queue_initialize(Queue *);
#define QUEUE_EMPTY { NULL, NULL, 0 }

/*
 * Prepend an any_t to a queue (both specifed as parameters).
 * Return 0 (success) or -1 (failure).
 */
extern int queue_prepend(Queue *, void *);

/*
 * Appends an void * to a queue (both specifed as parameters).  
 * Return 0 (success) or -1 (failure).
 */

static inline int queue_append(Queue *q, void *item) {
#ifndef NULL
#define NULL (0)
#define __NDEFED
#endif // NULL
  QItem *newitem = (QItem *)item;

  assert(q != NULL);

  newitem->next = NULL;
  newitem->prev = NULL;

  if (q->head){
    newitem->prev = q->tail;
    q->tail->next = newitem;
    q->tail = newitem;
  }else{
    q->head = newitem;
    q->tail = newitem;
  }
  ++q->len;
  return 0;
}

/*
 * Dequeue and return the first void * from the queue. 
 * Return 0 (success) and first item if queue is nonempty,
 * or -1 (failure) and NULL if queue is empty.
 */
// extern int queue_dequeue(Queue *, void **);

static inline int queue_dequeue(Queue *q, void **item) {
  assert(q != NULL);
  if (q->head == NULL)
    return -1;

  if(q->head->next)
    q->head->next->prev = NULL;
  *item = q->head;
  q->head = q->head->next;
  --q->len;
  return 0;
#ifdef __NDEFED
#undef NULL
#undef __NDEFED
#endif
}

/*
 * Iterate the function parameter over each element in the queue.  The
 * additional void * argument is passed to the function as its second
 * argument and the queue element is the first.  
 * Return the OR of all return values of the function parameter, or 0
 * if the queue was empty.
 */
extern int queue_iterate(Queue *, PFany, void *arg);

/*
 * Iterate the function (that returns nonzero for success or 0 for failure)
 * parameter over each element in the queue.  The additional any_t
 * argument is passed to the function as its second argument and the
 * queue element is the first.  Return first successful item and stop
 * (success) or NULL (failure).
 */
extern void *queue_find(Queue *q, PFany f, void *arg);
/* do an equality match on pointers */
void *queue_find_eq(Queue *q, void *item);

/* 
 * Free the queue. Return 0 (success) or -1 (failure).
 */
extern int queue_destroy(Queue *);

/*
 * Deallocate internal structures of queue
 */
int queue_dealloc(Queue *);

/*
 * Return the number of items in the queue.
 */
extern int queue_length(Queue *);

/* 
 * Delete the specified item from the given queue. 
 * Return -1 on error.
 */
extern int queue_delete(Queue *, void *);

/* for debugging */
extern void queue_dump(Queue *q);

/* standard accessors */
extern void *queue_gethead(Queue *q);
extern void *queue_getnext(void *ptr);
extern void *queue_getprev(void *ptr);

static inline int queue_checknotonqueue(QItem *item) {
  return item->next == 0 && item->prev == 0;
}

/*
 * uqueue: doubly linked queue, with per-node allocation
 * 
 * This queue can handle any kind of  
 */

typedef struct UQueue UQueue;

UQueue *uqueue_new(void);
void uqueue_enqueue(UQueue *q, void *data);
void *uqueue_dequeue(UQueue *q);
int uqueue_len(UQueue *q);
void uqueue_destroy(UQueue *q);

#endif
