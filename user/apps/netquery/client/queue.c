
// note: this code exists in both userspace and kernelspace
// do not use any includes in this file (to keep the dependency
// checking easy)

#include <stdio.h>
#include <stdlib.h>

#include <nq/queue.h>
#include <nq/gcmalloc.h>

// #define INTEGRITY_CHECK

/* queue */

Queue *queue_new() {
  Queue *q = (Queue *)malloc(sizeof(Queue));
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
  if(q->head) printf("Freeing a non-empty queue!!!!\n");
  free(q);
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

#ifdef INTEGRITY_CHECK
  if(queue_find(q, ptr_eq, ptr) == NULL)
    return -1;
#endif

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

  for(ptr = q->head; ptr != NULL; ptr = ptr->next) {
    printf("Queue item %d: 0x%p\n", ++i, ptr);
    if(i > 5) {
		printf(" ... and %d or so additional items\n", (q->len-5));
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

/* uqueue */

struct UQItem {
  struct UQItem *next;
  struct UQItem *prev;
  void *data;
};

struct UQueue {
  struct UQItem *next;
  struct UQItem *prev;
  int len;
};

struct UQueue *uqueue_new(void) {
  struct UQueue *rv = malloc(sizeof(*rv));
  rv->next = (struct UQItem *)rv;
  rv->prev = (struct UQItem *)rv;
  rv->len = 0;
  return rv;
}

void uqueue_enqueue(struct UQueue *q, void *data) {
  struct UQItem *e = malloc(sizeof(*e));
  e->data = data;

  struct UQItem *orig_next = (struct UQItem *)q,
				   *orig_prev = q->prev;
  e->next = orig_next;
  e->prev = orig_prev;
  orig_next->prev = e;
  orig_prev->next = e;
  q->len++;
}

void *uqueue_dequeue(struct UQueue *q) {
  if(q->next == (struct UQItem *)q)
	  return NULL;
  struct UQItem *e = q->next;
  void *data = e->data;

  struct UQItem *orig_next = e->next, 
    *orig_prev = e->prev;
  orig_prev->next = orig_next;
  orig_next->prev = orig_prev;
  q->len--;
  free(e);
  return data;
}

int uqueue_len(struct UQueue *q) {
  return q->len;
}

void uqueue_destroy(struct UQueue *q) {
  while(q->len > 0) {
    uqueue_dequeue(q);
  }
  free(q);
}
