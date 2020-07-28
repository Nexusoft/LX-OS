#ifndef DLIST_H
#define DLIST_H

#include <nexus/commontypedefs.h>
#include <linux/compiler.h>

#define CONTAINER_OF(TYPE, FIELD, PTR)				\
  ((TYPE *) (((unsigned long)(PTR)) - (unsigned long)&((TYPE *)0)->FIELD))

struct dlist_head {
	/* Must match order in minisocket header */
	struct dlist_head *prev;
	struct dlist_head *next;
	struct dlist_head_list *list;
};

struct dlist_head_list {
	struct dlist_head *prev;
	struct dlist_head *next;
	struct dlist_head_list *list;
	int len;
};


static inline int dlist_empty(struct dlist_head_list *head) {
	return head->next == (struct dlist_head*)head;
}

static inline void dlist_init_head(struct dlist_head_list *head) {
	head->next = head->prev = (struct dlist_head*)head;
	head->list = head;
	head->len = 0;
}

static inline void dlist_init_link(struct dlist_head *link) {
	link->next = link->prev = NULL;
	link->list = NULL;
}

static inline void dlist_insert_head(struct dlist_head_list *head, struct dlist_head *elem) {
	elem->next = head->next;
	head->next->prev = elem;

	elem->prev = (struct dlist_head*)head;
	head->next = elem;

	elem->list = head;
	head->len++;
}

static inline void dlist_insert_tail(struct dlist_head_list *head, struct dlist_head *elem) {
	elem->next = (struct dlist_head*)head;
	elem->prev = head->prev;

	head->prev->next = elem;

	elem->list = head;
	head->prev = elem;
	head->len++;
}

static inline void dlist_unlink(struct dlist_head *elem) {
	elem->next->prev = elem->prev;
	elem->prev->next = elem->next;
	elem->prev = elem->next = NULL;

	elem->list->len--;
	elem->list = NULL;
}

static inline int dlist_islinked(struct dlist_head *elem) {
  return elem->list != NULL;
}

static inline void dlist_insert(struct dlist_head *elem, struct dlist_head *prev, struct dlist_head *next) {
	elem->next = prev->next;
	prev->next = elem;

	elem->prev = prev;
	next->prev = elem;

	elem->list = prev->list;
	elem->list->len++;
}

static inline dlist_head *dlist_peek_front(struct dlist_head_list *head) {
  if(unlikely(head->len == 0)) { // this branch prediction hint makes sure the rest of the function is emited in line
    return NULL;
  }
  dlist_head *rv = head->next;
  return rv;
}

static inline dlist_head *dlist_dequeue(struct dlist_head_list *head) {
  if(unlikely(head->len == 0)) { // this branch prediction hint makes sure the rest of the function is emited in line
    return NULL;
  }

  dlist_head *rv = head->next;
  dlist_unlink(rv);
  return rv;
}

#define dlist_head_walk(QUEUE, ELEM) \
		for (ELEM = (typeof(ELEM))(QUEUE)->next;	\
		     (ELEM != (typeof(ELEM))(QUEUE));	\
		     ELEM=(typeof(ELEM))ELEM->next)

#define dlist_head_walk_safe(QUEUE, ELEM, NEXT_ELEM)			\
	for (ELEM = (typeof(ELEM))(QUEUE)->next, NEXT_ELEM = ELEM->next;		\
	     (ELEM != (typeof(ELEM))(QUEUE));				\
	     ELEM = NEXT_ELEM, NEXT_ELEM = NEXT_ELEM->next)

#define dlist_head_reverse_walk(QUEUE, ELEM) \
		for (ELEM = (typeof(ELEM))(QUEUE)->prev;	\
		     (ELEM != (typeof(ELEM))(QUEUE));	\
		     ELEM=(typeof(ELEM))ELEM->prev)

#endif // DLIST_H
