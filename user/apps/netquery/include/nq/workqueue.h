#ifndef WORKQUEUE_H_SHIELD
#define WORKQUEUE_H_SHIELD

#define DEFAULT_WORKQUEUE_SIZE 100000

//A simple producer-consumer queue.  Synchronization is charanteed between the two.

typedef struct NQ_Workqueue {
  void **ptrlist;
  int read;
  int write;
  unsigned int size;
  pthread_mutex_t write_lock;
  pthread_mutex_t read_lock;
} NQ_Workqueue;

NQ_Workqueue *NQ_Workqueue_create(unsigned int size);
void NQ_Workqueue_destroy(NQ_Workqueue *queue);
void NQ_Workqueue_insert(NQ_Workqueue *queue, void *ptr);
void *NQ_Workqueue_remove(NQ_Workqueue *queue);

#endif
