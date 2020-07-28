#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <pthread.h>

#include <nq/workqueue.h>

NQ_Workqueue *NQ_Workqueue_create(unsigned int size){
  NQ_Workqueue *queue = malloc(sizeof(NQ_Workqueue));
  bzero(queue, sizeof(NQ_Workqueue));
  
  pthread_mutex_init(&queue->write_lock, NULL);
  pthread_mutex_init(&queue->read_lock, NULL);
  
  queue->ptrlist = malloc(sizeof(void *) * size);
  bzero(queue->ptrlist, sizeof(void *) * size);
  queue->size = size;
  
  return queue;
}
void NQ_Workqueue_destroy(NQ_Workqueue *queue){
  pthread_mutex_destroy(&queue->write_lock);
  pthread_mutex_destroy(&queue->read_lock);
  free(queue->ptrlist);
  free(queue);
}
int NQ_Workqueue_entries(NQ_Workqueue *queue){
  if(queue->write >= queue->read){
    return queue->write - queue->read;
  } else {
    return queue->size - queue->read + queue->write;
  }
}
void NQ_Workqueue_resize(NQ_Workqueue *queue, int size){
  pthread_mutex_lock(&queue->read_lock); //no readers at the same time.
  int x = 0;
  void **newbuff = malloc(sizeof(void *) * size);
  bzero(newbuff, sizeof(void *) * size);
  printf("before: size %d, read %d, write %d, fill %d\n", queue->size, queue->read, queue->write, NQ_Workqueue_entries(queue));
  while(queue->read != queue->write){
    newbuff[x] = queue->ptrlist[queue->read];
    queue->read = (queue->read + 1)%queue->size;
    x++;
  }
  free(queue->ptrlist);
  queue->ptrlist = newbuff;
  queue->size = size;
  queue->write = x;
  queue->read = 0;
  printf("after: size %d, read %d, write %d, fill %d\n", queue->size, queue->read, queue->write, NQ_Workqueue_entries(queue));
  pthread_mutex_unlock(&queue->read_lock);
}
void NQ_Workqueue_insert(NQ_Workqueue *queue, void *ptr){
  pthread_mutex_lock(&queue->write_lock);
  if(queue->size < NQ_Workqueue_entries(queue) + 10){
    assert(queue->size < queue->size * 2); //catch integer overflow errors
    NQ_Workqueue_resize(queue, queue->size * 2);
  }
  queue->ptrlist[queue->write] = ptr;
  queue->write = (queue->write + 1)%queue->size;
  pthread_mutex_unlock(&queue->write_lock);
}
void *NQ_Workqueue_remove(NQ_Workqueue *queue){
  pthread_mutex_lock(&queue->read_lock);
  void *ret = NULL;
  if(queue->write != queue->read){
    ret = queue->ptrlist[queue->read];
    queue->read = (queue->read + 1)%queue->size;
  }
  pthread_mutex_unlock(&queue->read_lock);
  return ret;
}
