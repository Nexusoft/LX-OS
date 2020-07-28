#include <iostream>
#include <assert.h>

#include "../include/util/safe_malloc.h"
#include "../include/util/g_tl.h"

Ghetto_Vector::Ghetto_Vector(int size_l){
#define PING() printf("(%d)", __LINE__)
  assert(size_l > 0);
  max_size = size_l;
  buff = (void **)safe_malloc(sizeof(void *) * size_l);
  left = right = 0;
  //printf(">>>>ghetto_vector_init %d, %0lx\n", left, buff);
  iter = 0;
  gv_debug = 0;
}
Ghetto_Vector::~Ghetto_Vector(){
  safe_free(buff);
}
void Ghetto_Vector::check_size(int size_l){
  int temp = size_l % 4; //round up to the nearest multiple;
  size_l += 4-temp;
  //printf("check_size %d->%d", max_size, size_l);
  if(max_size < size_l){
    void **tmp = (void **)safe_malloc(sizeof(void *) * size_l);
    if(left < right){
      memcpy(tmp, &(buff[left]), sizeof(void *) * (right - left));
      right = (right - left);
    } else {
      memcpy(tmp, &(buff[left]), sizeof(void *) * (max_size - left));
      if(right > 0)
	memcpy(&(tmp[max_size-left]), buff, sizeof(void *) * right);
      right = max_size + right - left;
    }
    left = 0;
    safe_free(buff);
    buff = tmp;
    max_size = size_l;
  }
}
int Ghetto_Vector::size(){
  return (max_size + right - left) % max_size;
}
void Ghetto_Vector::push_back(void *in){
  //make sure we have enough space
  check_size(size() + 1);
  
  buff[right] = in;
  right = (right + 1)%max_size;
}
void *Ghetto_Vector::pop(){
  int oldleft = left;
  if(left == right) return NULL;
  left = (left + 1)%max_size;
  return buff[oldleft];
}
void Ghetto_Vector::debug(){
  gv_debug = 1;
}
void Ghetto_Vector::iterator_reset(){
  if(gv_debug ==1) printf("iterator reset(%d)\n", left);
  iter = left;
}
void *Ghetto_Vector::iterator_next(){
  int olditer = iter;
  
  if(gv_debug ==1) printf("iterator_next %d < %d < %d %% %d\n", left, iter, right, max_size);
  if(iter == right) return NULL;
  
  //printf("iterator_next2: %d %0lx\n", olditer, buff);
  iter = (iter + 1)%max_size;
  return buff[olditer];
}
void *Ghetto_Vector::at(int i){
  if(i >= size()) return NULL;
  
  return buff[(i + left)%max_size];
}




Ghetto_PQueue::Ghetto_PQueue(){
  first = NULL;
  my_size = 0;
}
Ghetto_PQueue::~Ghetto_PQueue(){
  Ghetto_PQueue_t *tmp;

  while(first != NULL){
    tmp = first->next;
    safe_free(first);
    first = tmp;
  }
}

void Ghetto_PQueue::insert(int priority, void *obj){
  Ghetto_PQueue_t *entry = (Ghetto_PQueue_t *)safe_malloc(sizeof(Ghetto_PQueue_t)), *tmp;
  entry->val = obj;
  entry->priority = priority;
  
  if((first == NULL)||(first->priority >= priority)){
    entry->next = first;
    first = entry;
  } else {
    for(tmp = first; (tmp->next != NULL) && (tmp->next->priority < priority); tmp = tmp->next);
    entry->next = tmp->next;
    tmp->next = entry;
  }
  my_size++;
}
void *Ghetto_PQueue::dequeue(int *priority){
  void *val;
  Ghetto_PQueue_t *tmp;
  
  if(first == NULL){
    return NULL;
  }

  tmp = first;
  first = first->next;
  my_size--;

  if(priority != NULL) *priority = tmp->priority;
  val = tmp->val;
  safe_free(tmp);
  return val;
}
int Ghetto_PQueue::peek_priority(){
  if(first == NULL) return -1;
  return first->priority;
}
void *Ghetto_PQueue::peek_object(){
  if(first == NULL) return NULL;
  return first->val;
}
int Ghetto_PQueue::empty(){
  return first != NULL;
}
int Ghetto_PQueue::size(){
  return my_size;
}
