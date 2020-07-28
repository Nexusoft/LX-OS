#include <iostream>
#include <string.h>
#include "../../../include/runtime/minipipe.h"
#include "../../../include/util/common.h"
#include "../../../include/util/safe_malloc.h"
#include <assert.h>

Minipipe::Minipipe(){
  first = last = NULL;
  pthread_mutex_init(&mutex, NULL); 
  count = 0;
  signal = NULL;
  bytes = 0;
  maxbytes = 0;
  multithreaded = 1;
}
void Minipipe::set_multithreaded(int _multithreaded){
  multithreaded = _multithreaded;
}
Minipipe::~Minipipe(){
  struct Minipipe_v *curr, *tmp;

  printf(">>>>>>>>>>>BAAAAAAAAAAAD!  Minipipe being destroyed!<<<<<<<<<<<<<<<\n");
  assert(!"Minipipes should never be destroyed!");

  for(curr = first; curr != NULL; curr = tmp){
    tmp = curr->next;
    safe_free(curr->data);
    safe_free(curr);
  }

  pthread_mutex_destroy(&mutex);
}

void Minipipe::set_signal(minipipe_signal signal_l, void *user_data_l){
  signal = signal_l;
  user_data = user_data_l;
}

void Minipipe::write(char *data, int len){
  char *my_data = (char *)safe_malloc(len);
  memcpy(my_data, data, len);
  write_malloced(my_data, len);
}
void Minipipe::write_malloced(char *data, int len){
  //printf("Write malloced\n");

  struct Minipipe_v *tmp = (struct Minipipe_v *)safe_malloc(sizeof(struct Minipipe_v));

  tmp->data = data;
  tmp->len = len;
  tmp->next = NULL;

  lock();
  {
    //printf("writing%0lx: count is %d; (%d bytes)\n", this, count, bytes);
    if(last != NULL){
      last->next = tmp;
    } else {
      //printf("first element @ %0lx < %0lx\n", tmp, data);
      first = tmp;
    }
    last = tmp;

    count++;
    bytes += len;
    maxbytes = MAX(maxbytes, bytes);
    //printf("leaving write mutex\n");
  }
  unlock();

  if(signal != NULL){
    signal(user_data);
  }
}
int Minipipe::read(char **data){
  struct Minipipe_v *tmp = NULL;
  int len;
  
  //printf("trying to read: lock: %d\n", mutex.mutex.value);
  lock();
  {
    //printf("reading%0lx: count is %d; first is %0lx\n", this, count, (unsigned long)first);
    if(first != NULL){
      tmp = first;
      first = tmp->next;
      if(first == NULL){
	last = NULL;
      }
      count--;
      bytes -= tmp->len;
    }
    //printf("leaving read mutex\n");
  }
  unlock();
  if(tmp != NULL){
    //printf("got a good packet: %0lx\n", tmp->data);
    *data = tmp->data;
    len = tmp->len;
    //printf("freeing the buffer: %0lx\n", tmp);
    safe_free(tmp);
    
  } else {
    //printf("empty queue\n");
    *data = NULL;
    len = -1;
  }
  //printf("done %d\n", len);
  return len;
}
int Minipipe::peek(char ***data, int **sublen){
  struct Minipipe_v *tmp;
  int i, cnt = 0;
  //printf(">>>Starting peek\n");
  //  static char (*data_real)[1000];
  //  static int sublen_real[1000];

  lock();
  {
    //printf(">>>Checking count\n");
    if(count <= 0){
      //printf(">>>Empty list\n");
      *data = NULL;
      *sublen = NULL;
    } else {
      //printf(">>>Allocating lists of %d elements(%0lx, %0lx)\n", count, data, sublen);
      
      *data = (char **)safe_malloc(sizeof(char *) * count);
      assert(*data);
      *sublen = (int *)safe_malloc(sizeof(int) * count);
      assert(*sublen);

      cnt = count;
      //printf(">>>populating lists\n");

      for(tmp = first, i = 0; tmp != NULL; tmp = tmp->next, i++){
	//printf(">>>peeking at %d: len: %d\n", i, tmp->len);
	(*data)[i] = tmp->data;
	(*sublen)[i] = tmp->len;
	//printf(">>>done\n");
      }
    }
  }
  unlock();

  return cnt;
}

int Minipipe::drop(int cnt){
  struct Minipipe_v *tmp = first;
  int len;

  lock();
  {
    len = 0;
    while((first != NULL) && (cnt > 0) && (count > 0)){
      tmp = first->next;
      
      len += first->len;

      safe_free(first->data);
      //printf("dropping : %0lx\n", first);
      safe_free(first);

      first = tmp;
      if(first == NULL){
	last = NULL;
      }
      cnt--;
      count--;
      //printf("droping a packet, count is %d\n", count);
    }
    bytes -= len;
  }
  unlock();
  return len;
}

int Minipipe::get_count(){
  int count_l;
  //printf("trying to get count: lock: %d\n", mutex.mutex.value);
  lock();
  count_l = count;
  unlock();
  return count;
}

unsigned int Minipipe::get_bytes(){
  unsigned int bytes_l;
  //printf("trying to get bytes: lock: %d\n", mutex.mutex.value);
  lock();
  bytes_l = bytes;
  unlock();
  return bytes_l;
}

unsigned int Minipipe::get_maxsize(){
  return maxbytes;
}

void Minipipe::lock(){
  if(multithreaded){
    pthread_mutex_lock(&mutex);
  }
}

void Minipipe::unlock(){
  if(multithreaded){
    pthread_mutex_unlock(&mutex);
  }
}
