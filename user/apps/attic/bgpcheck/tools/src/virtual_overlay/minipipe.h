#ifndef MINIPIPE_H_SHIELD
#define MINIPIPE_H_SHIELD

#include <pthread.h>

struct Minipipe_v {
  char *data;
  int len;
  struct Minipipe_v *next;
};

typedef void (*minipipe_signal)(void *user_data);

class Minipipe {
 public:
  Minipipe();
  ~Minipipe();

  void write(char *data, int len);
  void write_malloced(char *data, int len);
  int read(char **data);
  int drop(int cnt);

  //this function is not read-threadsafe.  Concurrent writes are possible but
  //it is up to the programmer to ensure that no code calls read or drop on this
  //minipipe before they finish using the data in the data and sublen arrays
  int peek(char ***data, int **sublen);

  //this function provides only a hint.  You are not guaranteed that a subsequent
  //read or peek will return anything, etc...
  int get_count();

  //this function also only provides a peek.
  unsigned int get_bytes();
  unsigned int get_maxsize();

  //note that the following function is NOT threadsafe
  //it associates a signal call with this minipipe that will be called whenever a write
  //successfully completes.
  void set_signal(minipipe_signal signal_l, void *user_data_l);

  //disable multithreading support in this pipe
  void set_multithreaded(int _multithreaded);
 private:
  struct Minipipe_v *first, *last;
  pthread_mutex_t mutex;
  unsigned int bytes;
  int count;
  minipipe_signal signal;
  unsigned int maxbytes;
  void *user_data;
  int multithreaded;
  
  void lock();
  void unlock();
};

#endif
