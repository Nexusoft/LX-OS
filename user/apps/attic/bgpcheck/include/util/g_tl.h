#ifndef GTL_H_SHIELD
#define GTL_H_SHIELD

class Ghetto_Vector {
 private: 
  int max_size;
  void **buff;
  int left, right;
  int iter;
  int gv_debug;

 public:
  Ghetto_Vector(int size_l);
  ~Ghetto_Vector();

  void check_size(int size_l);
  int size();
  void push_back(void *);
  void *pop();

  void debug();

  void iterator_reset();
  void *iterator_next();
  void *at(int i);
};

struct Ghetto_PQueue_t {
  void *val;
  int priority;
  Ghetto_PQueue_t *next;
};

class Ghetto_PQueue {
 private:
  Ghetto_PQueue_t *first;
  int my_size;
  
 public:
  Ghetto_PQueue();
  ~Ghetto_PQueue();

  void insert(int priority, void *obj);
  void *dequeue(int *priority);
  int peek_priority();
  void *peek_object();
  int empty();
  int size();
};

#endif
