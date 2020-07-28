#ifndef RUNTIME_H_SHIELD
#define RUNTIME_H_SHIELD

#include "../runtime/minipipe.h"
#include "../runtime/minisocket.h"
#include "../runtime/pipedsocket.h"
#include "../util/nexussync.h"
#include <vector>
#include <deque>

// Some notes regarding Runtime_Handler
// Firstly, all times are in milliseconds.  Second, each handler may only monitor one
// socket (for each of read, write, and except).  The FD or time -1 is equivalent to
// a lack of interest in the relevant callback.

class Runtime;

#define RUNTIME_EVENT_TIMER 0
#define RUNTIME_EVENT_MINIPIPE 1
#define RUNTIME_EVENT_SOCKACCEPT 2
#define RUNTIME_EVENT_SOCKREADY 3
#define RUNTIME_EVENT_SOCKCLOSED 4


#define NUM_RUNTIME_EVENTS 3

//
// All times are given in msec.
//

class Runtime_Handler {
 public:
  Runtime_Handler(char *_name);
  Runtime_Handler(int periodic_l, Minipipe *minipipe_l, char *_name);
  virtual ~Runtime_Handler();
  
  Runtime *get_runtime();

  /////////////////////////////////////////////////////////////
  // Override these functions to implement a runtime handler //
  /////////////////////////////////////////////////////////////

  virtual void handle_minipipe(Minipipe *pipe, Runtime *runtime);
  virtual void handle_accept(Minisocket *sock, Runtime *runtime);
  virtual void handle_sockready(Minisocket *sock, Runtime *runtime);
  virtual void handle_sockclosed(Minisocket *sock, Runtime *runtime);
  //this should return the msec until the next timeout or -1 for no more timeouts
  virtual int handle_periodic(Runtime *runtime);

  ////////////////////////////////////////////////////////
  // Use these functions to add triggers after creation //
  ////////////////////////////////////////////////////////
  
  // triggers handle_periodic() 'time' millis from now
  void set_periodic_time(int time);

  // sets this handler to use the following minipipe;
  void set_minipipe(Minipipe *minipipe_l);
  
  // sets this handler to use the following server socket;
  void set_minisockserv(Minisocketserver *sock);
  void set_minisock(Minisocket *sock, int ssl);
  Minisocket *create_minisock(unsigned int ip, int port, int ssl);
  
  // priority manipulation
  void set_priority(int _priority);
  int get_priority();

  //////////////////////////////////////////////////////////
  // functions for internal use (DO NOT USE IN USER CODE) //
  //////////////////////////////////////////////////////////

  // trigger functions (called by Runtime to trigger handle_*())
  void trigger_event(int type, void *data);
  
  // Registers this handler with a given runtime.  This is called by Runtime's 
  // register_handler()
  void register_runtime(Runtime *runtime_l);
  
  // Event interpreters (executed out of the runtime's context)
  void minipipe_message_arrived();
  void periodic_thread();
  void minissl_accept(Minisocket *sock);
  void minissl_ready();
  void minissl_closed();

  int get_sleep_time();

 protected:
  Runtime *runtime;
  
 private:
  pthread_t periodic_trigger;
  pthread_mutex_t lock;
  Minipipe *minipipe;
  int sleep_time;
  Semaphore *sleep_sem;
  Minisocketserver *serv;
  Minisocket *cli;
  int priority;
  char *name;

};

struct Runtime_Event {
  Runtime_Handler *handler;
  int event_type;
  void *data;
};

class Runtime {
 public:
  Runtime();
  Runtime(int _priority_levels);
  void internal_init();
  ~Runtime();

  // API
  void register_handler(Runtime_Handler *handler);
  
  void start_runtime(); //this function does not return until stop_runtime is called
  void stop_runtime();

  void trigger_event(Runtime_Handler *handler, int event_type, void *data);

 private:
  int alive;
  int priority_levels;
  std::vector <Runtime_Handler *> *handlers;
  std::deque <Runtime_Event> **events;
  pthread_mutex_t eventlock;
  Semaphore *eventcount;
};

#endif
