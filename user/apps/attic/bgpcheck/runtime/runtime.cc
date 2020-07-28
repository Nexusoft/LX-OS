#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <assert.h>
#include "../include/util/common.h"
#include "../include/runtime/runtime.h"
#include "../include/runtime/minipipe.h"
#include <sys/select.h>
extern "C" {
#include <nexus/Thread.interface.h>
}

using namespace std;

extern int sleep(int);

void minipipe_wrapper(Runtime_Handler *handler){
  handler->minipipe_message_arrived();
}

void periodic_wrapper(Runtime_Handler *handler){
  handler->periodic_thread();
}

void minissl_wrapper(Minisocket *sock, Runtime_Handler *handler){
  handler->minissl_accept(sock);
}
void minisslready_wrapper(Minisocket *sock, Runtime_Handler *handler){
  handler->minissl_ready();
}
void minisslclosed_wrapper(Minisocket *sock, Runtime_Handler *handler){
  handler->minissl_closed();
}

Runtime_Handler::Runtime_Handler(char *_name){
  sleep_time = -1;
  sleep_sem = NULL;
  minipipe = NULL;
  serv = NULL;
  cli = NULL;
  runtime = NULL;
  name = _name;
  priority = 1;
}

Runtime_Handler::Runtime_Handler(int periodic_l, Minipipe *minipipe_l, char *_name){
  sleep_time = -1;
  sleep_sem = NULL;
  set_periodic_time(periodic_l);
  minipipe = NULL;
  set_minipipe(minipipe_l);
  serv = NULL;
  cli = NULL;
  runtime = NULL;
  name = _name;
  priority = 1;
}
Runtime_Handler::~Runtime_Handler(){
}

Runtime *Runtime_Handler::get_runtime(){
  return runtime;
}

void Runtime_Handler::handle_minipipe(Minipipe *pipe, Runtime *runtime){
  //ignore.  Override if you want something to happen
}
void Runtime_Handler::handle_accept(Minisocket *sock, Runtime *runtime){
  //ignore.  Override if you want something to happen
}
void Runtime_Handler::handle_sockready(Minisocket *sock, Runtime *runtime){
  //ignore.  Override if you want something to happen
}
int Runtime_Handler::handle_periodic(Runtime *runtime){
  return -1;
  //ignore.  Override if you want something to happen
}
void Runtime_Handler::handle_sockclosed(Minisocket *sock, Runtime *runtime){

}

void Runtime_Handler::set_minipipe(Minipipe *minipipe_l){
  if(minipipe != NULL){
    minipipe->set_signal(NULL, NULL);
    minipipe = NULL;
  }
  if(minipipe_l != NULL){
    minipipe = minipipe_l;
    minipipe->set_signal((minipipe_signal)minipipe_wrapper, this);
  }
}

void Runtime_Handler::set_periodic_time(int time){
  if(time > 0){
    if(sleep_time >= 0){ printf("sleep time > 0 on a %s\n", name); assert(0); }
    sleep_time = time;
    if(!sleep_sem){
      sleep_sem = new Semaphore(0);
      pthread_create(&(this->periodic_trigger), NULL, (void *(*)(void *))&periodic_wrapper, this);
    }
    sleep_sem->up();
  }
}

void Runtime_Handler::set_minisockserv(Minisocketserver *_sock){
  if(serv != NULL){ printf("serv != NULL on a %s\n", name); assert(0); }
  serv = _sock;
  serv->start_listen((minissl_ready_callback *)&minissl_wrapper, this);
}
void Runtime_Handler::set_minisock(Minisocket *sock, int ssl){
  if(cli != NULL){ printf("cli != NULL on a %s\n", name); assert(0); }
  cli = sock;
  cli->accept((minissl_ready_callback *)&minisslready_wrapper, this, ssl);
  cli->set_closed_cback((minissl_ready_callback *)&minisslclosed_wrapper, this);
}
Minisocket *Runtime_Handler::create_minisock(unsigned int ip, int port, int ssl){
  if(cli != NULL){ printf("cli != NULL on a %s\n", name); assert(0); }
  cli = new Minisocket(ip, port, (minissl_ready_callback *)&minisslready_wrapper, this, ssl);
  cli->set_closed_cback((minissl_ready_callback *)&minisslclosed_wrapper, this);
  return cli;
}

void Runtime_Handler::trigger_event(int event_type, void *data){
  switch(event_type){
    case RUNTIME_EVENT_TIMER:
      set_periodic_time(handle_periodic(runtime));
      break;
    case RUNTIME_EVENT_MINIPIPE:
      handle_minipipe(minipipe, runtime);
      break;
    case RUNTIME_EVENT_SOCKACCEPT:
      handle_accept((Minisocket *)data, runtime);
      break;
    case RUNTIME_EVENT_SOCKREADY:
      set_minipipe(cli->read_pipe());
      handle_sockready(cli, runtime);
      break;
    case RUNTIME_EVENT_SOCKCLOSED:
      handle_sockclosed(cli, runtime);
      break;
    default:
      assert(!"Runtime Error: Unknown event occurred");
  }
}

void Runtime_Handler::register_runtime(Runtime *runtime_l){
  if(runtime != NULL){ printf("runtime != NULL on a %s\n", name); assert(0); }
  runtime = runtime_l;
}

void Runtime_Handler::minipipe_message_arrived(){
  assert(runtime != NULL);
  runtime->trigger_event(this, RUNTIME_EVENT_MINIPIPE, NULL);
}
void Runtime_Handler::periodic_thread(){
  int next_time;
  while(true){
    sleep_sem->down();
    Thread_USleep(sleep_time * 1000); //XXX is there a better way to do this?
    sleep_time = -1;
    assert(runtime != NULL);
    runtime->trigger_event(this, RUNTIME_EVENT_TIMER, NULL);
  }
}

void Runtime_Handler::minissl_accept(Minisocket *sock){
  assert(runtime != NULL);
  runtime->trigger_event(this, RUNTIME_EVENT_SOCKACCEPT, sock);
}
void Runtime_Handler::minissl_ready(){
  assert(runtime != NULL);
  runtime->trigger_event(this, RUNTIME_EVENT_SOCKREADY, NULL);
}
void Runtime_Handler::minissl_closed(){
  assert(runtime != NULL);
  runtime->trigger_event(this, RUNTIME_EVENT_SOCKCLOSED, NULL);
}

void Runtime_Handler::set_priority(int _priority){
  priority = _priority;
}
int Runtime_Handler::get_priority(){
  return priority;
}

//////////////////////////////////// END RUNTIME_HANDLER

Runtime::Runtime(){
  priority_levels = 3;
  internal_init();
}
Runtime::Runtime(int _priority_levels){
  priority_levels = _priority_levels;
  internal_init();
}
void Runtime::internal_init(){
  int i;
  
  pthread_mutex_init(&eventlock, NULL);
  eventcount = new Semaphore(0);
  
  handlers = new vector<Runtime_Handler *>();
  events = new (std::deque <Runtime_Event> *)[priority_levels];
  for(i = 0; i < priority_levels; i++){
    events[i] = new deque<Runtime_Event>();
  }
  
  alive = 0;
}
Runtime::~Runtime(){
  int i;

  pthread_mutex_destroy(&eventlock);
  delete eventcount;

  while(handlers->size() > 0){
    delete handlers->back();
    handlers->pop_back();
  }

  delete handlers;
  for(i = 0; i < priority_levels; i++){
    delete events[i];
  }
  delete events;
}

void Runtime::register_handler(Runtime_Handler *handler){
  handler->register_runtime(this);

  handlers->push_back(handler);
}
void Runtime::start_runtime(){
  int i;
  Runtime_Event e;

  if(alive > 0){
    assert(!"This Runtime instance has already been started!");
  }

  alive = 1;

  while(alive){
    //printf("Waiting for event!\n");
    eventcount->down();
    //printf("Event occurred!\n");

    pthread_mutex_lock(&eventlock);
    //printf("Got event lock!\n");
    for(i = priority_levels-1; i >= 0; i--){
      if(events[i]->size() > 0){
        e = events[i]->front();
        events[i]->pop_front();
        break;
      }
    }
    assert(i >= 0);
    pthread_mutex_unlock(&eventlock);
    
    //printf("Triggering event : %d on handler (0x%08x)\n", e.event_type, e.handler);
    
    e.handler->trigger_event(e.event_type, e.data);
  }
}
void Runtime::stop_runtime(){
  alive = 0;
}

void Runtime::trigger_event(Runtime_Handler *handler, int event_type, void *data){
  Runtime_Event e;
  e.handler = handler;
  e.event_type = event_type;
  e.data = data;
  
  //printf("Preparing trigger for event : %d on handler (0x%08x)(me: (0x%08x)\n", e.event_type, e.handler, this);
  assert(handler->get_priority() < priority_levels);
  
  pthread_mutex_lock(&eventlock);
    events[handler->get_priority()]->push_back(e);
  pthread_mutex_unlock(&eventlock);
  
  eventcount->up();
}
