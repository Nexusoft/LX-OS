#ifndef _EVENTQUEUE_HH_
#define _EVENTQUEUE_HH_

#include <vector>
#include <algorithm>
#include <iostream>
#include <sstream>

#include <nq/util.hh>

// Logging helper functions

static inline std::string ip_to_string(uint32_t ip) {
  return itos(ip);
}

struct EventQueue {
  struct Entry_base {
    double issue_time;
    double curr_time;
    Entry_base(double i_time, double t) : 
      issue_time(i_time), curr_time(t) { }
    virtual inline ~Entry_base() { }
    virtual void apply(std::ostream &log) = 0;
    bool operator<(const Entry_base &r) {
      // NOTE!!! This is reversed because we want the heap to give us the smallest item!
      return curr_time > r.curr_time;
    }
  };

  // wrap the pointer so that we can run operator< & heapify the event vector
  struct Entry_P {
    Entry_base *ptr;
    Entry_P() : ptr(NULL) { }
    Entry_P(Entry_base *p) : ptr(p) { }
    bool operator<(const Entry_P &r) {
      return *this->ptr < *r.ptr;
    }
  };

  template <class T>
  struct Entry : Entry_base {
    T continuation;
    Entry(double issue_time, double t, const T &c) :
      Entry_base(issue_time, t), continuation(c) { }
    // need virtual destructor to insure that continuation is freed
    virtual inline ~Entry() { }

    virtual inline void apply(std::ostream &log) {
      continuation(log, *this);
    }
  };

  std::ostream &log_stream;
  std::stringstream curr_event_log;
  double sim_time;
  std::vector<Entry_P> events;

  EventQueue(const std::string &logfile) : 
    log_stream(*(new std::ofstream(logfile.c_str()))), 
    curr_event_log(""),
    sim_time(0) { }

  EventQueue() : 
    log_stream(std::cout), 
    curr_event_log(""),
    sim_time(0) {
  }
  ~EventQueue() {
    delete &log_stream;
  }

  void reset(void){
    assert(events.size() == 0);
    sim_time = 0;
  }

  // Returns true if a simulation step was taken
  bool run_step(void) {
    if(events.size() == 0) {
      std::cerr << "No more sim steps\n";
      return false;
    }
    std::pop_heap(events.begin(), events.end());
    Entry_base *e = events.back().ptr;
    events.pop_back();

    // std::cerr << "Next event at time " << e->time << "\n";
    assert(sim_time <= e->curr_time);
    sim_time = e->curr_time;
    e->apply(curr_event_log);
    delete e;

    //if(strlen(curr_event_log.str().c_str()) > 0) {
    if(curr_event_log.str().size() > 0) {
      log_stream << sim_time << ": " << curr_event_log.str() << "\n";
    }
    curr_event_log.str("");

    return true;
  }

  // returns number of steps
  int run_all(void) {
    int count;
    while(run_step()) {
      count++;
    }
    return count;
  }

  void log_curr_event(const std::string &s) {
    curr_event_log << s << " ";
  }
  void log_curr_event(std::stringstream &s) {
    log_curr_event(s.str());
  }

  // N.B.: The event pointer is owned by the queue
  template <class T>
  void schedule_from_now(double delta, const T &continuation) {
    double event_time = sim_time + delta;
    // std::cerr << "Scheduling event at " << event_time << "\n";
    events.push_back(Entry_P(new Entry<T>
				       (sim_time, event_time, continuation)) );
    std::push_heap(events.begin(), events.end());
  }

  template <class T>
  void fail(T &continuation) {
    std::stringstream str_log("");
    continuation.fail(str_log, sim_time);
    log_curr_event(str_log);
  }
};

#endif
