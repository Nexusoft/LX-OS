#include <iostream>
#include <fcntl.h>
#include <sys/time.h>
#include <map>

#include "../include/util/debug.h"
#include "../include/runtime/runtime.h"

struct DebugState {
  int usec_total, sec_total;
  int events;
  
  struct timeval last_time;
  
  DebugState() {
    usec_total = sec_total = events = 0;
    last_time.tv_sec = 0;
    last_time.tv_usec = 0;
  }
};

static std::map<char *,DebugState *> *debug_states;
static FILE *debug_output = NULL;
int debug_run_id = -1;

void debug_open_logfile(char *fname){
  assert(debug_output = fopen(fname, "w+"));
}

int read_int(FILE *f){
  char c;
  int i = 0;
  while(!feof(f)){
    if(fread(&c, sizeof(char), 1, f) < 1) break;
    if(c < 0) break;
    c -= '0';
    if((c >= 0) && (c < 10)){
      i *= 10;
      i += c;
    }
  }
  return i;
}

void debug_open_logset(char *setname){
  FILE *set_file;
  char *newname;
  
  assert(set_file = fopen(setname, "r"));
  debug_run_id = read_int(set_file);
  fclose(set_file);
  newname = (char *)alloca(strlen(setname) + 30);
  assert(newname);
  sprintf(newname, "%s_%03d", setname, debug_run_id);
  debug_open_logfile(newname);
  
  assert(set_file = fopen(setname, "w"));
  fprintf(set_file, "%d", debug_run_id+1);
  fclose(set_file);
}

void enable_debug(){
  if(debug_states) return;
  debug_states = new std::map<char *,DebugState *>();
}

DebugState *debug_get_stateptr(char *name){
  if(!debug_states) return NULL;
  std::map<char *,DebugState *>::iterator s;
  
  s = debug_states->find(name);
  if(s == debug_states->end()){
    (*debug_states)[name] = new DebugState();
    s = debug_states->find(name);
    assert(s != debug_states->end());
  }
  
  return s->second;
}

void debug_start_timing(DebugState *s){
  if(!debug_states || !s) return;
  gettimeofday(&s->last_time, NULL);
}
void debug_start_timing(char *name){
  if(!debug_states) return;
  debug_start_timing(debug_get_stateptr(name));
}

static void debug_calc_timing(DebugState *s, int events, struct timeval now){
  if(!debug_states) return;
  s->usec_total += (int)now.tv_usec - (int)s->last_time.tv_usec;
  s->sec_total += (int)now.tv_sec - (int)s->last_time.tv_sec;
  while(s->usec_total >= 1000*1000){
    s->sec_total ++;
    s->usec_total -= 1000*1000;
  }
  while(s->usec_total < 0){
    s->sec_total --;
    s->usec_total += 1000*1000;
  }
  s->events += events; 
}
void debug_stop_timing(DebugState *s, int events){
  if(!debug_states || !s) return;
  struct timeval now;
  gettimeofday(&now, NULL);
  debug_calc_timing(s, events, now);
}
void debug_stop_timing(char *name, int events){
  if(!debug_states) return;
  struct timeval now;
  gettimeofday(&now, NULL);
  debug_calc_timing(debug_get_stateptr(name), events, now);
}

FILE *debug_file(){
  if(!debug_states) return NULL;
  return debug_output;
}

void debug_file_state(){
  if(!debug_states) return;
  if(debug_output){
    debug_print_state(debug_output);
    fflush(debug_output);
  }
}

void debug_print_state(FILE *f){
  if(!debug_states) return;
  
  std::map<char *,DebugState *>::iterator i;
  
  for(i = debug_states->begin(); i != debug_states->end(); ++i){
    fprintf(f, "%s: %d.%06d seconds total",
      i->first,
      i->second->sec_total, i->second->usec_total
    );
    if(i->second->events > 0){
      fprintf(f, ", %d events", i->second->events);
      if(i->second->sec_total > 0){
        fprintf(f, ", %d events/sec", i->second->events/i->second->sec_total);
        
      }
    }
    fprintf(f, "\n");
  }
}
