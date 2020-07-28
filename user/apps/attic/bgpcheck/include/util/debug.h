#ifndef NBGP_DEBUG_H_SHIELD
#define NBGP_DEBUG_H_SHIELD

struct DebugState;

void enable_debug();

void debug_open_logfile(char *fname);
void debug_open_logset(char *setname);

DebugState *debug_get_stateptr(char *name);
void debug_start_timing(DebugState *s);
void debug_stop_timing(DebugState *s, int events);
void debug_start_timing(char *name);
void debug_stop_timing(char *name, int events);
void debug_trace(char *name);

FILE *debug_file();
#define dprintf(...) do { if(debug_file()){ fprintf(debug_file(), __VA_ARGS__); } } while (0)
void debug_file_state();
void debug_print_state(FILE *f);

#endif
