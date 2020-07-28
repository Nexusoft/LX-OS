#ifndef _NEXUS_DEBUG_H_
#define _NEXUS_DEBUG_H_

#ifndef __NEXUSKERNEL__

/* Initialize the debug trap handlers, but nothing more. */
void gdb_init_local(void);

/* Initialize the remote debugging system.
 * If port is >0, it is taken as a hint for which tcp port to try and listen on,
 * otherwise port 4444 is used. In both cases, we try port, port+1, port+2,
 * etc., in trun.
 * If activate is non-zero, it will block and wait for a connection from a
 * remote gdb.
 *
 * Whenever an assert() fails, or breakpoint() is called, or some other
 * debuggable event, the application will wait for a connection from a remote
 * gdb if one is not already established. On the remote machine, do like so:
 *
 *    ~/nexus/user> gdb apps/nskgen/nskgen.debug
 *    (gdb) target remote 128.84.227.23:4444
 *
 * As shown, it helps to be in the top-level directory, so source paths line up
 * right.  It also helps to use the debug version of the binary.  And, you
 * should use whatever IP/port is printed on your nexus box.
 */
void gdb_init_remote(int port, int activate);

/* Generate a breakpoint exception and trap into gdb. */
void breakpoint(void);

#endif // __NEXUSKERNEL__

/* Debug printing can be turned on and off globally or per-c-file.
 * The global level overrides the local level (favoring more printing).
 *
 * The debug levels can be changed at run-time time using, e.g:
 *    global_debug_level = DEBUG_LEVEL_WARN;
 *    local_debug_level = DEBUG_LEVEL_INFO;
 *
 * The default local level can be changed on a per-c-file basis as well:
 *    #define LOCAL_DEBUG_LEVEL DEBUG_LEVEL_WARN // do this on line 1 of the c file
 *
 */

enum {
  DEBUG_LEVEL_NONE = 0, // no debug messages
  DEBUG_LEVEL_WARN = 1, // print errors and warnings
  DEBUG_LEVEL_INFO = 2, // print random crap
};

extern int global_debug_level; 
#ifndef LOCAL_DEBUG_LEVEL
#define LOCAL_DEBUG_LEVEL DEBUG_LEVEL_NONE
#endif
static int __attribute__ ((unused)) local_debug_level = LOCAL_DEBUG_LEVEL; 

#ifdef __NEXUSKERNEL__
#define debug_print(...) printk_red(__VA_ARGS__)
#else
#define debug_print(...) fprintf(stderr, __VA_ARGS__)
#endif

/* A convenience function for printing debug information, e.g.:
 *    dprintf(INFO, "about to do something with i=%d, j=%d\n", i, j);
 *    dprintf(WARN, "oh dear, somehow %d is bigger than %d\n", i, j);
 */
#define dprintf(level, ...) \
  do { \
    int lvl = DEBUG_LEVEL_##level; \
    if (lvl <= global_debug_level || lvl <= local_debug_level) \
      debug_print(__VA_ARGS__); \
  } while (0)

/* A convenience function for returning failures from functions, e.g.:
 * Instead of writing:
 *    return NULL; // oops, secret magic number was missing
 * Use instead:
 *    FAILRETURN(NULL, "oops, secret magic number was missing");
 */
#define FAILRETURN(retval, ...) \
  do { \
    dprintf(WARN, "%s:%d ", __FILE__, __LINE__); \
    dprintf(WARN, __VA_ARGS__); \
    dprintf(WARN, "\n"); \
    return (retval); \
  } while (0)

/* Some convenience booleans for checking the current debug level, e.g.:
 * if (DEBUG_INFO) {
 *    int temp = compute_expensive_thing();
 *    dprintf(INFO, "a little bird told me me %d\n", temp);
 * }
 */
#define DEBUG_WARN (DEBUG_LEVEL_WARN <= global_debug_level || DEBUG_LEVEL_WARN <= local_debug_level)
#define DEBUG_INFO (DEBUG_LEVEL_INFO <= global_debug_level || DEBUG_LEVEL_INFO <= local_debug_level)

/*
 * convenience function: write some data to a file
 */
int writefile(const char *filename, const void *data, int datalen);

#endif // _NEXUS_DEBUG_H_

