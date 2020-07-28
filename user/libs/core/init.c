/* Nexus OS
   Code called before main()
 */

#include <stdint.h>

#include <nexus/tls.h>
#include <nexus/sema.h>
#include <nexus/atomic.h>
#include <nexus/pthread-nexus.h>
#include <nexus/linuxcalls_io.h>

#include <nexus/Thread.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Console.interface.h>

/** console is setup automatically for each application.
    they can use these handles for console I/O */
unsigned int printhandle, kbdhandle;

int __disable_filesystem;

/** allow applications to run code even before the 
    library pre-main() initialization code. */
void (*pre_main_hook)(void);

/* the actual application program start routine */
extern int main(int argc, char **argv);

/** second-stage init
    called from compatmain (see below) after TLS magic */
static void 
__init_finish(int argc, char **argv)
{
  // pre_main_hook must run before __errno_enable_tls; xen loader uses
  // this to disable use of TLS in the compat library
  if (pre_main_hook)
    pre_main_hook();
  
  if (__errno_enable_tls)
    __errno_use_tls = 1;

  // Early users of semaphores depends on initialized pthread state
  pthread_init_main(getesp() - 4);

  // Initialize stdio filedescriptors
  generic_file_init();

  // initialize IPC table
  __ipc_init();

  // mount kernefs (unless __disable_filesystem is set)
  posix_file_init();

  // set TPM version from environment
  //tpmcompat_init();

  //if (!__disable_filesystem)
   // set_current_nsk(get_default_nsk());

  exit(main(argc, argv));
}

/** application entry point (as set by the linker) */
int 
compatmain(int argc, char **argv) 
{
  printhandle = Console_Blit_Init();
  kbdhandle = Console_Kbd_Init();

  return tls_setup_and_start(__init_finish, (uint32_t) argc, (uint32_t) argv, NULL);
}

