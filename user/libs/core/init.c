/** Nexus OS: Code called before main() */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include <nexus/tls.h>
#include <nexus/sema.h>
#include <nexus/atomic.h>
#include <nexus/pthread-nexus.h>
#include <nexus/linuxcalls_io.h>

#include <nexus/Thread.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Console.interface.h>

int __disable_filesystem;

/** allow applications to run code even before the 
    library pre-main() initialization code. */
void (*pre_main_hook)(void);

extern int main(int argc, char **argv);

/** libc compatibility: initialize its environment variable.
    Normally, __uClibc_main sets this. That clashes with our
    initialization, so we skip it. */
extern char **__environ;

/** second-stage init
    called from compatmain (see below) after TLS magic */
static int
__init_second(int argc, char **argv)
{
  int ret;

  // pre_main_hook must run before __errno_enable_tls; xen loader uses
  // this to disable use of TLS in the compat library
  if (pre_main_hook)
    pre_main_hook();
  
  // if __errno_enable_tls then the caller is the xen monitor. 
  if (__errno_enable_tls) {
    __errno_use_tls = 1;
  
    // Early users of semaphores depends on initialized pthread state
    pthread_init_main(getesp() - 4);

    // Initialize stdio filedescriptors
    generic_file_init();

    // mount kernelfs (unless __disable_filesystem is set)
    posix_file_init();
  }

  __environ = &argv[argc + 1];
  exit(main(argc, argv));
}

/** application entry point (as set by the linker) */
int
compatmain(int argc, char **argv) 
{
  if (__errno_enable_tls)
  	return tls_setup_and_start(__init_second, (uint32_t) argc, 
				   (uint32_t) argv, NULL);
  else
	return __init_second(argc, argv);
}

