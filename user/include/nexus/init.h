/* Nexus OS
   Support for code called before main()
 */

#ifndef NEXUS_USER_INIT_H
#define NEXUS_USER_INIT_H

/* Hook for performing custom initialization */
extern void (*pre_main_hook)(void);

/* Turns off posix filesystems (breaks tpmcompat) */
extern int __disable_filesystem; 

/* Handles to the console */
extern int printhandle;
extern int kbdhandle;

#endif /* NEXUS_USER_INIT_H */

