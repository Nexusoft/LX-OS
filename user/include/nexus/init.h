/* Nexus OS
   Support for code called before main()
 */

#ifndef NEXUS_USER_INIT_H
#define NEXUS_USER_INIT_H

/* Hook for performing custom initialization */
extern void (*pre_main_hook)(void);

/* Turns off posix filesystems */
extern int __disable_filesystem; 

#endif /* NEXUS_USER_INIT_H */

