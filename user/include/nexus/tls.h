/* Nexus OS
   Thread local storage support 
 */

#ifndef NEXUS_TLS_H
#define NEXUS_TLS_H

extern unsigned long __thread_default_stack_size;
extern unsigned long __thread_global_stack_base;
extern unsigned long __thread_global_stack_limit;

extern int __errno_enable_tls;
extern int __errno_use_tls; 

int tls_setup_and_start(void *target, unsigned int arg0, unsigned int arg1,
			void (*continuation)(void *));

/* continuation takes rv from target as context */
#define FIRST_COMMON_USER_FUNCTION (tls_setup_and_start)

int fork_and_setup_tls(void *fork_spec);

#endif /* NEXUS_TLS_H */

