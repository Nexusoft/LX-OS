/** NexusOS: support for standardized tests */

#ifndef NEXUS_USER_TEST_H
#define NEXUS_USER_TEST_H

#ifdef __NEXUS__
#include <nexus/Debug.interface.h>
#else
#define Debug_Trace(x)
#endif

#define ReturnError(retval, str) 					\
	{ do {								\
		unsigned long ebp;					\
		fprintf(stderr, "%s.%d: %s\n", __FUNCTION__, __LINE__, str); \
  		asm("movl %%ebp, %0" : "=g" (ebp));			\
		Debug_Trace(ebp);					\
	     	return retval; 						\
	} while (0); }							\

// quietly skip automated testing 
#define test_skip_auto()						\
	if (argc == 2 && !strcmp(argv[1], "auto"))			\
		return 0;

static inline int
nxtest_isauto(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "auto"))
		return 1;
	else
		return 0;
}

#define nxtest_msg(str)	fprintf(stderr, "%s.%d: %s\n",\
				__FUNCTION__, __LINE__, str);

#endif /* NEXUS_USER_TEST_H */

