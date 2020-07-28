/** NexusOS: support for standardized tests */

#ifndef NEXUS_USER_TEST_H
#define NEXUS_USER_TEST_H

#define ReturnError(retval, str) 					\
	do {								\
		fprintf(stderr, "%s.%d: %s", __FUNCTION__, __LINE__, str); \
	     	return retval; 						\
	} while (0);							\

// quietly skip automated testing 
#define test_skip_auto()						\
	if (argc == 2) {						\
		if (strcmp(argv[1], "auto")) {				\
			fprintf(stderr,"Usage: %s\n", __FUNCTION__);	\
			return 1;					\
		}							\
		return 0;						\
	}

#endif /* NEXUS_USER_TEST_H */

