/* NexusOS: standalone proof evaluator. Compiles on Linux 
   XXX integrate with proofchecker.c without losing Linux build */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>	// only if mallinfo is used

#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>

#include <nexus/rdtsc.h>
#include <nexus/test.h>
#include <nexus/profiler.h>
#include <nexus/hashtable.h>
#include <nexus/vector.h>
#include <nexus/guard.h>
#include <nexus/guard-impl.h>
#include <nexus/formula.h>
#include <nexus/der.h>
#include <nexus/pem.h>
#include <nexus/formula.h>
#include <nexus/base64.h>

// replaces nexus defines to be able to build for linux
#ifndef __NEXUS__
#define guard_authority_port 		(1)
#endif
#define RSA_EXPONENT_BYTE_SIZE          (3)
#define RSA_DEFAULT_EXPONENT_ARRAY	(rsa_default_exponent_array_g)
#define FAILRETURN(ERR, ...)		do {printf(__VA_ARGS__); return ERR;} while (0);

typedef char VKey;
#ifndef __NEXUS__
typedef struct HashTable HashTable;

// replace nexus security library to be able to build for linux
#include "../../../common/code/guard_pf.c" 
#include "../../../common/code/guard_eval.c" 
#include "../../../common/code/vector-code.c"
#include "../../../common/code/hashtable-code.c"
#include "../../../common/code/der.c"
#include "../../../common/code/formula-code.c"  
#include "../../../common/code/base64-code.c"
#include "../../../common/code/profiler.c"
#include "../../../user/libs/security/NAL.tab.c"
#include "../../../user/libs/security/NAL.yy.c"
#endif

#include "eval_inner.c"

int
main(int argc, char **argv)
{
	printf("NAL proof evaluation benchmark\n");
	
	if (test_outer("delegation", proof_generate_delegation))
		return 1;
	if (test_outer("negation", proof_generate_negation))
		return 1;
	if (test_outer("boolean", proof_generate_boolean))
		return 1;
	
	printf("[eval] OK. Completed all tests successfully\n");
	return 0;
}

