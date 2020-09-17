/** NexusOS: authorities embedded in the guard */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/defs.h>
#include <nexus/ipc.h>
#include <nexus/rdtsc.h>
#include <nexus/guard.h>
#include <nexus/guard-impl.h>

#include <nexus/IPC.interface.h>

/** Blueprints for the parameter authority 'parser'
    The arguments to 'param' are (decriptorno, byte offset, byte length)
    where descriptorno is the offset in the list of descriptors. Each
    VarLen parameter has a descriptor, counting starts at 1.
 
    Note that, as a result, this function can only inspect the contents
    of parameters of type varlen */
#define FML_STR	"name.guard says param(%d,%d,%d) = \"%100s\""

extern __thread struct nxguard_tuple *tuple_active;

/** An authority for access control on call parameters */
int
guard_authority_param(const char *formula)
{
	char data[100], data2[100];
	int ret, dnum, doff, dlen;

	// try match string
	ret = sscanf(formula, FML_STR, &dnum, &doff, &dlen, data);
	if (ret != 4)
		return 0;
	
	if (dlen > 99)
		return 0;
	if (IPC_TransferInterpose(dnum, data2, doff, dlen, 1)) {
		fprintf(stderr, "param auth: transfer\n");
		return 0;
	}
	
	ret = memcmp(data, data2, dlen) ? 0 : 1;
	return ret;
}

/** Authority on proofs in the proof database 
    fmt is proof.<pid>.<operation>.<object (hi)>.<object (low)>
           where <pid> may be replaced by 0 to denote caller
	   (as pid 0, the kernel, does not need authorization)
 */
static int
guard_authority_proof(const char *formula)
{
	struct nxguard_tuple tuple;
	struct proof *proof;
	char proofreq[100];
	int ret, num, plen, p2len;

	num = sscanf(formula, "name.guard says proof.%d.%d.%llu.%llu = \"%99s\"",
		     &tuple.subject, &tuple.operation, 
		     &tuple.object.upper, &tuple.object.lower, proofreq);
	if (num != 5) 
		return 0;

	// special case: interpret pid 0 as caller
	if (tuple.subject == 0) {
		assert(tuple_active);
		tuple.subject = tuple_active->subject;
	}
	
	// verify passed proof (drop trailing \")
	plen = strlen(proofreq);
	if (plen && proofreq[plen - 1] == '"')
		plen--;

	proof = nxguardsvc_proof_get_locked(&tuple);
	// string and saved proof
	if (proof) {
		p2len = strlen(proof->deduction);
		if (!plen && !p2len)
			ret = 1;
		else
			ret = strcmp(proofreq, proof->deduction) ? 0 : 1;
	}
	else {
		// no string and no proof 
		if (!plen)
			ret = 1;
		// fail
		else
			ret = 0;
	}
	
	nxguardsvc_unlock();

	return ret;	
}

/** authority on current authorization subject */
static inline int
guard_authority_subject(const char *formula)
{
	int subject;

	if (sscanf(formula, "name.guard says subject = %d", &subject)) 
		return (subject == tuple_active->subject) ? 1 : 0;
	else
		return 0;
}

static inline int
guard_authority_clockcycle(const char *formula)
{
	int tread;

	// authority on CPU cyclecount
	if (sscanf(formula, "name.guard says mcycles < %d", &tread) == 1)
		return (rdtsc64() >> 20) < tread ? 1 : 0;
	else 
		return 0;
}

/** trivial "always accept" (for benchmarking) */
static inline int
guard_authority_ok(const char *formula)
{
	const char ok[] = "name.guard says me = ok";
	
	if (!memcmp(formula, ok, sizeof(ok) - 1))
		return 1;
	else 
		return 0;
}

/** The guard can also act as authority.
    For instance, it will attest to the state of the CPU timestamp counter
 
 	name.guard says mcycles < <int> 

    Here, mcycles means megacycles. We use that because the NAL 
    integer format cannot express 64-bit numbers (on 32-bit architectures)
 */
int 
nxguardsvc_auth_embedded(const char * formula)
{
	if (guard_authority_ok(formula))
		return 1;

	if (guard_authority_clockcycle(formula))
		return 1;

	if (guard_authority_proof(formula))
		return 1;

	if (guard_authority_subject(formula))
		return 1;

	if (guard_authority_param(formula))
		return 1;

	// block by default
	return 0;
}

