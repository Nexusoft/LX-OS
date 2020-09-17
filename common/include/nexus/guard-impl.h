/** NexusOS: Guard implementation specification:
             - serialization structures 
             - internal interfaces to proof checker */

#ifndef _NEXUS_GUARD_H_
#define _NEXUS_GUARD_H_

#include <nexus/vector.h>
#include <nexus/guard.h>

//////// Access control decisions  ////////
//
// userspace guards return to the kernel one of the AC_.. options

#define __AC_USED		(0x1 << 2)	///< this entry in use?
#define __AC_CACHE 		(0x1 << 1)	///< this entry cacheable?
#define	__AC_ALLOW		(0x1)		///< enabled & cached: decision

#define AC_UNKNOWN		(0)
#define AC_BLOCK_CACHE		(__AC_USED | __AC_CACHE)
#define AC_ALLOW_CACHE		(__AC_USED | __AC_CACHE | __AC_ALLOW)
#define AC_BLOCK_NOCACHE	(__AC_USED)
#define AC_ALLOW_NOCACHE	(__AC_USED              | __AC_ALLOW)

#ifndef __NEXUSKERNEL__

//  Databases (cred, goal, proof) //

int nxguardsvc_init(void);

int nxguardsvc_cred_add(const char *label, int caller);
int nxguardsvc_cred_addkey(const char *label, const char *pubkey, 
		           const char *sdigest, int slen, int caller);
int nxguardsvc_proof_set2(struct nxguard_tuple *tuple, const char *formula);
struct proof * nxguardsvc_proof_get_locked(struct nxguard_tuple *tuple);
int nxguardsvc_goal_set2(struct nxguard_tuple *tuple, const char *formula);
int nxguardsvc_goal_get(struct nxguard_tuple *tuple, char **goalcopy);

void nxguardsvc_unlock(void);

//  Proofchecker  //

int nxguardsvc_chk(struct nxguard_tuple *tuple);
int nxguardsvc_cred_chk(const char *der);

//  Authorities  //

int nxguardsvc_auth_ask(int portnum, const char *formula);
int nxguardsvc_auth_embedded(const char * formula);

// Name Server //

int nxguardsvc_name_add(const char *key, long port);
long nxguardsvc_name_get(const char *key);
void nxguardsvc_name_del(const char *key);
int  nxguardsvc_test(void);

#endif /* __NEXUSKERNEL__ */

/////////  Original code  ////////
//
// we use some of this, but not all. 
// XXX clean out when guard is stable

/*
 * Whenever a state predicate p is left "bare" in a policy goal formula (i.e.
 * outside of any "says"), the guard lets the application define the evaluation,
 * in effect silently prepending "Resource.epsilon says" to p in the policy goal
 * formula. 
 *
 * In the course of evaluating a policy goal, whenever a term S is found for
 * which the grounds provided don't give any evidence, the guard also silently
 * prepends a "Resource.epsilon says" to the S. In effect, the guard lets the
 * resource evaluate such terms in whatever way it sees fit.  Resources either
 * evaluate the predicate or term directly (by some local computation, and
 * possibly with the help of the kernel), or rely on some third party that is
 * usually reachable over an ipc channel. 
 *
 * The term_auth structure below provides the hook by which the guard can be
 * customized to handle such predicates and terms. We provide two specific
 * example term_auth constructors (one for evaluating the time of day by calling
 * the kernel, the other for evaluating certain expressions over the proc
 * filesystem, by doing filesystem reads), and one generic example term_auth
 * constructor that calls over an ipc channel to any service implementing the
 * TermAuth.svc interface.
 */

struct eval;

// An rule has the form IF h0 true, ..., hN true THEN F true.
// An lemma is the same but also has a proof.
struct _Lemma {
  char *name;
  struct form *arg; // argument, if any
  struct form *concl;
  int numprems;
  struct form **prems;
  char *pf; // optional proof (in which case we call it a lemma instead of a rule)
};


//////// proof evaluation ////////

/** Conclusion: a NAL statement derived from assumptions (hypotheses) */
struct Judge { 
  int refcnt;
  int arity; 			///< (optional) number of antecedents

  struct form *concl;		///< conclusion
  char *rule;			///< (optional) name of deduction rule
  PointerVector hyp;		///< hypotheses
  struct Judge *ant[]; 		///< (optional) antecedents (rules by which arrived here)
};

typedef struct Judge Judge;

enum proofstatus {PF_UNKNOWN, PF_SOUND, PF_UNSOUND};

/** Proof as supplied by a subject.
    Contains a deduction and after first evaluation, also 
    1) a statement on its soundness and
    2) a list of authorities to contact on each subsequent evaluation
 */
struct proof {
	struct nxguard_tuple hash;	///< identifying triple (sub, op, obj)
	
	// deduction
	char *deduction;		///< the proof, in hintcode
	enum proofstatus status;	///< deduction soundness
	unsigned long goal_id;		///< goal for which proof was verified

	// authorities: non-cachable credentials
	int num_auth;		
	char **auth_req;		///< NAL statements to attest to
	char **auth_der;		///< NAL statements in other form (optimization only for missing credential search)
	struct form **auth_form;	///< NAL statements in third form (optimizaiton only for missing credential search)
	int *auth_ports;		///< ipc ports to contact on
};

/* A goal expression plus a unique identifier. 
   The identifier is used to cheaply identify stale proof cache entries */
struct goal {
	struct form *form;
	unsigned long id;
};

/** Structure used during evaluation */
struct eval {
	int flags;
	int errors; // count of errors encountered
	
	const char *code; // current position of code (useful after an error)
	struct HashTable *rules;
	PointerVector rules_sorted;

	PointerVector stack; 		/* of Judges: deduction */
	PointerVector recentstack; 	/* of Judges: deduction backtracking */
};

struct eval * eval_create(void);
void eval_reset(struct eval *eval);
void eval_free(struct eval *eval);
int eval_run1(struct eval *eval, const char *code, int codelen, PointerVector *args);
int eval_run(struct eval *eval, const char *code, PointerVector *args);
void dump_eval_stack(struct eval *eval);

/** main proofchecker */
int guard_check(struct goal *goal, struct proof *proof);
int guard_check_deduction(struct eval *eval, const char *proof);

#endif // _NEXUS_GUARD_H_

