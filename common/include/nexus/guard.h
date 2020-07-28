/** NexusOS: Interface to the standard nexus guard. This file is intended for use by
    servers and resources, and defineds the interface they use to customize and
    interact with the guard.
 
    ``Unless you are kwalsh, you probably don't mean to be looking here.''
 */

#ifndef _NEXUS_GUARD_H_
#define _NEXUS_GUARD_H_

#include <stdarg.h>
#ifndef __NEXUSKERNEL__
#include <stdio.h> // for FILE

#include <openssl/rsa.h>
#endif

#include <nexus/guard.h>
#include <nexus/formula.h>
#include <nexus/policy.h>
#include <nexus/ipc.h>
#include <nexus/fs.h>

/////////  Userspace guard  ////////

#ifndef __NEXUSKERNEL__

#define GUARD_CRED_MAXSZ	(1 << 13)
#define DIGESTLEN 		(16)		///< long enough for MD5
#define PUBKEY_LEN		(427)		///< long enough for PEM-encoded RSA pubkey
#define SDIGEST_LEN 		(PUBKEY_LEN)
#define CHALLENGE_LEN 		16		///< auth.channel challenge/response random number
#define AUTHREQ_LEN		1024		///< maximum length of a request to an authority

enum guard_calltype { call_cred, call_goal, call_proof };

/** Object (in the context of security, not OO) identifier.
    The structure is a bit complicated, because it must support
    legacy 12bit FSIDs. */
struct nxguard_object {
	union {
		struct {
			uint64_t upper;
			uint64_t lower;
		};
		FSID fsid;
	};
};

struct guard_upcall_msg {
	unsigned long subject;		///< process identifier (ipd->id)
	unsigned long operation;	///< .svc or .sc call number
	struct nxguard_object object;
};

// header of a credential or goal message
struct guard_cred_header {
	unsigned short length;
	enum guard_calltype type;
	int replyport;			///< where to send response. no response if -1
};

struct guard_cred_msg {
	struct guard_cred_header header;

	char sdigest[SDIGEST_LEN];
	int slen;			///< true length of secure digest

	char pubkey[PUBKEY_LEN];

	char formula[];
};

struct guard_goalproof_msg {
	struct guard_cred_header header;

	struct nxguard_object object;
	unsigned long operation;

	char formula[];
};


struct guard_auth_challenge {
	int port;			///< port to continue conversion on
	char challenge[CHALLENGE_LEN];
};

/** message to open an authenticated channel 
    a standard challenge/response response
 */
struct guard_auth_response {
	char sdigest[SDIGEST_LEN];
	int slen;

	char pubkey[PUBKEY_LEN];
};

void rand_init(void);

RSA *  rsakey_create(void);
RSA *  rsakey_public_import(char *pem_pubkey);
char * rsakey_public_export(RSA *key);

int nxguard_sdigest_create(const char *plaintext, int plen,
		           char *sdigest, RSA *key);
int nxguard_sdigest_verify(const char *plaintext, int plen, RSA *key, 
		           const char *sdigest, int slen);

int nxguard_cred_add(const char *in_fml, RSA *key);
int nxguard_goal_set(int operation, struct nxguard_object *object, 
		     const char *in_fml);
int nxguard_proof_set(int operation, struct nxguard_object *object, 
		      const char *in_fml);

#endif

/////////  Kernel guard  ////////
// XXX deprecated

#ifdef __NEXUSKERNEL__
int nxguard_verify(Port_Num dest_port, Map *map, char *msg, int mlen, int ipd);
void nxguard_chgoal(FSID object, int operation, const char *nal_formula);
#endif


/////////  Original code  ////////

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

struct term_auth;
struct cred;
struct guard;
struct opencred;
struct eval;

typedef struct guard Guard;
typedef struct cred *(credential_query)(struct term_auth *auth, Form *f);

struct term_auth {
	char *name; 			///< the term we are an authority on
	struct cred * (*query)(void); 	///< generates a credential
};

/* Several kinds of credentials can be understood by guards. In future, we will
 * possibly add additional kinds, or make the guard extensible in this respect.
 *
 * Clients of resources specify the credentials to send using new_cred_*(), and
 * then cred_serialize.
 *
 * Resources accept the serialized credentials, and unpack them using
 * cred_deserialize().
 *
 * TODO: add types for "transient" "labeling functions" that add credentials at
 * the time of IPC.
 */

// tag values for credentials
#define CRED_SIGNED      0x1 /* a SignedFormula */
#define CRED_LABEL	 0x2 /* a Formula (i.e. label) obtained from a labelstore */
#define CRED_OTHER	 0x4 /* anything else, typically something from a term_auth */
#define CRED_BOGUS	 0x5 /* a Formula taken at face value (for debugging) */

typedef struct cred {
	int tag; 		///< type of credential, see CRED_... above
	char *data;		///< DER encoded statement

	/// function to translate type-specific data into a Form oc->f
	int (*open)(struct opencred *oc);
} Cred;

Cred *new_cred_signed(SignedFormula *sf);
Cred *new_cred_bogus(Formula *f); // similar to signed, but no signature (for testing)

void cred_free(Cred *cred);

int creds_serialize(Cred **cred, int ncreds, unsigned char *buf, int *len);
Cred **creds_deserialize(unsigned char *buf, int len, int *numcreds);

struct opencred {
	struct cred *cred;
	int needed;		///< is credential used in proof? tempvar
	Form *f;

	/// the following are for dynamic generation of credentials
	//  by authorities from runtime state
	int (*start)(struct opencred *oc);
	int (*stop)(struct opencred *oc);
	void *priv;
};

struct opencred *cred_open(Cred *cred);
void cred_close(struct opencred *oc);

// three example constructors that can create useful term_auth structures
term_auth *new_auth_ipc_byname(char *svcname, char *prin);
term_auth *new_auth_clock(void);
term_auth *new_auth_procfs(void);

/*
 * Policies come in (at least) two varieties:
 *  IF (gf) DO op1
 *  DURING (gf) DO op1 THEN op2 CATCH op3
 * where gf is an arbitrary policy goal formula.
 *
 * Typically, resources protected by a guard will support only one variety, and
 * the operations op1, op2, and op3 will be fixed by the designer ahead of time.
 * Thus only the gf part of the policy can typically be chosen by the owner, or
 * changed at run time.
 *
 * Grounds contain all the information a guard needs to evaluate the policy goal
 * formula: a evaluation and instantiation tree, and the set of credentials that
 * correspond to the leaves of the tree.
 */

struct _Policy {
  Formula gf;
};

static inline int _Policy_len(_Policy *pol) {
  return Formula_len(&pol->gf);
}

static inline int _Policy_serialize(_Policy *pol, char *buf, int *len) {
  memcpy(buf, pol->gf.body, *len);
  return 0;
}

static inline int _Policy_deserialize(_Policy *pol, int *pollen, char *buf, int buflen) {
  memcpy(pol->gf.body, buf, buflen);
  return 0;
}

// create a new "allow all" policy
_Policy *policy_all(void);

// create a new "allow none" policy
_Policy *policy_none(void);

struct _Grounds {
  char *hints; // a string containing hints, written in the hintcode grammar
  int argc;
  Formula **args; // inline arguments
  int numleaves;
  Cred **leaves;
};

// An rule has the form IF h0 true, ..., hN true THEN F true.
// An lemma is the same but also has a proof.
struct _Lemma {
  char *name;
  Form *arg; // argument, if any
  Form *concl;
  int numprems;
  Form **prems;
  char *pf; // optional proof (in which case we call it a lemma instead of a rule)
};

struct _Lemma *guard_rule_introduce_a(Guard *g, char *name, char *concl, char **premises);
struct _Lemma *guard_rule_introduce(Guard *g, char *name,
    char *concl, /* char *prem1, char *prem2, */ ... /*, 0 */); 

struct _Lemma *guard_lemma_introduce_a(Guard *g, char *name, char *concl, char *pf, char **premises);
struct _Lemma *guard_lemma_introduce(Guard *g, char *name,
    char *concl, char *pf, /* char *prem1, char *prem2, */ ... /*, 0 */); 

// stuff a _Grounds into a contiguous chunk of memory  
char *grounds_serialize(_Grounds *pg, int *len);
_Grounds *grounds_deserialize(char *buf, int len);

#ifdef __NEXUSKERNEL__
// _Grounds can be passed to the kernel directly -- it can traverse the fairly
// simple data structure without much effort
// return will be NULL on error or if pg argument was NULL
_Grounds *peek_grounds(Map *map, _Grounds *pg, int max, int *err);
#endif

void grounds_free(_Grounds *pg);

//////// proof evaluation ////////

/* Structure used during evaluation */
struct Judge { // hyp0, ..., hypN --> concl true
  char *comment;
  int was_dup;
  PointerVector hyp;
  Form *concl;
  char *rule; // (optional) rule by which this judgement was derived
  int arity; // (optional) number of antecedents
  struct Judge *ant[]; // (optional) antecedents
};

typedef struct Judge Judge;

/** Structure used during evaluation */
struct eval {
	int flags;
	PointerVector stack; /* of Judge* */
	PointerVector recentstack; /* of Judge* */
	char *code; // current position of code (useful after an error)
	int errors; // count of errors encountered
	struct HashTable *rules;
	PointerVector rules_sorted;
	struct HashTable *params; // same hashtable as guard->params
	PointerVector *param_names, *param_vals; // same vector as guard->param_*
};

int eval_run1(struct eval *eval, char *code, int codelen, PointerVector *args);


//////// A Guard object holds all state needed to evaluate a policy. ////////

struct guard {
	int flags;
#ifdef __NEXUSKERNEL__
	void *pfout;
#else
	FILE *pfout;
#endif
	struct eval eval;
	Formula *gf;
	Form *gfx;
	
	///< (optional) proof that gives conclusion gfx. If given, a caller
	//   may use the default proof, if it can satisfy all assumptions,
	//   i.e., if it has all the right credentials.
	char *proof;		

	///< axiomatic truths given by guard_addpolicy
	PointerVector facts;

	PointerVector vars;
	struct HashTable *params;
	PointerVector *param_names, *param_vals;
};

Guard *guard_create(void);
void guard_init(Guard *g);
void guard_dump(Guard *g);
void guard_destroy(Guard *g);
void guard_free(Guard *g);


#define GUARD_DEBUG_ALL      (-1)
#define GUARD_DEBUG_POLICY   0x1
#define GUARD_DEBUG_HINTCODE 0x2
#define GUARD_DEBUG_PROOFS   0x3
void guard_setdebug(Guard *g, int flags);
#ifndef __NEXUSKERNEL__
void guard_setdebugpfout(Guard *g, FILE *out);
#else
void guard_setdebugpfout(Guard *g, void *out);
#endif

int guard_setgoal(Guard *g, Formula *gf);
Formula *guard_getgoal(Guard *g);

int guard_addpolicy(Guard *g, Formula *fact);

int guard_addauth(Guard *g, term_auth *auth);

//int guard_setvar(Guard *g, char *var, Form *val);

/* guard_setvar() can be used to simplify the representation of formulas in
 * proofs by defining a sort of global variables. Passing NULL for val unsets
 * the value.
 */
void guard_set_param(Guard *g, char *paramname, Form *val);

int guard_check(Guard *g, Form *req, _Grounds *pg);
//int guard_check_hold(Guard *g, char *req, char **asmps, int nasmps, cred_t **creds, int ncreds);
//int guard_check_release(int token);

int guard_check_lemma(Guard *g, struct _Lemma *lemma);

Cred *new_cred_label(FSID labelid);

#endif // _NEXUS_GUARD_H_

