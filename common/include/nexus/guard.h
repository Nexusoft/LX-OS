/** NexusOS: Interface to the nexus label-, proof- and goalstores 
             implemented in labelstore and guard processes */

#ifndef _NEXUS_GUARD_IFACE_H_
#define _NEXUS_GUARD_IFACE_H_

#ifdef __NEXUS__
#include <nexus/fs.h>
#else /* Linux */
#define FSID int
#endif

struct form;
struct nxguard_object;
struct nxguard_tuple;

/** access control object ID 
    a bit complicated, to support legacy 12bit FSIDs */
struct nxguard_object {
	union {
		struct {
			unsigned long long upper;
			unsigned long long lower;
		};
		FSID fsid;
	};
};

struct nxguard_tuple {
	// subject MUST be first, as we skip first int to hash regions
	unsigned int 		subject;
	unsigned int 		operation;
	struct nxguard_object	object;
};

/// kernel decision cache element: readable through procfs
struct dcache_elem {
	union {
		struct {
			unsigned char decision;
			struct nxguard_tuple tuple;
		};

		// make power of two aligned
		unsigned char padding[32];
	};
};


////  Definitions  ////

#define GUARD_CRED_MAXSZ	(1 << 13)
#define DIGESTLEN 		(16)		///< long enough for MD5 and SHA1
#define PUBKEY_LEN		(427)		///< long enough for PEM-encoded 2K RSA pubkey
#define PRIVKEY_LEN		(1679)		///< long enough for PEM-encoded 2K RSA privkey
#define SDIGEST_LEN 		(PUBKEY_LEN)
#define CHALLENGE_LEN 		16		///< auth.channel challenge/response random number
#define AUTHREQ_LEN		1024		///< maximum length of a request to an authority
#define AUTHNAME_LEN 		(40)
#define PROOF_RULELENGTH	9000		///< maximum length of a single hintcode rule

#define REFMON_PORT_BLOCKALL	(-2)
#define REFMON_PORT_ALLOWALL	(-3)

#ifndef __NEXUSKERNEL__
#include <openssl/rsa.h>
#include <nexus/sema.h>

////  Guard crypto support API  ////

void rand_init(void);

RSA *	rsakey_create(void);
void	rsakey_destroy(RSA *rsakey);

RSA *	rsakey_public_import(char *pem_pubkey);
char *	rsakey_public_export(RSA *key);
RSA *	rsakey_public_import_file(const char *filename);
int	rsakey_public_export_file(RSA *key, const char *filepath);

RSA *	rsakey_private_import(const char *pem_privkey);
RSA *	rsakey_private_import_file(const char *filename);
int	rsakey_private_export_file(RSA *key, const char *filepath);


////  Guard API (think chmod/chown)  ////

int nxguard_cred_add(const char *in_fml, RSA *key);
int nxguard_cred_add_raw(const char *in_fml);
int nxguard_cred_addshort(const char *in_fml);
char * nxguard_goal_get(int oper, struct nxguard_object *object);
int nxguard_goal_set_str(int oper, struct nxguard_object *ob, const char *goal);
int nxguard_proof_set(int oper, struct nxguard_object *object, const char *p);

int nxguard_sdigest_create(const char *digest, RSA *rsakey, char *sdigest);
int nxguard_sdigest_verify(const char *digest, RSA *rsakey, 
		           const char *sdigest, int slen);

int nxguard_goalproof_set(const char *authname, int oper, 
			  struct nxguard_object *object, 
			  const char *statement, int goal);

// Authority API //

int nxguard_auth_register(int guard_port, int auth_port, const char *name);
#if defined __NEXUS__ && !defined __NEXUSKERNEL__
int nxguard_auth(int guard_port, const char *name, Sema *sema);
#endif

// File specific API //

int nxguard_chown(const char *file, const char *subject);
int nxguard_chmod(const char *file, const char *subject, int mode);

#else

// Kernel does not support full API

int nxkguard_init(void);

int nxguard_cred_add_raw(const char *in_fml);
int nxkguard_interposition_set(IPD *ipd, long ipcport);
int nxkguard_record_begin(void);
int nxkguard_record_end(void);
int nxkguard_allow(long subject, long operation, struct nxguard_object object);
int nxkguard_drop(long subject, long operation, struct nxguard_object object);

int  nxkguard_in(int ipcport, char *msg, int mlen, struct nxguard_tuple *tuple);
void nxkguard_out(struct nxguard_tuple *tuple);

int nxkguard_unittest(void);
int nxkguard_getsize(void);

int nxrefmon_start(int refmon_id);

extern int nxguard_kern_ready;
extern struct HashTable *guard_porttable;
extern char * guard_cache;
#endif

static inline void
nxguard_object_clear(struct nxguard_object *object)
{
	object->upper = object->lower = 0;
}

/** Special 'any' object in proof database. 
    Checked before checking an object specific goal
    Default policy (absence of a (sub, op, 'any') proof) is ALLOW */
#define NXGUARD_OBJECT_WILDCARD_UP	(0ULL)
#define NXGUARD_OBJECT_WILDCARD_LO	(0ULL)

#endif // _NEXUS_GUARD_IFACE_H_

