/** NexusOS: Communication between guard process and its callers */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>

#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>

#include <nexus/defs.h>
#include <nexus/ipc.h>
#include <nexus/vector.h>
#include <nexus/formula.h>
#include <nexus/policy.h>
#include <nexus/guard.h>
#include <nexus/hashtable.h>
#include <nexus/debug.h>

#include <nexus/IPC.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/LabelStore.interface.h>

#include <../../../common/code/guard-code.c>
#include <../../../common/code/guard_eval.c>
#include <../../../common/code/guard_cred.c>
#include <../../../common/code/guard_pf.c>

#define ReturnError(str, retval) \
	do { fprintf(stderr, str); return retval; } while (0);

void
rand_init(void)
{
	char seedstring[] = "you didn't expect real randomness, did you?\n";
	static int initialized;

	if (!initialized) {
		initialized = 1;
		RAND_seed(seedstring, sizeof(seedstring)); 
	}
}

RSA *
rsakey_create(void)
{
	RSA *key;

	rand_init();

	printf("[rsa] Generating key pair. This may take a while..\n");
	key = RSA_generate_key(2048, 17, NULL, NULL);
	if (key)
		printf("[rsa] OK. Keypair generated\n");
	else
		printf("[rsa] ERROR. Key creation failed\n");

	return key;
}

/** Extract the public part from an RSA key in PEM format */
char *
rsakey_public_export(RSA *key)
{
	BUF_MEM *biobuf;
	BIO *bio;
	char *pem_pubkey;
	int plen;

	bio = BIO_new(BIO_s_mem());
	if (!bio)
		return NULL;

	PEM_write_bio_RSAPublicKey(bio, key);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &biobuf);
	
	plen = biobuf->length;
	pem_pubkey = malloc(plen + 1);
	memcpy(pem_pubkey, biobuf->data, plen);
	pem_pubkey[plen] = 0;

	BIO_free(bio);
	return pem_pubkey;
}

/** Import a public RSA key from a PEM format */
RSA *
rsakey_public_import(char *pem_pubkey) 
{
	RSA *key;
	BIO *bio;

	bio = BIO_new_mem_buf(pem_pubkey, PUBKEY_LEN);
	if (!bio) 
		return NULL;

	key = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
	BIO_free(bio);

	return key;
}

/** Create a secure digest. 
    @param sdigest must be at least SDIGEST_LEN bytes long

    @return the digest length on success or -1 on failure */
int
nxguard_sdigest_create(const char *plaintext, int plen,
		       char *sdigest, RSA *rsakey)
{
	char digest[DIGESTLEN];

	if (SDIGEST_LEN < RSA_size(rsakey))
		return -1;

	MD5(plaintext, plen, digest);
	return RSA_private_encrypt(DIGESTLEN, digest, sdigest, 
			           rsakey, RSA_PKCS1_PADDING);
}

/** Return 0 if sdigest is the signed version of digest or -1 if not. */
int
nxguard_sdigest_verify(const char *plaintext, int plen, RSA *rsakey, 
		       const char *sdigest, int slen)
{
	char odigest[DIGESTLEN];
	char digest[DIGESTLEN];
	int ret;

	ret = RSA_public_decrypt(slen, sdigest, odigest, rsakey, 
			         RSA_PKCS1_PADDING);
	if (ret != DIGESTLEN) {
		printf("Decryption Failed (%d)\n", ret);
		return -1;
	}

	MD5(plaintext, plen, digest);
	if (memcmp(digest, odigest, DIGESTLEN))
		return -1;

	return 0;
}

/** Insert a DER encoded NAL statement of the type "key:[key] says X".
    
    @param cred is NAL statement in memory-tree format
    @param key must be the RSA key whose public part is used in the formula 
 */
static struct guard_cred_msg * 
__nxguard_cred_new(Form *form, RSA *key)
{
	struct guard_cred_msg *msg;
	char digest[DIGESTLEN];
	char *der, *pubkey;
	int dlen, plen, ret, mlen;

	// create DER representation
	der = (char *) form_to_der(form);
	free(form);
	dlen = der_msglen(der);

	// create message
	mlen = sizeof(*msg) + dlen;
	msg = malloc(mlen);
	msg->header.length = mlen;
	msg->header.type = call_cred;
	msg->header.replyport = -1;

	// create sdigest
	msg->slen = nxguard_sdigest_create(der, dlen, msg->sdigest, key);
	if (msg->slen <= 0)
		ReturnError("[guardcall] cred sign error\n", NULL);

#ifndef NDEBUG
	// verify sdigest
	if (nxguard_sdigest_verify(der, dlen, key, msg->sdigest, msg->slen))
		ReturnError("[guardcall] cred signature error\n", NULL);
#endif

	// copy public key
	pubkey = rsakey_public_export(key);
	memcpy(msg->pubkey, pubkey, PUBKEY_LEN);
	free(pubkey);

	// copy statement
	memcpy(msg->formula, der, dlen);

	return msg;
}

/** Tell the guard a statement S. 
    This function automatically rewrites it into 
    pem(<rsa public key>) says S*/
int
nxguard_cred_add(const char *in_fml, RSA *key)
{
#define MAXCREDLEN 500
	struct guard_cred_msg *msg;
	Form *form;
	char prefix[MAXCREDLEN + 1];
	char *pubkey;
	int flen;

	// extract the public key
	pubkey = rsakey_public_export(key);

	// prepend "pem(..) says"
	snprintf(prefix, MAXCREDLEN, "pem(%%{bytes:%d}) says %s", PUBKEY_LEN, in_fml);
	form = form_fmt(prefix, pubkey);
	free(pubkey);
	if (!form)
		ReturnError("[guardcall] cred extend statement failed\n", -1);

	msg = __nxguard_cred_new(form, key);
	free(form);
	if (!msg)
		return -1;

	if (IPC_Send(guard_credential_port, msg, msg->header.length)) 		
		ReturnError("[guardcall] send cred error\n", -1);

	return 0;	
}

/** Tell the guard to set a policy */
static int
nxguard_goalproof_set(int operation, struct nxguard_object *object, 
		      const char *in_fml, enum guard_calltype type)
{
	struct guard_goalproof_msg *msg;
	int mlen, slen, ret, portnum;

// need a recv port to get a reply. not needed in general.
// but XXX I need to find a way to keep the automated test working.
#ifdef DO_RECV
	portnum = IPC_CreatePort(NULL);
#endif

	slen = strlen(in_fml) + 1;
	mlen = sizeof(*msg) + slen;
	msg = malloc(mlen);

	msg->header.length = mlen;
	msg->header.type = type;
#ifdef DO_RECV
	msg->header.replyport = portnum;
#else
	msg->header.replyport = -1;
#endif

	memcpy(&msg->object, object, sizeof(*object));
	msg->operation = operation;
	memcpy(msg->formula, in_fml, slen);

	if (IPC_Send(guard_credential_port, msg, mlen)) 		
		ReturnError("[guardcall] send goal error\n", -1);
	
#ifdef DO_RECV
	if (IPC_Recv(msg->header.replyport, &ret, sizeof(ret)) != sizeof(ret))
		ReturnError("[guardcall] recv goal error\n", -1);
#endif

	printf("[guard] set goal OK\n");
	return 0;
}

int
nxguard_goal_set(int operation, struct nxguard_object *object, 
		 const char *in_fml)
{
	return nxguard_goalproof_set(operation, object, in_fml, call_goal);
}

int
nxguard_proof_set(int operation, struct nxguard_object *object, 
		  const char *in_fml)
{
	return nxguard_goalproof_set(operation, object, in_fml, call_proof);
}

