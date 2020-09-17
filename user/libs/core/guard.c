/** NexusOS: clientside implementation of guard API */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <malloc.h>

#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>

#include <nexus/defs.h>
#include <nexus/ipc.h>
#include <nexus/log.h>
#include <nexus/vector.h>
#include <nexus/formula.h>
#include <nexus/policy.h>
#include <nexus/guard.h>
#include <nexus/guard-impl.h>
#include <nexus/hashtable.h>
#include <nexus/debug.h>
#include <nexus/sema.h>
#include <nexus/test.h>
#include <nexus/machine-structs.h>

#include <nexus/IPC.interface.h>
#include <nexus/Guard.interface.h>
#include <nexus/Thread.interface.h>

// only for file-specific calls (chown, chmod)
// move to separate file if this codebase grows
#include <nexus/idl.h>
#include <nexus/fs.h>
#include <nexus/fs_path.h>
#include <nexus/FS.interface.h>
#include <nexus/Auth.interface.h>
#include <nexus/Guard.interface.h>


////////  OpenSSL wrappers  ////////

void
rand_init(void)
{
	char seedstring[] = "you didn't expect real entropy, did you?\n";
	static int initialized;

	if (!swap(&initialized, 1))
		RAND_seed(seedstring, sizeof(seedstring)); 
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
		printf("[rsa] Key creation failed\n");

	return key;
}

/** Extract the public part from an RSA key in PEM format. */
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

	assert(plen + 1 <= PUBKEY_LEN);
	pem_pubkey = calloc(1, PUBKEY_LEN);
	memcpy(pem_pubkey, biobuf->data, plen);
	pem_pubkey[plen] = 0;

	BIO_free(bio);
	return pem_pubkey;
}

static int
rsakey_export_file(RSA *key, const char *filepath, int private)
{
	BIO *bio;

	bio = BIO_new_file(filepath, "w");
	if (!bio) {
		fprintf(stderr, "[rsa] failed to create file %s\n", filepath);
		return -1;
	}
	
	if (private)
		PEM_write_bio_RSAPrivateKey(bio, key, NULL, NULL, 
					    0, NULL, NULL);
	else
		PEM_write_bio_RSAPublicKey(bio, key);

	BIO_flush(bio);
	BIO_free(bio);

	return 0;
}

/** Write the public key to a file.
    @return 0 on success, -1 on error */
int
rsakey_public_export_file(RSA *key, const char *filepath)
{
	return rsakey_export_file(key, filepath, 0);
}

int
rsakey_private_export_file(RSA *key, const char *filepath)
{
	return rsakey_export_file(key, filepath, 1);
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

static RSA *
rsakey_import_file(const char *filepath, int private)
{
	RSA *key;
	BIO *bio;

	bio = BIO_new_file(filepath, "r");
	if (!bio) {
		fprintf(stderr, "[rsa] failed to open file %s\n", filepath);
		return NULL;
	}

	if (private)
		key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	else
		key = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);

	BIO_free(bio);

	return key;
}

RSA *
rsakey_public_import_file(const char *filepath)
{
	return rsakey_import_file(filepath, 0);
}

RSA *
rsakey_private_import_file(const char *filepath)
{
	return rsakey_import_file(filepath, 1);
}

/** Read a PEM-encoded key from a buffer. 
    Format listens very closely:
      - include PEM header and footer 
      - have \n at all line-ends 
 */
RSA *
rsakey_private_import(const char *pem_privkey)
{
	RSA *key;
	BIO *bio;

	bio = BIO_new_mem_buf((char *) pem_privkey, PRIVKEY_LEN);
	if (!bio) 
		return NULL;

	key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	if (!key) {
		fprintf(stderr, "[rsa] read private key failed\n");
		return NULL;
	}

	if (RSA_check_key(key) != 1) {
		fprintf(stderr, "[rsa] invalid key\n");
		RSA_free(key);
		return NULL;
	}

	BIO_free(bio);
	return key;
}

void   
rsakey_destroy(RSA *rsakey)
{
	RSA_free(rsakey);
}

/** Create a secure digest. 
    @param sdigest must be at least SDIGEST_LEN bytes long

    @return the digest length on success or -1 on failure */
int
nxguard_sdigest_create(const char *digest, RSA *rsakey, char *sdigest)
{
	int ret;

	// verify that the memory area is large enough for openssl RSA
	if (SDIGEST_LEN < RSA_size(rsakey)) {
		fprintf(stderr, "[rsa] sdigest too small: %d < %d\n",
			SDIGEST_LEN, RSA_size(rsakey));
		return -1;
	}

	ret = RSA_private_encrypt(DIGESTLEN, digest, sdigest, 
			          rsakey, RSA_PKCS1_PADDING);
	if (ret == -1) {
		ERR_load_crypto_strings();
		fprintf(stderr, "[rsa] %s\n",
			ERR_error_string(ERR_get_error(), NULL));
	}
	
	return ret;
}

/** Return 0 if sdigest is the signed version of digest or -1 if not. */
int
nxguard_sdigest_verify(const char *digest, RSA *rsakey, 
		       const char *sdigest, int slen)
{
	char odigest[DIGESTLEN];
	int ret;

	ret = RSA_public_decrypt(slen, sdigest, odigest, rsakey, 
			         RSA_PKCS1_PADDING);
	if (ret != DIGESTLEN) {
		printf("Decryption Failed (%d)\n", ret);
		return -1;
	}

	if (memcmp(digest, odigest, DIGESTLEN))
		return -1;

	return 0;
}


////////  Clientside Interface  ////////

static int guard_replyport;

////  Policy API (think chmod/chown)  ////

/** Insert an unsigned ('raw') credential. 
    The guard will only accept these if the calling process 
    can demonstrate to 
      (1) speakfor whoever it has as X in X says Y or
          most likely, this means the label is ``process.x says S'',
	  where x is the current pid
      (2) be the kernel */
int
nxguard_cred_add_raw(const char *in_fml)
{
	return Guard_AddCred_ext(default_guard_port, VARLENSTR(in_fml));
}

int
nxguard_cred_addshort(const char *in_fml)
{
	struct label label;
	int slen;

	slen = strlen(in_fml);
	if (slen + 30 >= sizeof(label.data))
		return -1;

	sprintf(label.data, "process.%d says %s", getpid(), in_fml);
	return Guard_AddCredShort_ext(default_guard_port, label);
}

/** Tell the guard to set or delete a statement S. 
    This function automatically rewrites it into 
	
	principal says S

    Where principal is a PEM key if parameter key is not NULL
    or the current process id if it is.

    @return 0 on success, failure otherwise
 */
int
nxguard_cred_add(const char *in_fml, RSA *key)
{
	Form *form;
	char digest[DIGESTLEN], sdigest[SDIGEST_LEN];
	char *der, *pubkey, *label, *template;
	int ret = 1, ilen, llen, slen;

	ilen = strlen(in_fml);
	
	if (!key) {
		label = malloc(ilen + 30);
		sprintf(label, "process.%d says %s", getpid(), in_fml);
		ret = nxguard_cred_add_raw(label);
	
		free(label);
		return ret;
	}

	// serialize key
	pubkey = rsakey_public_export(key);
	assert(pubkey);

	// generate label key:X says S
	template = malloc(ilen + 100);
	snprintf(template, ilen + 99, "pem(%%{bytes:%d}) says %s", PUBKEY_LEN, in_fml);
	form = form_fmt(template, pubkey);
	if (!form) 
		goto cleanup;
	label = form_to_pretty(form, 0);
	der = (char *) form_to_der(form);
	llen = strlen(label);

	// create MAC 
	MD5(der, der_msglen(der), digest);
	slen = nxguard_sdigest_create(digest, key, sdigest);
	if (slen <= 0)
		ReturnError(1, "[guardcall] cred sign error");

#ifdef DEBUG_EXTENSIVE
	// verify MAC
	if (nxguard_sdigest_verify(digest, key, sdigest, slen))
		ReturnError(1, "[guardcall] cred signature error");
#endif

	// serialize and send label
	ret = Guard_AddCredKey_ext(default_guard_port, 
				   VARLEN(label, llen + 1),
			           VARLEN(pubkey, PUBKEY_LEN),
				   VARLEN(sdigest, slen));
	free(der);
	free(label);
	form_free(form);

cleanup:
	free(template);
	free(pubkey);
	return ret;
}

static inline void
nxguard_tuple_set(struct nxguard_tuple *tuple, int subject, int oper, 
		  struct nxguard_object *object)
{
	tuple->subject = subject;
	tuple->operation = oper;
	if (object)
		tuple->object = *object;
	else
		tuple->object.upper = tuple->object.lower = 0;
}

int
nxguard_goal_set_str(int oper, struct nxguard_object *ob, const char *goal)
{
	struct nxguard_tuple tuple;

	nxguard_tuple_set(&tuple, 0, oper, ob);
	if (goal)
		return Guard_SetGoal_ext(default_guard_port, tuple, VARLENSTR(goal));
	else
		return Guard_SetGoal_ext(default_guard_port, tuple, VARLENSTR(""));
}

/** Ask for the DER encoded goal
    @return a DER string (that the caller must free) 
            or NULL if no goal is set
 	    or (void *) -1 on error */
char *
nxguard_goal_get(int oper, struct nxguard_object *object)
{
	struct nxguard_tuple tuple;
	char *goal, *out;
	int len;

	nxguard_tuple_set(&tuple, 0, oper, object);
	goal = alloca(1024);
	len = Guard_GetGoal_ext(default_guard_port, tuple, VARLEN(goal, 1024));
	if (len < 0) 
		return NULL;

	out = malloc(len);
	memcpy(out, goal, len);
	
	return out;
}

int
nxguard_proof_set(int oper, struct nxguard_object *object, const char *p)
{
	struct nxguard_tuple tuple;

	nxguard_tuple_set(&tuple, getpid(), oper, object);
	if (p)
		Guard_SetProof_ext(default_guard_port, tuple, VARLENSTR(p));
	else
		Guard_SetProof_ext(default_guard_port, tuple, VARLENSTR(""));
	return 0;
}

/** Automatically set goal "authority says $statement" 
                  and proof "assume authority says $statement"
		  goal = 0 -> only set proof
		  goal = 1 -> only set goal
		  goal = 2 -> set both                      */
int
nxguard_goalproof_set(const char *authname, int oper, 
		      struct nxguard_object *object, const char *statement,
		      int goal)
{
	char *buf;

	// large enough to hold a proof with PEM key
	// slight memleak on return with error
	buf = malloc(GUARD_CRED_MAXSZ);	

	// set policy
	if (goal >= 1) {
		snprintf(buf, GUARD_CRED_MAXSZ, "name.%s says %s\n", authname, statement);
		if (nxguard_goal_set_str(oper, object, buf))
			ReturnError(1, "set goal");
	}
	
	if (goal != 1) {
	// set proof
		snprintf(buf, GUARD_CRED_MAXSZ, "assume name.%s says %s\n", authname, statement);
		if (nxguard_proof_set(oper, object, buf))
			ReturnError(1, "set proof");

		free(buf);
	}

	return 0;
}


////////  Experimental Unix chown/chmod support
  
/** Nexus version of chown 
             
    This is NOT a perfect correspondence with Unix chown() 
    The function inserts the credential <file> says <principal> speaksfor <file>,
    if the caller may insert the credential (i.e., speaks for the file)

    XXX also set goal on SetGoal to grant exclusive access to principal
    XXX increase nonce
 */
int
nxguard_chown(const char *filepath, const char *subject)
{
	const int buflen = 512;

	struct nxguard_object ob;
	char buf[buflen];

	// resolve filepath
	ob.fsid = nexusfs_resolve(filepath);
	if (!FSID_isValid(ob.fsid)) 
		ReturnError(1, "unknown file\n");

// need "file says name speaksfor file", not "process says name speaksfor file"
#if 0
	// generate credential
	if (snprintf(buf, buflen, "%s speaksfor ipc.%u.%llu",
		     subject, ob.fsid.port, fsid_upper(&ob.fsid)) == buflen)
		ReturnError(1, "path or principal too long\n");

	// insert cred
	if (nxguard_cred_add(buf, NULL))
		ReturnError(1, "access denied");
#else
	// generate credential
	if (snprintf(buf, buflen, "ipc.%u.%llu.1 says %s speaksfor ipc.%u.%llu.1",
		     ob.fsid.port, fsid_upper(&ob.fsid), subject, 
		     ob.fsid.port, fsid_upper(&ob.fsid)) == buflen)
		ReturnError(1, "path or principal too long\n");

	// insert cred
	if (nxguard_cred_add_raw(buf))
		ReturnError(1, "access denied");
#endif

	return 0;
}

/** remove access control check */
static int
mod_clr(const char *file, int oper)
{
	struct nxguard_object ob;

	// resolve filepath
	ob.upper = ob.lower = 0;
	ob.fsid = nexusfs_resolve(file);
	if (!FSID_isValid(ob.fsid)) 
		ReturnError(1, "unknown file\n");

	return nxguard_goal_set_str(oper, &ob, NULL);
}

/** insert access control check
    @param subject the principal that is given access

    XXX do NOT hardcode nonce '1'
 */
static int
mod_set(const char *file, const char *subject, int oper)
{
	struct nxguard_object ob;
	char buf[512];

	// resolve filepath
	ob.upper = ob.lower = 0;
	ob.fsid = nexusfs_resolve(file);
	if (!FSID_isValid(ob.fsid)) 
		ReturnError(1, "unknown file\n");

	// insert delegation policy
	snprintf(buf, 511, "ipc.%u.%llu.1 says %s speaksfor ipc.%u.%llu.1",
		 ob.fsid.port, fsid_upper(&ob.fsid), subject, 
		 ob.fsid.port, fsid_upper(&ob.fsid));
	return nxguard_goal_set_str(oper, &ob, buf);
}

/** Nexus equivalent of chmod

    NOT a Unix chmod implementation.
    It [at|de]tached the goal that the given principal speaksfor the file, if
    this tool is allowed to change goals on the file
 
    does not explicitly support group privileges. Just apply S_IRUSR to
    the group subject 

    BROKEN logic. XXX change 
      - goal to "file says allow=1"
      - some (auto) proof for principals to show
        - "principal says allow=1"
	- "principal speaksfor guard"

  */
int
nxguard_chmod(const char *file, const char *subject, int mode)
{
	int ret = 0;

	// read permissions
	if (mode & S_IROTH) 
		ret |= mod_clr(file, SYS_FS_Write_CMD);
	else if (mode & S_IRGRP)
		{ ReturnError(1, "group privileges not explicitly supported\n"); }
	else if (mode & S_IRUSR) 
		ret |= mod_set(file, subject, SYS_FS_Read_CMD);

	// write permissions
	if (mode & S_IWOTH) 
		ret |= mod_clr(file, SYS_FS_Write_CMD);
	else if (mode & S_IWGRP)
		{ ReturnError(1, "group privileges not explicitly supported\n"); }
	else if (mode & S_IWUSR) 
		ret |= mod_set(file, subject, SYS_FS_Write_CMD);

	// execute permissions
	if (mode & S_IXOTH) 
		ret |= mod_clr(file, SYS_IPC_Exec_CMD);
	else if (mode & S_IXGRP)
		{ ReturnError(1, "group privileges not explicitly supported\n"); }
	else if (mode & S_IXUSR) 
		ret |= mod_set(file, subject, SYS_IPC_Exec_CMD);

	return ret;
}

