#ifndef __VKEY_H__
#define __VKEY_H__

#include <nexus/policy.h> 
#include <nexus/guard.h>  // experimental policy stuff
#include <nexus/generaltime.h> 

#include <nexus/kvkey.h> /* for AlgType */

typedef struct VKey_public VKey;

enum VKEY_ERRORS{
  VKEY_ERR_SUCCESS = 0,
  VKEY_ERR_WRONGTYPE,
  VKEY_ERR_OUTSPACE,
};

typedef enum VKeyType{
  VKEY_TYPE_PUBLIC = 1,
  VKEY_TYPE_PAIR,
  VKEY_TYPE_NSK,
  VKEY_TYPE_NRK,
}VKeyType;

#define NEXUS_DEFAULT_CA_PATH "/nfs/ca.crt"
#define NEXUS_DEFAULT_NEXUSCA_PATH "/nfs/nexusca.crt"
#define NEXUS_DEFAULT_NSK_PATH "/nfs/nexus.nsk"
#define NEXUS_DEFAULT_NSKCERT_PATH "/nfs/nexus.nsk.crt"
#define NEXUS_DEFAULT_NSKSFORM_PATH "/nfs/nexus.nsk.signed"
#define NEXUS_DEFAULT_NRK_PATH "/nfs/nexus.nrk"
#define NEXUS_DEFAULT_NRKCERT_PATH "/nfs/nexus.nrk.crt"
#define NEXUS_DEFAULT_NRKSFORM_PATH "/nfs/nexus.nrk.signed"
VKey *get_default_nsk(void);
void set_current_nsk(VKey *nsk);
VKey *get_default_nrk(void);
void set_current_nrk(VKey *nrk);

/* One of three types of keys can be created: 

   VKEY_TYPE_PAIR: Create a public private keypair that lives in
   userspace.  This can be used either to sign/verify or
   encrypt/decrypt (but should NOT be used for both, although the
   library doesn't enforce this).

   VKEY_TYPE_NSK: Create an NSK.  The NSK is stored in user space but the private
   part is encrypted such that the TPM(SRK under a set of PCRs) is the
   only one that can decrypt it.  It speaks for the kernel, and as
   such is used for signing formulas/ externalizing labels from the
   kernel. 

   VKEY_TYPE_NRK: Create an NRK.  The NRK is stored in user space but the private
   part is encrypted such that the TPM(SRK under a set of PCRs) is the
   only one that can decrypt it.  It serves as a storage key; data can
   be encrypted with its public half with a policy during sealing. */
VKey *vkey_create(VKeyType type, AlgType algtype);

VKeyType vkey_get_type(VKey *anykey);
AlgType vkey_get_algo(VKey *anykey);
void vkey_set_algo(VKey *anykey, AlgType algtype);

/* Free memory used by vkey. Note that none of the types of vkey hold
   kernel resources, so this is equivalent to a number of free's. */
void vkey_destroy(VKey *anykey);


/* Serialize a vkey so that it can be stored on disk or sent over the
   network.  If public_only == 1, only the public part of the key pair
   will be serialized. */
char *vkey_serialize(VKey *anykey, int serialize_public_only);

/* Deserialize a key (of any type) from a serialized buffer. */
/* You must call vkey_set_algo() after this, as the (industry standard)
 * serialized format does not record if this is an encryption key (ALG_RSA_ENCRYPT),
 * or a signing key (ALG_RSA_SHA1/MD2/...) */
VKey *vkey_deserialize(char *serialized, int serializedlen);


/* vkey_sign will takes the message m, signs it with the private part
   of usersigpair, and puts the resultant signature in sig.  The
   signature and message are not bundled together so that other
   protocols (like email/pgp) can put the messages and signatures in
   their own format.  */
int vkey_sign(VKey *usersignkey, unsigned char *msg, unsigned int msglen,
	      /*out:*/    unsigned char *sig, 
	      /*in/out:*/ int *siglen);

/* Return the length of the signature output buffer that vkey_sign
   will need. */
int vkey_sign_len(VKey *usersignkey);

/* vkey_verify returns 0 if the signature matches and <0 otherwise.
   It does not assume a format for the signature and message. */
int vkey_verify(VKey *anysignpubkey, 
		unsigned char *msg, unsigned int msglen,
		unsigned char *sig, int siglen);




/* Encrypt clen bytes at clear with storagepub and put result in
   output buffer enc. */
int vkey_encrypt(VKey *userstoragepubkey,
		 unsigned char *clear, int clen, 
		 /*out:*/    unsigned char *enc, 
		 /*in/out:*/ int *elen);

/* Return the length of the out buffer needed by vkey_encrypt. */
int vkey_encrypt_len(VKey *userstoragepubkey, unsigned char *clear, int clen); 


/* Decrypt elen bytes at enc with the private part of storagepair and
   put result in output buffer clear. */
int vkey_decrypt(VKey *userstoragepair, 
		 unsigned char *enc, int elen, 
		 /*out:*/    unsigned char *clear, 
		 /*in/out:*/ int *clen);

/* Return the length of the output buffer needed by vkey_decrypt. */
int vkey_decrypt_len(VKey *userstoragepair, unsigned char *enc, int elen);





/* Encrypt the private part of the pair tosealpriv with the public key
   storagepub along with a policy about the principals the data should
   be released to.  Storagepub can be a local or remote NRK or any
   other public storage key. */
/* Note: The holder of the private half of storagepub key is responsible
   for enforcing the two policies. In the case of an NRK, the kernel
   is the holder, and the kernel will give out only the data to 
   applications meeting the policies. */
int vkey_seal(VKey *anystoragepubkey, VKey *tosealpriv, 
	      _Policy *unsealpolicy, _Policy *resealpolicy,
	      /*out:*/    unsigned char *sealeddata, 
	      /*in/out:*/ int *sealeddatalen);

/* Same, but for sealing an arbitrary buffer instead of a private key. */
int vkey_seal_data(VKey *anystoragepubkey, unsigned char *data, int datalen,
	      _Policy *unsealpolicy, _Policy *resealpolicy,
	      /*out:*/    unsigned char *sealeddata, 
	      /*in/out:*/ int *sealeddatalen);

/* Return the length of the output buffer needed by vkey_seal. */
int vkey_seal_len(VKey *anystoragepub, VKey *tosealpriv, _Policy *unsealpolicy, _Policy *resealpolicy);

/* Return the length of the output buffer needed by vkey_seal_data. */
int vkey_seal_data_len(VKey *anystoragepub, int datalen, _Policy *unsealpolicy, _Policy *resealpolicy);

/* Unseal a key sealed to a user key.  The policy is not
   enforced. Unsealing with a user key passes the policies back so that
   they can be examined or enforced by the application.  */
VKey *vkey_user_unseal(VKey *userstoragepair,
		       unsigned char *sealeddata, int sealeddatalen, 
		       /*out:*/    _Policy **unsealpolicy, _Policy **resealpolicy); 

/* Same, but for unsealing an arbitrary buffer instead of a key. */
int vkey_user_unseal_data(VKey *userstoragepair,
		       unsigned char *sealeddata, int sealeddatalen, 
		       unsigned char *cleardata, int *cleardatalen,
		       /*out:*/    _Policy **unsealpolicy, _Policy **resealpolicy); 

/* Unseal key bound to a local nrk.  The policy is enforced by the
   kernel for data sealed by an nrk, so the grounds for meeting the policy
   must be passed in. */
VKey *vkey_nrk_unseal(VKey *nrk, 
		      unsigned char *sealeddata, int sealeddatalen, 
		      _Grounds *pg);

/* Same, but for unsealing an arbitrary buffer instead of a key. */
int vkey_nrk_unseal_data(VKey *nrk, 
		      unsigned char *sealeddata, int sealeddatalen, 
		      unsigned char *cleardata, int *cleardatalen,
		      _Grounds *pg);

int vkey_nrk_reseal(VKey *nrk, VKey *anystoragepub,
		      unsigned char *sealeddata, int sealeddatalen, 
		      unsigned char *resealeddata, int *resealeddatalen,
		      _Grounds *pg);

/* Same, but for unsealing an arbitrary buffer instead of a key. */
int vkey_nrk_reseal_data(VKey *nrk, VKey *anystoragepub,
		      unsigned char *sealeddata, int sealeddatalen, 
		      unsigned char *cleardata, int *cleardatalen,
		      _Grounds *pg);




/* Returns a pem encoded DER encoded x509 statement constructed in the
   kernel containing the public key anypub, valid from
   starttime->endtime.  The subject name includes the unique ipd name
   in the common name field and the issuer name is the kernel's
   distinguished name. */
int vkey_nsk_certify_key(VKey *nsk, VKey *anypubkey, 
			 TimeString *starttime, TimeString *endtime,
			 /*out:*/    char *x509, 
			 /*in/out:*/ int *x509len);

/* Returns the length of the x509 that will be created by the kernel
   during vkey_nsk_certify_len. */
int vkey_nsk_certify_key_len(VKey *nsk, VKey *anypubkey, 
			     TimeString *starttime, TimeString *endtime);


/* Returns a malloced pem encoded DER encoded x509 statement from the
   Nexus Ca specified in the x509 self-signed certifictate ncax509pem
   stating that the passed in NSK speaks for a particular Nexus
   version.  The buffer is malloced because the library does not know
   (without contacting the CA) how long the resulting certificate will
   be.  The length of the certificate is output in outlen. 

   This call could be split into 3: creating an aik, certifying the
   aik, and certifying the nsk, if it is too slow to create a new aik
   for every nsk certification. */
unsigned char *vkey_get_remote_certification(VKey *nsk, 
					     char *ncax509pem, 
					     int ncax509pemlen,
					     char *cax509pem, 
					     int cax509pemlen,
					     /*out:*/ int *outlen, int *outlen2);




/* Return a PEM encoded DER encoded X509 certificate issued by
   usersigpair and certifying anypub.  The distinguished name of the
   issuer and the subject can be supplied by the caller. */
int vkey_user_certify_key(VKey *usersignkey, VKey *anypubkey, 
			  unsigned char *serialnum, int serialnumlen,
			  char *iss_countryname, char *iss_statename,
			  char *iss_localityname, char *iss_orgname,
			  char *iss_orgunit, char *iss_commonname,
			  char *subj_countryname, char *subj_statename,
			  char *subj_localityname, char *subj_orgname,
			  char *subj_orgunit, char *subj_commonname,
			  TimeString *starttime, TimeString *endtime,
			  char *x509, int *x509len);

/* Calculate the needed length for the x509 returned by
   vkey_user_certify_key. */
int vkey_user_certify_key_len(VKey *usersignkey, VKey *anypubkey, 
			      unsigned char *serialnum, int serialnumlen,
			      char *iss_countryname, char *iss_statename,
			      char *iss_localityname, char *iss_orgname,
			      char *iss_orgunit, char *iss_commonname,
			      char *subj_countryname, char *subj_statename,
			      char *subj_localityname, char *subj_orgname,
			      char *subj_orgunit, char *subj_commonname,
			      TimeString *starttime, TimeString *endtime);
			  
#include <nexus/formula.h>
// users can sign with VKey_pair, or ask kernel to sign with VKey_nsk
SignedFormula *formula_sign(Formula *f, VKey *key);
SignedFormula *form_sign(Form *f, VKey *key);

/* For backwards compatibility with openssl RSA keys, these methods
   convert between openssl RSA*'s and VKey's. If we have other
   algorithms supported, we'll need more of these.
   Note: the serialized vkey format is compatible with most crypto libraries
   (like openssl) as well, so openssl keys can be loaded as vkeys using those
   methods.
   */
#include <openssl/rsa.h>
VKey *vkey_openssl_import(RSA *key);
RSA *vkey_openssl_export(VKey *key);


#endif
