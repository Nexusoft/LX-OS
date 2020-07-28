#ifndef __LIBTCPA_IDENTITY_PRIVATE_H__
#define __LIBTCPA_IDENTITY_PRIVATE_H__

#include <libtcpa/keys.h>  /* PubKeyData and SymKeyData definitions */
#include <libtcpa/buildbuff.h>

#define MAX_IDLABEL_LEN         (256)
#define MAX_CRED_LEN            (4096)
#define MAX_IDBINDING_LEN       (1024)

/* the max sizes for certain ready-for-tpm structures */
#define TCPA_PROOF_SIZE (TCPA_VERSION_SIZE + 20 + MAX_IDLABEL_LEN + MAX_IDBINDING_LEN + 3*MAX_CRED_LEN)
#define TCPA_IDENTITY_REQ_SIZE (8 + TCPA_ASYM_PARM_SIZE + TCPA_SYM_PARM_SIZE + TCPA_PROOF_SIZE + AES_BLOCK_SIZE + TCPA_SYM_KEY_SIZE + RSA_ENC_SIZE)
#define TCPA_IDCONTENTS_SIZE (TCPA_VERSION_SIZE + 4 + TCPA_HASH_SIZE + TCPA_PUBKEY_SIZE)
#define TCPA_IDENTITY_RESP_SIZE (4 + TCPA_SYM_PARM_SIZE + MAX_CRED_LEN + TCPA_SYM_KEY_SIZE + TCPA_HASH_SIZE + RSA_ENC_SIZE + AES_BLOCK_SIZE)


/* loosely corresponds to TCPA_Identity_Proof */
typedef struct IdentityProofData{
  unsigned int labelSize;
  unsigned int idbindingSize;
  unsigned int endorsementSize;
  unsigned int platformSize;
  unsigned int conformanceSize;
  PubKeyData identityKey;
  unsigned char labelArea[MAX_IDLABEL_LEN];
  unsigned char idbinding[MAX_IDBINDING_LEN];
  unsigned char endorsementCred[MAX_CRED_LEN];
  unsigned char platformCred[MAX_CRED_LEN];
  unsigned char conformanceCred[MAX_CRED_LEN];
}IdentityProofData;

/* loosely cooresponds to TCPA_Identity_Req */
typedef struct IdentityReqData{
  PubKeyData pubkey; /* ca's pubkey */
  SymKeyData symkey;
  IdentityProofData proof;
}IdentityReqData;

/* loosely corresponds to TCPA_IDENTITY_CONTENTS */
typedef struct IdentityContentsData{
  int idlabelsize;
  char idlabel[MAX_IDLABEL_LEN];
  PubKeyData cakey;
  PubKeyData idkey;
}IdentityContentsData;


/* fill structures with known data */
int fillIdentityContentsData(IdentityContentsData *newid, 
			     unsigned char *idlabel, int idlabelsize,
			     PubKeyData *cakey, PubKeyData *idkey);


/* convert between network/tpm-ready structs and our structs */
int BuildChosenIdHash(unsigned char *buffer, IdentityContentsData *id);

/******************** USER ONLY *************************************/
#ifndef __NEXUSKERNEL__

/* loosely corresponds to TCPA_SYM_CA_ATTESTATION */
typedef struct SymCaBlob{
  int blobsize;
  SymKeyData symkey;
  unsigned char blob[MAX_CRED_LEN];
}SymCaBlob;

/* loosely corresponds to TCPA_SYM_CA_ATTESTATION and TCPA_ASYM_CA_CONTENTS */
typedef struct IdentityRespData{
  SymKeyData symkey;
  PubKeyData idkey;
  X509 *cert;
  RSA *pubek;
}IdentityRespData;


/* connect and send request to CA with server_addr and destport */
int connectToPrivacyCA(const char *server_addr, short destport);
void sendIdentityRequest(int fd, unsigned char *buf, int buflen);


/* fill structures with known data */
int fillIdentityReqData(IdentityReqData *newid,
			char *idname, int idnamelen,
			char *idbinding, int idbindingsize,
			PubKeyData *idkey, PubKeyData *cakey, 
			char *ek_cert, char *conf_cert, char *platform_cert);
int fillIdentityProofData(IdentityProofData *newid,
			  char *idname, int idnamelen,
			  char *idbinding, int idbindingsize,
			  PubKeyData *idkey, 
			  char *ek_cert, char *conf_cert, char *platform_cert);
int fillIdentityRespData(IdentityRespData *newid,
			 PubKeyData *idkey,
			 X509 *cert, RSA *pubek);


/* convert between network/tpm-ready structs and our structs */
int BuildIdentityProof(unsigned char *buffer, IdentityProofData *proof);
int ExtractIdentityProof(IdentityProofData *proof, unsigned char *buffer);
int BuildIdentityReq(unsigned char *buffer, IdentityReqData *req);
int ExtractIdentityReq(IdentityReqData *req, unsigned char *buffer, RSA *priv);
int BuildIdentityContents(unsigned char *buffer, IdentityContentsData *data);
int BuildIdentityResp(unsigned char *buffer, IdentityRespData *resp);

/* fetch off the wire */
int RecvIdentityReq(int fd, unsigned char *buf);
int RecvAsymCaContents(int fd, unsigned char *buf);
int RecvSymCaContents(int fd, unsigned char *buf);
int RecvCertifyReq(int fd, unsigned char *buf);
int RecvAIKCert(int fd, unsigned char *buf);

/******************** KERNEL ONLY ***********************************/
#else 


/********************************************************************/
#endif

#endif
