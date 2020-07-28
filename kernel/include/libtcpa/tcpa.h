/****************************************************************************/
/*                                                                          */
/*  TCPA.H  03 Apr 2003                                                     */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/
#ifndef TCPA_H
#define TCPA_H

#include <libtcpa/tpm.h>
#include <libtcpa/keys.h>
#include <libtcpa/oiaposap.h>
#include <libtcpa/pcrs.h>
#include <libtcpa/hmac.h>

//extern PubKeyData CAKeyData;
//extern int ca_set;

unsigned char *get_opass(void);
unsigned char *get_spass(void);

unsigned int TPM_Transmit(unsigned char *buff, char *msg);
unsigned int TPM_Reset(void);
unsigned int TPM_GetCapability_Version(int *major, int *minor, int *version,
                                   int *rev);
unsigned int TPM_GetCapability_Slots(unsigned int *slots);
unsigned int TPM_GetCapability_Pcrs(unsigned int *pcrs);
unsigned int TPM_GetCapability_Key_Handle(unsigned short *num, unsigned int keys[]);
unsigned int TPM_OIAP(unsigned int *handle, char *enonce);
unsigned int TPM_OSAP(osapsess *sess, unsigned char *key, unsigned short etype,
                  unsigned int evalue);
unsigned int TPM_Terminate_Handle(unsigned int handle);
uint32_t TPM_TakeOwnership(int oencdatasize, unsigned char *ownerencr,
			   int sencdatasize, unsigned char *srkencr);


/* keys.c */
int TPM_GetPubKey(unsigned int keyhandle, unsigned char *keyauth, 
		  unsigned char *keydata, unsigned int *keydatalen);
unsigned int TPM_ReadPubek(PubKeyData *k);
uint32_t TPM_CreateWrapKey(uint32_t keyhandle,
                           unsigned char *keyauth,
                           unsigned char *newauth,
                           unsigned char *migauth,
                           KeyData *keyparms, 
			   KeyData *key);
unsigned int TPM_LoadKey(unsigned int keyhandle, unsigned char *keyauth,
			 KeyData *keyparms, unsigned int *newhandle);
unsigned int TPM_LoadKeyBlob(uint32_t keyhandle, unsigned char *keyauth,
			 unsigned char *keyblob, unsigned int keybloblen, uint32_t *newhandle);
unsigned int TPM_EvictKey(unsigned int keyhandle);
     

unsigned int TPM_Sign(unsigned int keyhandle, unsigned char *keyauth,
                  unsigned char *data, int datalen,
                  unsigned char *sig, unsigned int *siglen);
unsigned int TPM_Seal(unsigned int keyhandle,
                  unsigned char *pcrinfo, unsigned int pcrinfosize,
                  unsigned char *keyauth,
                  unsigned char *dataauth,
                  unsigned char *data, unsigned int datalen,
                  unsigned char *blob, unsigned int *bloblen);
unsigned int TPM_Seal_CurrPCR(unsigned int keyhandle,
                          unsigned int pcrmap,
                          unsigned char *keyauth,
                          unsigned char *dataauth,
                          unsigned char *data, unsigned int datalen,
                          unsigned char *blob, unsigned int *bloblen);
unsigned int TPM_Unseal(unsigned int keyhandle,
                  unsigned char *keyauth,
                  unsigned char *dataauth,
                  unsigned char *blob, unsigned int bloblen, 
                  unsigned char *data, unsigned int *datalen);

int TPM_UnBind(unsigned int keyhandle,
	       unsigned char *keyauth,
	       unsigned char *blob, unsigned int bloblen,
	       unsigned char *out, unsigned int *outlen);


unsigned int TPM_PcrRead(unsigned int pcrindex, unsigned char *pcrvalue);
int TPM_Extend(unsigned int pcrindex, unsigned char *digest);
uint32_t TPM_Quote(uint32_t keyhandle, unsigned char *keyauth,
		   unsigned short pcrmap,
		   unsigned char *data,
		   unsigned char *sig, unsigned int *siglen,
		   unsigned char *pcrResult, unsigned int *pcrlen);
int TPM_MakeIdentity(unsigned char *passhash, 
		     unsigned char *srkpasshash, 
		     unsigned char *ownpasshash, 
		     char *identitylabel, int idlabelsize, 
		     PubKeyData *keyCA,
		     KeyData *keyparms,
		     unsigned char *idbind, int *idbindlen);
//int TPM_ActivateIdentity(SymKeyData *symkey, KeyData *idkey, 
//			 unsigned char *blob, int bloblen);
int TPM_ActivateIdentity(//SymKeyData *symkey, 
			 KeyData *idkey, 
			 unsigned char *blob, int bloblen,
			 unsigned char *clear, int *clearlen);


unsigned int TPM_DirRead(int i, unsigned char *databuf, int datalen);

#ifndef RWPSSTIMING
uint32_t TPM_DirWriteAuth(int index, unsigned char *value, unsigned char *ohash);
#else
uint32_t TPM_DirWriteAuth(int index, unsigned char *value, unsigned char *ohash, Timing *t);
#endif

uint32_t TPM_CertifyKey(unsigned int keyhandle, unsigned char *keyauth,
			unsigned int certhandle, unsigned char *certauth,
			unsigned char *antiReplay,
			unsigned char *sig, unsigned int *siglen,
			unsigned char *ckresult, unsigned int *cklen);

int createaik(char *identitylabel, int idlabelsize, PubKeyData *keyCA, 
	      KeyData *keyID, unsigned char *idbind, int *idbindlen);
int signfile(unsigned int handle, char *password, char *databuff, int datalen);
int createKey(unsigned int parenthandle, char *parentpw, char *keypw, KeyData *keybuf, unsigned int pcrmap, short signing);
int loadkey(unsigned int parenthandle, char *parentpw, char *keyname);
int evictkey(unsigned int handle);
int evictall(void);
int sealbuffer(unsigned int keyhandle, char *keypw, char *datapw, char *databuff, unsigned int datalen, char *out);
int unsealbuffer(unsigned int keyhandle, char *keypw, char *datapw, unsigned char *blob, unsigned int bloblen, unsigned char *out);
/* XXX RAND_bytes should probably not reside in keys.c */
int RAND_bytes(unsigned char *array, int size);

uint32_t TPM_OSAP_Emu(osapsess *sess, unsigned char *key, uint16_t etype,
		      uint32_t evalue);
uint32_t TPM_Transmit_Emu(unsigned char *blob, char *msg);

#endif
