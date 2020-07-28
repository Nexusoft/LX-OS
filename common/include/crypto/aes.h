#ifndef __AES_H__
#define __AES_H__

#define AES_MAX_KEYSIZE          (32)
#define AES_BLOCK_SIZE	         (16)
#define AES_DEFAULT_KEYSIZE      (32)
#define AES_DEFAULT_TWEAK_SIZE   (16)
#define AES_IV_SIZE              AES_DEFAULT_TWEAK_SIZE

/* normal aes cbc (aes-cbc.c) */ 
void nexus_cbc_encrypt(unsigned char *src, int srclen,
		 unsigned char *dest, int *destlen, 
		 unsigned char *key, int keylen,
		 unsigned char *tweak, int tweaklen);
void nexus_cbc_decrypt(unsigned char *src, int srclen,
		 unsigned char *dest, int *destlen, 
		 unsigned char *key, int keylen,
		 unsigned char *tweak, int tweaklen);

/* tweak block chaining (aes-tbc.c) */
int tbc_encrypt(unsigned char *src, int srclen,
		unsigned char *dest, int *destlen, 
		unsigned char *key, int keylen,
		unsigned char *tweak, int tweaklen,
		unsigned char *ktweak, int ktweaklen);
int tbc_decrypt(unsigned char *src, int srclen,
		unsigned char *dest, int *destlen, 
		unsigned char *key, int keylen,
		unsigned char *tweak, int tweaklen,
		unsigned char *ktweak, int ktweaklen);

/* pregenerate aes tables rather than waiting for first encrypt */
int nexus_aes_init(void);


#endif
