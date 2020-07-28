#ifndef __AES_PRIVATE_H__
#define __AES_PRIVATE_H__

/* aes low level block cipher stuff (aes.c) */
struct aes_ctx {
	int key_length;
	unsigned int E[60];
	unsigned int D[60];
};

int aes_set_key(void *ctx_arg, const unsigned char *in_key, unsigned int key_len);


/* single block aes encryption */
void aes_encrypt(void *ctx_arg, unsigned char *out, const unsigned char *in);
void aes_decrypt(void *ctx_arg, unsigned char *out, const unsigned char *in);


/* single block lrw encryption */
void aes_encrypt_tweak(struct aes_ctx *ctx_arg, unsigned char *out, const unsigned char *in, 
		       const unsigned char *tweak, const unsigned char *ktweak);
void aes_decrypt_tweak(struct aes_ctx *ctx_arg, 
		       unsigned char *out, const unsigned char *in, 
		       const unsigned char *tweak, const unsigned char *ktweak);



/* the eAXU2 function to apply to the tweak in lrw (gfmult.c) */
void gfmult(const unsigned char *C, const unsigned char *Y, unsigned char *Z);

#endif
