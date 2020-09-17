#ifndef _AES_H_
#define _AES_H_
/* ashieh: Direct access to AES, rather than via crypto API */

#include <linux/types.h>

const extern int aes_ctxsize;

int aes_set_key(void *ctx_arg, const u8 *in_key, unsigned int key_len, u32 *flags);
//void aes_init(void); /* now nexus_aes_init in common/crypto/aes.h */
void aes_encrypt(void *ctx_arg, u8 *out, const u8 *in);

void aes_decrypt(void *ctx_arg, u8 *out, const u8 *in);
#endif
