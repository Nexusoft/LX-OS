/** NexusOS: implementation of a secure key storage facility 
             these functions are called from LockBox.svc */

#include <openssl/aes.h>

int nxkey_shutdown(void);

// save/restore implementation

int nxkey_save_tpm(const char *filepath, const char *data, int dlen);
int nxkey_save_app(const char *filepath, const char *data, int dlen);
char * nxkey_restore_tpm(const char *filepath);
char * nxkey_restore_app(const char *filepath);

// key management

int nxkey_create(void);
int nxkey_insert(int index, char* key, int klen);
int nxkey_delete(int key_id);

// cryptographic operations

unsigned char* nxkey_encrypt(int key_id, const unsigned char *data, 
			     unsigned char ivec[AES_BLOCK_SIZE]);
unsigned char * nxkey_decrypt(int key_id, const unsigned char *ciphertext, 
			      unsigned char ivec[AES_BLOCK_SIZE]);

int nxkey_sign(const char *data, int dlen, char *digest);
int nxkey_verify(int index, const char *digest);

// deprecated
unsigned char* nxkey_hmac_sign(int key_id, const char* data, int dlen);
int nxkey_hmac_verify(int key_id, const unsigned char* data, int dlen, const unsigned char* hmac);


