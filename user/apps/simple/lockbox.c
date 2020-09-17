/** NexusOS: a secure key storage facility */

/* TODO: */

// * something about 512byte block sizes for AES (and cbc?)
// > DONE. Do CTR chaining for 512/AES_KEYBITS chunks.

// * sign/verify using RSA
// > WILL DO IN TPM KEYSTORE.

// * ensure that key is > 16 chars if it's used for AES
// > DONE. Not necessary to do anything, up to user to ensure this.

// * don't use a file to store keys, make them stored internally via array
// > DONE. Using an in-memory string array.

// * must pad the input (with 0s perse) to make it divisible by AES's block size which is 128 bits
// > DONE. Not necessary to do anything, up to user to ensure this.

// * Fix the inconsistencies with '\0' and "" and stuff.
// > DONE. Everything has been made into "". Using null pointers was contemplated, but deemed not worth the time to change.

// * Enforce a maximum size on a key (smaller than max_int) so malicious user cannot deplete our ram?
// > DONE. Check is done on insert to ensure we don't go over max Seal size (MAX_SEAL_SIZE bytes). 

// * Iteratively seal (and any other functions) that have a input datalen limit
// > DONE. Only cap is 255byte keys and max 255 key slots

// * Keep keys encrypted even in memory?
// > 

#include <fcntl.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <tpmfunc.h>
#include <tpmkeys.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <nexus/test.h>
#include <nexus/lockbox.h>
#include <nexus/LockBox.interface.h>

#define KEY_FILE "keys.txt"
#define TEMP_KEY_FILE "tempkeys.txt"
#define AES_KEYBITS AES_BLOCK_SIZE*8
#define SEALED_BLOB_SIZE 312
#define MAX_SEAL_SIZE 149
#define SAFE_UNSEAL_SIZE 256
#define ENCDEC_BLOCK_SIZE 512
#define INITIAL_NUM_SLOTS 10
#define DEBUG 0
#define USAGE "Keystore: Store and delete keys. First arg: p for priv, u for unpriv. Later args:\n\t-a [key]: add key to keystore\n\t-r [key_id]: remove key from keystore\n\t-e [key_id] [data]: encrypt data via AES\n\t-d [key_id] [ciphertext]: decrypt ciphertext via AES\n\t-s [key_id] [data]: get hmac signature of data\n\t-v [key_id] [data] [hmac]: verify hmac signature\n\t-t: run a diagnostic test on the keystore\n\t-h: this helpful information\n"

/* This data structure will store the keys that users supply */
char** keystore;
/* This counts how many keys we have in the array, so we know to realloc when we fill all slots */
unsigned char keys_stored;
/* This records the total number of key slots in keystore, so we know when to realloc */
unsigned char keystore_size = 0;
/* This holds function return values */
uint32_t ret = 0;
/* This is the SRK keyhandle, for use in TPM functions */
uint32_t srkkeyhandle = 0x40000000;
/* The file to write keystore blob data to */
char * primary_blobfilename = "masterlockbox.dat";

static unsigned char ownauth[SHA_DIGEST_LENGTH];
static unsigned char srkauth[SHA_DIGEST_LENGTH];

/* Set to 1 to stop processing requests */
static int stop;

/*
 * Create a new, empty keystore
 * Inputs:
 * num_slots: Initial number of slots. Max 255
 */
void create_new_keystore(unsigned char num_slots) {

        // Make initial key slots, can remalloc later to grow
        keystore = malloc(sizeof(char*) * num_slots);
        if (keystore == NULL) {
                exit(1);
        }

        keystore_size = num_slots;

        keys_stored = 0;

        // Initialize all keys to be empty strings. Empty strings define unused slots
        int i;
        for(i = 0; i < keystore_size; i++) {
                keystore[i] = "";
        }
}
/* 
 * keystore_grow:
 * Increase keystore size to provide room for more keys.
 * Inputs:
 * growby: Number of extra slots to add. If 0, double the size. If negative, do nothing.
 * Return:
 * New size of keystore. If allocation failed, returned value will be the same as the old size.
 */
unsigned char keystore_grow(unsigned char growby) {
	if (growby < 0) {
		return keystore_size;
	}
	if (growby==0) {
		growby = keystore_size;
	}

        // check to ensure size+1 doesn't go past a unsigned char
        // so that size of metadata can fit in a uchar
        // because size of metadata is equal to #keys+1
        int s1 = keystore_size;
        int s2 = growby;
        if (s1 + s2 + 1 > 255) {
                printf("lockbox cannot grow any larger");
                return keystore_size;
        }

        // allocate resources for the new lockbox
	char** new_keystore = malloc(sizeof(char*) * (keystore_size + growby));

	/* copy in the existing keys */
	memcpy(new_keystore, keystore, keystore_size*sizeof(char*));
       
        // initialize all new elements to empty strings 
        int i;
        for (i = keystore_size; i < (keystore_size + growby); i++) {
                new_keystore[i] = "";
        }

	free(keystore);
	keystore = new_keystore;
	keystore_size += growby;

	return keystore_size;
}

/*
 * nxkey_insert:
 * Insert a key into the keystore
 * Inputs:
 * index: index to store the key at. if -1: select one ourselves
 *        values are NOT overwritten. will fail if a slot is already in use (free it with .._delete)
 * key: The keystring to store. Caller can do as they wish with this after the call -- keystore uses a local copy of the key.
 * klen -1 to calculate keylength using strlen+1 or the length of key
 * Return:
 * key_id to be used for subsequent references to the key, -1 if failed to insert
 */
int nxkey_insert(int index, char* key, int klen)
{
	char *local_key;

        if (DEBUG) printf("[%d] insert %dB\n", index, klen);
        // We need to enforce that key fits in a unsigned char
	if (klen == -1)
		klen = strlen(key) + 1;
        if (klen > 255)
                return -1;

        int i;
	if (keys_stored >= keystore_size) {
		printf("Lockbox size before realloc: %d\n",keystore_size);
		keystore_grow(INITIAL_NUM_SLOTS);
		printf("Lockbox size after  realloc: %d\n",keystore_size);
		printf("keys in lockbox:\n");
		for (i=0; i<keystore_size; i++) {
			printf("key[%d] = %s\n",i,keystore[i]);
		}
	}

	// find slot
	// fixed index: see if it is already occupied
	if (index != -1) {
		if (strcmp(keystore[index], ""))
			ReturnError(-1, "[insert] key in use");
	}

	// search for empty index
	else {
		for (i = 0; i < keystore_size; i++) {
			if (!strcmp(keystore[i],"")) {
				index = i;
				break;
			}
		}

		if (index == -1)
			ReturnError(-1, "[insert] all keys in use");
	}

	// create local copy
	local_key = malloc(klen + 1);
	memcpy(local_key, key, klen);
	local_key[klen] = 0;

	// place in slot
	keystore[index] = local_key;
	keys_stored++;
	return index;
}

/*
 * nxkey_delete:
 * Delete a key from the keystore.
 * Inputs:
 * key_id: index to the key to delete, provided by nxkey_insert
 * Return:
 * key_id if deletion succeeded, -1 if failed to delete
 */
int nxkey_delete(int key_id)
{	
	/* If there exist keys in keystore, key_id is not beyond array end, and the array actually contains a key at the index */
	if(keys_stored > 0 && key_id < keystore_size && strcmp(keystore[key_id],"")!=0) {
		free(keystore[key_id]);
		keystore[key_id]="";
		keys_stored--;
		return key_id;
	} else {
		return -1;
	}
}

/*
 * get_key:
 * Function for extracting a key based on key_id
 * from the keystore's internal key management data structure
 * Inputs:
 * key_id: The id of the key - generally the index of the key within the data structure
 * Returns:
 * key: The key
 */
char* get_key(int key_id) 
{
	if (key_id < keystore_size) {
		return keystore[key_id];
	} else {
		return "";
	}
}

/* debug_print_lockbox
 * Print out each of the keys on a separate line to stdout
 */
void debug_print_lockbox(void)
{
	int i;
	printf("Lockbox contents:\n");
	for (i = 0; i < keystore_size; i++) {
		printf("%d: %s\n",i,keystore[i]);
	}
}

/*
 * nxkey_encrypt:
 * Encrypt a ENCDEC_BLOCK_SIZE byte datablock via 128-bit AES
 * Inputs:
 * key_id: ID of an key in the keystore. Key must be at least 128bits (16B) long, and any further bits are not used.
 * data: block of data to encrypt. Up to user to pad the input properly to be ENCDEC_BLOCK_SIZE byte (probably 512)
 * ivec: The initial ivec to encrypt the first AES block of data within the datablock. 
 *      Use this when decrypting the block.
 * 	Note: ivec gets incremented every 16B of data -- as per CTR encryption with a ++ counter.
 *            Will get incremented 32 times through the course of encryption.
 * Return:
 * ENCDEC_BLOCK_SIZE byte encrypted data, null for invalid key
 */
unsigned char* nxkey_encrypt(int key_id, const unsigned char *data, unsigned char ivec[AES_BLOCK_SIZE])
{
	int i;
	char* key = get_key(key_id);

        if (DEBUG) printf("nxkey_encrypt: Encrypting data with key %d\n", key_id);
        
	if (!strcmp(key,"")) { // if invalid key
                printf("encrypt: invalid key\n");
                return NULL;
        }

	AES_KEY * enkey = malloc(sizeof(AES_KEY));
	int result = AES_set_encrypt_key((unsigned char*)key, AES_KEYBITS, enkey);
	if (DEBUG) printf("nxkey_encrypt: AES key setting returned %d\n",result);
	
	unsigned char * ciphertext = malloc(ENCDEC_BLOCK_SIZE);
	unsigned int num = 0;
	unsigned char ecount_buf[AES_BLOCK_SIZE];
	memset(ecount_buf, 0, AES_BLOCK_SIZE);

        if (DEBUG) {
                printf("The ivec before encrypt:\n");
                for (i=0; i<AES_BLOCK_SIZE; i++) {
                        printf("%d",ivec[i]);
                }
                printf("\n");
        }

	AES_ctr128_encrypt(
		data,
		ciphertext,
		(unsigned long)ENCDEC_BLOCK_SIZE,
		enkey,
		ivec,
		ecount_buf,
		&num
	);

        if (DEBUG) {
                printf("nxkey_encrypt: Encrypted data: \n");
                for (i = 0; i < ENCDEC_BLOCK_SIZE; i++) {
                        printf("%02X",ciphertext[i]);
                }
                printf("\n");
                
                printf("The ivec after encrypt:\n");
                for (i=0; i<AES_BLOCK_SIZE; i++) {
                        printf("%d",ivec[i]);
                }
                printf("\n");
        }

	free(enkey);

	return ciphertext;
}

/*
 * nxkey_decrypt:
 * Decrypt a fixed size datablock (ENCDEC_BLOCK_SIZE bytes) via AES
 * Inputs:
 * key_id: ID of AES key in the keystore. Key must be at least 128bits long, and any further bits are not used.
 * ciphertext: ENCDEC_BLOCK_SIZE byte block of data that has been encrypted with the key
 * ivec: The ivec to use for decryption (this is the same ivec that was used for encrypting this block)
 * Return:
 * ENCDEC_BLOCK_SIZE byte decrypted ciphertext (plaintext), null for invalid key
 */
unsigned char * nxkey_decrypt(int key_id, const unsigned char *ciphertext, unsigned char ivec[AES_BLOCK_SIZE])
{
	int i;
	char* key = get_key(key_id);
        if (!strcmp(key,"")) { // if invalid key
                return NULL;
        }
	
	if (DEBUG) {
                printf("nxkey_decrypt: Using key: %s\n",key);
                printf("nxkey_decrypt: Decrypting data: \n");
                for(i = 0; i < ENCDEC_BLOCK_SIZE; i++) {
                        printf("%02X",ciphertext[i]);
                }
                printf("\n");
        }
	AES_KEY * enkey = malloc(sizeof(AES_KEY));
	int result = AES_set_encrypt_key((unsigned char*)key, AES_KEYBITS, enkey);
	if (DEBUG) printf("nxkey_decrypt: AES key setting returned %d\n",result);

	unsigned char* plaintext = malloc(ENCDEC_BLOCK_SIZE);
	
	unsigned int num = 0;
	unsigned char ecount_buf[AES_BLOCK_SIZE];
	memset(ecount_buf, 0, AES_BLOCK_SIZE);

	AES_ctr128_encrypt(
		ciphertext,
		plaintext,
		(unsigned long)ENCDEC_BLOCK_SIZE,
		enkey,
		ivec,
		ecount_buf,
		&num
	);

        if (DEBUG) {
                printf("nxkey_decrypt: Decrypted data: %s\n",plaintext);
                printf("The ivec after decrypt:\n");
                for (i=0; i<AES_BLOCK_SIZE; i++) {
                        printf("%d",ivec[i]);
                }
                printf("\n");
        }

	free(enkey);
	
	return plaintext;
}

/* create SHA */
int nxkey_sign(const char *data, int dlen, char *digest)
{
	SHA1(data, dlen, (unsigned char *) digest);
	return 0;
}

int nxkey_verify(int index, const char *digest)
{
	return memcmp(keystore[index], digest, 20);
}

/* 
 * nxkey_hmac_sign:
 * Sign the hmac of a data string
 * Inputs:
 * key_id: Shared secret key
 * data: Data to sign
 * dlen: Length of data
 * Returns:
 * Signature (hmac encrypted with private key), null for invalid key
 */
unsigned char* nxkey_hmac_sign(int key_id, const char* data, int dlen)
{
	char * key = get_key(key_id);
        if (!strcmp(key,"")) { // if invalid key
                return NULL;
        }

	// based on an example I found - don't know why 1024 is good to use here
	unsigned char hmac[1024];
	
	unsigned int hmac_len;

	if (DEBUG) printf("nxkey_hmac_sign: Running hmac on data with key: %s\n",key);
	HMAC(EVP_sha1(), key, strlen(key), (unsigned char*)data, dlen, hmac, &hmac_len); // XXX do not usestrlen, #define a keylength
	if (DEBUG) printf("nxkey_hmac_sign: Hmac length: %d\n",hmac_len);
	if (DEBUG) {
                printf("nxkey_hmac_sign: Hmac: ");
                int l;
                for(l = 0; l < hmac_len; l++) {
                        printf("%02X",hmac[l]);
                }
                printf("\n");
        }

	unsigned char* hmac_return = malloc(sizeof(char)*hmac_len + 1);
	memcpy(hmac_return, hmac, hmac_len);
	return hmac_return;
}

/*
 * nxkey_hmac_verify
 * Inputs:
 * key: Shared secret key
 * data: Signed data
 * dlen: Length of signature
 * hmac: The data's hmac digest, used for verification
 * Returns:
 * 1 for correct signature, 0 for incorrect signature
 */
int nxkey_hmac_verify(int key_id, const unsigned char* data, int dlen, const unsigned char* hmac)
{
	if (DEBUG) printf("nxkey_hmac_verify: got data %s\n",data);
	if (DEBUG) printf("nxkey_hmac_verify: got datalen %d\n",dlen);

	if (DEBUG) printf("nxkey_hmac_verify: Provided hmac: %s\n",hmac);

	if (DEBUG) printf("nxkey_hmac_verify: Generating hmac...\n");
	unsigned char* genhmac = nxkey_hmac_sign(key_id, data, dlen);

	int hmac_len = SHA_DIGEST_LENGTH; // XXX hardcode doesn't matter, temporarily just used for printing it out to screen
	if (DEBUG)
        {
                char hexhmac[41];
                printf("nxkey_hmac_verify: Generated hmac: ");
                int l;
                for(l = 0; l < hmac_len; l++) {
                        sprintf(&hexhmac[l*2],"%02X",genhmac[l]);
                }
                printf("%s",hexhmac);
                printf("\n");
        }

	// XXX: should probably be operating on binary data and not hex strings here
	int comparison = 0;
	comparison = !memcmp(genhmac,hmac,SHA_DIGEST_LENGTH);	
	printf("nxkey_hmac_verify: HMAC comparison: %d\n", comparison);

	return comparison;
}

/*
 * Take the current lockbox
 * and turn it into a bitstring
 * Inputs:
 *      datalen -- Gets assigned the length of the serialized lockbox data
 * Return:
 *      Pointer to the serialized lockbox data
 */
unsigned char* serialize_lockbox(unsigned int * datalen) {
        int i, j;
	/* Calculate the total number of bytes that comprise all keys, NUL bytes included*/
	int total_size_keys = 0;
	for (i = 0; i < keystore_size; i++) {
		total_size_keys += strlen(keystore[i])+1;
	}

	/* Metadata contains keystore size (# of slots) as well as each key's strlen, each value is an byte */
	unsigned char total_size_metadata = (keystore_size+1)*sizeof(char);

        if (DEBUG) {
                printf("metadata size: %d\n", total_size_metadata);
                printf("all keys size: %d\n", total_size_keys);
        }

	*datalen = SHA_DIGEST_LENGTH + total_size_keys + total_size_metadata;
	unsigned char * data = malloc(sizeof(char) * (*datalen));

	// Use this index to build the data byte by byte
	// We reserve SHA_DIGEST_LENGTH bytes at start of data for the hash
	int data_index = SHA_DIGEST_LENGTH; 

	/* First 4 bytes are the keystore size */
        data[data_index++] = keystore_size;

	/* All subsequent bytes follow the pattern: 1 bytes of keysize, keysize bytes of key */
	char * temp_key;
	unsigned char temp_key_size = 0;
	for (i = 0; i < keystore_size; i++) {
		temp_key = keystore[i];
		temp_key_size = strlen(temp_key)+1; // include NUL in keysize
		/* 1 bytes of keysize: */
		data[data_index++] = temp_key_size;
		/* keysize bytes of key: */
		for (j = 0; j < temp_key_size; j++) {
			data[data_index++] = temp_key[j];
		}
	}

	// Generate a hash of the data, for integrity purposes
	unsigned char datahash[SHA_DIGEST_LENGTH];
	TSS_sha1(data + SHA_DIGEST_LENGTH, (*datalen) - SHA_DIGEST_LENGTH, datahash);
	// Put it in the SHA_DIGEST_LENGTH reserved bytes at the beginning of the data
	memcpy(data,datahash,SHA_DIGEST_LENGTH);
        return data;
}

/*
 * Read through the entire serialized lockbox data structure
 * To determine how many bytes it contains.
 * The purpose of this is for the unpriveleged restore
 * which uses nxkey_decrypt, which returns an entire ENCDEC_BLOCK_SIZE chunk of data
 * so we don't know how much padding is at the end of the block
 * Inputs:
 * data: the bitstring that contains the serialized lockbox data with potential padding
 * datalen: The total length of the data bitstring
 * Returns:
 * The length of the lockbox contained within 'data' without the padding.
 *      Always <= datalen input
 */
int determine_lockbox_length(unsigned char * data, int datalen) {
        int i = SHA_DIGEST_LENGTH; // we skip over the digest
        int num_keys = data[i++];
        int key_i = 0;
        int key_i_len;
        while (i < datalen && key_i < num_keys) {
                key_i_len = data[i++];
                key_i++;
                i += key_i_len;
        }
        printf("Lockbox length determined to be: %d\n",i);
        if (i <= datalen)
                return i;
        else
                return -1;
}
/* 
 * Take in serialized lockbox data
 * and turn it into a lockbox
 * Inputs:
 *      data -- Serialized lockbox data
 *      datalen -- Length in bytes of serialized lockbox data
 * Returns:
 *      0 for success
 *      1 if the datalen is too small
 *      2 if integrity check fails
 */
int deserialize_lockbox(unsigned char * data, unsigned int datalen) {
        int i, j;

        // ensure that a potentially valid datalen is inputted
        if (datalen < SHA_DIGEST_LENGTH) {
                return 1;
        }
	// Extract the hash
	unsigned char storedhash[SHA_DIGEST_LENGTH];
	memcpy(storedhash,data,SHA_DIGEST_LENGTH);

	// Hash the keystore data
	unsigned char datahash[SHA_DIGEST_LENGTH];
	TSS_sha1(data + SHA_DIGEST_LENGTH, datalen - SHA_DIGEST_LENGTH, datahash);
	
	// Compare the hashes, exit if unequal
	if (memcmp(storedhash,datahash,SHA_DIGEST_LENGTH) != 0) {
		printf("Integrity check failed. Hashes are not identical.\n");
		printf("Stored hash:\n");
		for(i = 0; i < SHA_DIGEST_LENGTH; i++) {
			printf("%02X ",storedhash[i]);
		}
		printf("\n");
		printf("Data hash:\n");
		for(i = 0; i < SHA_DIGEST_LENGTH; i++) {
			printf("%02X ",datahash[i]);
		}
		printf("\n");
		return 2;
	}

	// determine the number of key slots in the keystore
	int data_index = SHA_DIGEST_LENGTH;
        // unsigned int tempval;
	unsigned char temp_keystore_size;
	temp_keystore_size = data[data_index++];

	// allocate the new keystore
	char** temp_keystore = malloc(temp_keystore_size*sizeof(char*));
        if (temp_keystore == NULL) {
                printf("Lockbox unable to allocate memory for key storage. Shutting down...\n");
                exit(1);
        }
	unsigned char temp_keys_stored = 0;

	/* All subsequent bytes follow the pattern: 1 bytes of keysize, keysize bytes of key */
	char * temp_key;
	unsigned char temp_key_size;
	// for every keyslot
	for (i = 0; i < temp_keystore_size; i++) {
		// extract the keysize from the data
		temp_key_size = data[data_index++];

		// create a new key
		temp_key = malloc(temp_key_size*sizeof(char));

		// read the key from the data into our new key
		// XXX memcpy?
		for(j = 0; j < temp_key_size; j++) {
			temp_key[j] = data[data_index++];
		}

		// put new key into the keystore
		temp_keystore[i] = temp_key;

		if(DEBUG) printf("placed temp key [%s] into slot [%d]\n",temp_key,i);

		// if the key was not blank, update the keystore
		if (strcmp(temp_key,"")!=0) {
			temp_keys_stored++;
		}
	}

	// update the real variables
	keystore_size = temp_keystore_size;
	keys_stored = temp_keys_stored;
	keystore = temp_keystore;

        return 0;
}

/*
 * UNPRIVILEGED LOCKBOX SAVE STATE:
 * Serialize the keystore, ask privileged lockbox to encrypt, and then store blob to disk.
 * Inputs:
 *      bfilename -- name of the file to write serialized data to
 *      bloblen -- Gets assigned the length of the generated blob.
 *      key_index -- The key to use in the privileged lockbox for encrypting the blob
 * Return:
 *      0 on success. 
 *      1 if fails to serialize lockbox
 *      2 if an encryption fails
 *      3 if blobfile cannot be opened for write
 */
int unpriv_serialize_to_disk(const char * bfilename, unsigned int * bloblen, unsigned char key_index)
{
	printf("Unprivileged serialize starting\n");
	int i;
        int j;

        unsigned char * data = NULL;
        unsigned int datalen;

        data = serialize_lockbox(&datalen);
        if (data == NULL) {
                printf("Serialize failed. Null data pointer returned.\n");
                return 1;
        } else {
                printf("Serialize succeeded. datalen: %d\n",datalen);
        }

	/* Create the blob to hold encrypted data */

        unsigned int tempdlen; // data encrypted per loop iteration

        unsigned int chunksize = ENCDEC_BLOCK_SIZE; // block size for nxkey_encrypt
	unsigned char * blob = malloc(sizeof(char) * ((datalen/chunksize)+1)*chunksize); // holds the entire encrypted blob

        unsigned int remainingdata = datalen; // loop condition
        unsigned int dataoffset = 0; // offset to read from data
        unsigned int bloboffset = 0; // offset to write into blob

        // initialize the ivec for encryption. each chunk will get an incremented ivec
        unsigned char ivec[AES_BLOCK_SIZE];
        memset(ivec,0,AES_BLOCK_SIZE);

        unsigned char pblock[chunksize];
        unsigned char cblock[chunksize];

        while (remainingdata > 0) {
                // determine amount to encrypt this iteration
                if (remainingdata >= chunksize) {
                        tempdlen = chunksize;
                } else {
                        tempdlen = remainingdata;
                }

                // set pblock to all 0s, used as padding if tempdlen < chunksize
                memset(pblock, 0, chunksize);
                // copy in the data to pblock
                memcpy(pblock, &data[dataoffset], tempdlen);
                // clear the ciphertext array, just for good measure
                memset(cblock, 0, chunksize);
                // Encrypt over IPC
                ret = LockBox_Encrypt(key_index,
                                        (struct VarLen) {.data = pblock, .len = 512},
                                        (struct VarLen) {.data = cblock, .len = 512},
                                        (struct VarLen) {.data = ivec, .len = AES_BLOCK_SIZE},
                                        chunksize, 0);

                if (cblock == NULL || ret != 0) {
                        printf("Error encrypting data chunk.\n");
                        free(blob);
                        free(data);
                        *bloblen = 0; // to indicate an error
                        return 2;
                }

                if (DEBUG) {
                        printf("The ivec after encrypt:\n");
                        for (i=0; i<AES_BLOCK_SIZE; i++) {
                                printf("%d",ivec[i]);
                        }
                        printf("\n");
                }

                // fill in the blob with the current encryption
                memcpy(&blob[bloboffset], cblock, chunksize);
                // update the offsets
                bloboffset += chunksize;
                dataoffset += tempdlen;
                remainingdata -= tempdlen;
        }
        *bloblen = bloboffset;

        // check if the saved blob already exists
        if (DEBUG) printf("opening %s to check if exists\n",bfilename);
        FILE * blobfile = fopen(bfilename,"r");
        if (DEBUG) printf("%s opened\n",bfilename);
        if (blobfile != NULL) {
                fclose(blobfile);
                // delete it if it does
                if (DEBUG) printf("deleting %s\n",bfilename);
                unlink(bfilename);
        }

        // open the blob file and write in the entire blob
        if (DEBUG) printf("opening %s to write. bloblen: %d\n",bfilename,*bloblen);
        blobfile = fopen(bfilename,"w");
        if (blobfile == NULL) {
                if (DEBUG) printf("error opening %s for write.\n",bfilename);
                free(blob);
                free(data);
                return 3;
        }
        fwrite(blob, 1, *bloblen, blobfile);
        fclose(blobfile);
        if (DEBUG) printf("wrote lockbox to %s\n",bfilename);

	// Write data hash to DIR0
	ret = TPM_DirWriteAuth(0, data, ownauth);
        if (ret == 0) {
		printf("Wrote datahash to DIR0.\n");
	} else {
		printf("Failed to write datahash to DIR0.\n");
	}

	free(data);
	free(blob);
	return 0;
}

/*
 * UNPRIVILEGED LOCKBOX RESTORE STATE:
 * Read stored lockbox from disk, ask privileged lockbox to decrypt, then deserialize to restore state
 * Inputs:
 *      bfilename -- file on disk containing encrypted serialized data
 *      key_index -- key in the privilege lockbox to use for decryption
 * Return:
 *      0 on success
 *      1 if unable to open blob file for read
 *      2 if length of blob file is too small
 *      3 if unable to allocate memory to store the data of blob file
 *      4 if read incorrect number of bytes from blob file
 *      5 if decryption fails
 *      6 if blob file was corrupt (not a multiple of ENCDEC_BLOCK_SIZE)
 *      7 if deserialize (state restore) fails
 */
int unpriv_deserialize_from_disk(const char * bfilename, unsigned char key_index)
{
        printf("Unprivileged deserialize starting.\n");
	int i;
	int j;

	FILE * blobfile = fopen(bfilename,"r");	
	if (blobfile == NULL) {
		return 1;
	}

	fseek (blobfile, 0, SEEK_END);
	unsigned int bloblen = ftell(blobfile);
	rewind(blobfile);
	if (bloblen == 0) {
		return 2;
	}

	unsigned char * blob = malloc(bloblen);
	if (blob == NULL) {
		return 3;
	}

	size_t elements_read = fread(blob, 1, bloblen, blobfile);
	if (elements_read != bloblen) {
		return 4;
	}
	fclose(blobfile);	
	printf("unpriv_deserialize_from_disk: Read blob file, bloblen: %d\n",bloblen);
	
        /* Retrieve the serialized lockbox data */
        unsigned int chunksize = ENCDEC_BLOCK_SIZE;

        unsigned char * data = malloc(sizeof(char) * (bloblen/chunksize)*chunksize);
        
        unsigned int remainingblob = bloblen; // loop condition
        unsigned int dataoffset = 0; // offset to read from data
        unsigned int bloboffset = 0; // offset to write into blob

        unsigned char ivec[AES_BLOCK_SIZE];
        memset(ivec,0,AES_BLOCK_SIZE);

        unsigned char pblock[chunksize];
        unsigned char cblock[chunksize];

        while (remainingblob >= chunksize) {
                if(DEBUG) printf("Unsealing %d bytes at blob[%d]\n",chunksize, bloboffset);
                
                // copy in the encrypted data to cblock
                memcpy(cblock, &blob[bloboffset], chunksize);
                // clear the plaintext array, just for good measure
                memset(pblock, 0, chunksize);
                // Decrypt over IPC
                ret = LockBox_Decrypt(key_index,
                                        (struct VarLen) {.data = cblock, .len = 512},
                                        (struct VarLen) {.data = pblock, .len = 512},
                                        (struct VarLen) {.data = ivec, .len = AES_BLOCK_SIZE},
                                        chunksize, 0);

                if (pblock == NULL || ret != 0) {
                        printf("Error decrypting data chunk.\n");
                        free(data);
                        free(blob);
                        return 5;
                }

                memcpy(&data[dataoffset], pblock, chunksize);
                dataoffset += chunksize;
                bloboffset += chunksize;
                remainingblob -= chunksize;
        }
        if (remainingblob != 0) {
                free(data);
                free(blob);
                printf("Decrypting failed due to corrupt blob.\n");
                return 6; // blob data length should be divisible by ENCDEC_BLOCK_SIZE
        }

        int datalen = determine_lockbox_length(data, bloblen);
        ret = deserialize_lockbox(data, datalen);
        if (ret != 0) {
                printf("Deserialize failed.\n");
                free(data);
                free(blob);	
                return 7;
        }
	free(data);
	free(blob);	
	return 0;	
}

/*
 * PRIVILEGED LOCKBOX SAVE STATE:
 * Serialize the keystore and save to disk as blob encrypted with TPM's SRK.
 * Metadata is calculated and provided in blob to assist with deserialization.
 * Inputs:
 *      bfilename -- File name of blob to save data to
 *      bloblen -- Gets assigned the length of the generated blob.
 * Return:
 *      0 on success
 *      1 if serialization fails
 *      2 if TPM_Seal fails
 *      3 if unable to open blob file for write
 */
int nxkey_serialize_to_disk(const char * bfilename, unsigned int * bloblen)
{
	printf("Serialize starting\n");
	int i;
        int j;
	RSA * rsa = NULL;

	unsigned char * newpass = "NEW PASS";
	unsigned char newauth[SHA_DIGEST_LENGTH];
	TSS_sha1(newpass, strlen(newpass), newauth);
        
        unsigned char * data = NULL;
        unsigned int datalen;

        data = serialize_lockbox(&datalen);
        if (data == NULL) {
                printf("Serialize failed. Null data pointer returned.\n");
                return 1;
        } else {
                printf("Serialize succeeded. datalen: %d\n",datalen);
        }

	/* We must add randomness to the randomness, otherwise various things will fail (e.g. TSS_Bind) */
	unsigned char * buf = malloc(256);
	if (DEBUG) printf("made the 256 buf. adding randomness\n");

	RAND_seed(buf, 256);
	if (DEBUG) printf("randomness added\n");

	/* Take ownership of TPM. This also returns the SRK as a keydata struct*/
	ret = TPM_TakeOwnership(ownauth, srkauth, NULL);
	if (ret != 0) {
		printf("TPM_TakeOwnership failed with error %p: %s\n",(void *)ret, TPM_GetErrMsg(ret));
	} else {
		printf("TPM_TakeOwnership succeeded.\n");
	}

	/* Create the blob to hold encrypted data */

        unsigned char tempblob[SEALED_BLOB_SIZE]; // blob data per loop iteration
        unsigned int tempblen; // blob size per loop iteration
        unsigned int tempdlen; // data encrypted per loop iteration

        unsigned char chunksize = MAX_SEAL_SIZE; // experimentally determined to be maximum bytes TPM_Seal can encrypt
	unsigned char * blob = malloc(sizeof(char) * ((datalen/chunksize)+1)*SEALED_BLOB_SIZE); // holds the entire encrypted blob

        unsigned int remainingdata = datalen; // loop condition
        unsigned int dataoffset = 0; // offset to read from data
        unsigned int bloboffset = 0; // offset to write into blob

        while (remainingdata > 0) {
                // determine amount to encrypt this iteration
                if (remainingdata >= chunksize) {
                        tempdlen = chunksize;
                } else {
                        tempdlen = remainingdata;
                }

                ret = TPM_SealCurrPCR(srkkeyhandle, 0x0000007F, srkauth, newauth, &data[dataoffset], tempdlen, tempblob, &tempblen);
                if (ret != 0) {
                        printf("TPM_Seal failed with error %u: %s\n",ret, TPM_GetErrMsg(ret));
                        free(blob);
                        free(data);
                        free(buf);
                        *bloblen = 0; // to further indicate failure
                        return 2;
                }

                // fill in the blob with the current encryption
                memcpy(&blob[bloboffset], tempblob, tempblen);
                // update the offsets
                bloboffset += tempblen;
                dataoffset += tempdlen;
                remainingdata -= tempdlen;
                
        }
        *bloblen = bloboffset;

        // check if the saved blob already exists
        if (DEBUG) printf("opening %s to check if exists\n",bfilename);
        FILE * blobfile = fopen(bfilename,"r");
        if (DEBUG) printf("%s opened\n",bfilename);
        if (blobfile != NULL) {
                fclose(blobfile);
                // delete it if it does
                if (DEBUG) printf("deleting %s\n",bfilename);
                unlink(bfilename);
        }

        // open the blob file and write in the entire blob
        if (DEBUG) printf("opening %s to write. bloblen: %d\n",bfilename,*bloblen);
        blobfile = fopen(bfilename,"w");
        if (blobfile == NULL) {
                if (DEBUG) printf("error opening %s for write.\n",bfilename);
                free(blob);
                free(data);
                free(buf);
                return 3;
        }
        fwrite(blob, 1, *bloblen, blobfile);
        fclose(blobfile);
        if (DEBUG) printf("wrote lockbox to %s\n",bfilename);

	// Write data hash to DIR0
	ret = TPM_DirWriteAuth(0, data, ownauth);
        if (ret == 0) {
		printf("Wrote datahash to DIR0.\n");
	} else {
		printf("Failed to write datahash to DIR0.\n");
	}

	free(data);
	free(buf);
	free(blob);
	return 0;
}

/*
 * PRIVILEGED LOCKBOX RESTORE STATE:
 * If blob file storing keystore exists:
 * Read blob file on disk that represents sealed keystore.
 * Unseal it via TPM and SRK.
 * Create the keystore array based on the file data.
 * Input:
 *      bfilename -- blob file name to read stored lockbox data from
 * Return:
 *      0 on success
 *      1 if unable to open blob file for read
 *      2 if length of blob file is too small
 *      3 if unable to allocate memory to store the data of blob file
 *      4 if read incorrect number of bytes from blob file
 *      5 if TPM_UnSeal fails
 *      6 if blob file was corrupt (not a multiple of ENCDEC_BLOCK_SIZE)
 *      7 if deserialize (state restore) fails
 */
int nxkey_deserialize_from_disk(const char * bfilename)
{
	int i;
	int j;

	FILE * blobfile = fopen(bfilename,"r");	
	if (blobfile == NULL) {
		return 1;
	}

	fseek (blobfile, 0, SEEK_END);
	unsigned int bloblen = ftell(blobfile);
	rewind(blobfile);
	if (bloblen == 0) {
		return 2;
	}

	unsigned char * blob = malloc(bloblen);
	if (blob == NULL) {
		return 3;
	}

	size_t elements_read = fread(blob, 1, bloblen, blobfile);
	if (elements_read != bloblen) {
		return 4;
	}
	fclose(blobfile);	
	printf("deserialize_from_disk: Read blob file, bloblen: %d\n",bloblen);
	
	unsigned char * newpass = "NEW PASS";
	unsigned char newauth[SHA_DIGEST_LENGTH];
	TSS_sha1(newpass, strlen(newpass), newauth);

        /* Retrieve the serialized lockbox data */
        unsigned int chunksize = SEALED_BLOB_SIZE;

        // just incase, we are using SAFE_UNSEAL_SIZE here instead of MAX_SEAL_SIZE.
        unsigned char * data = malloc(sizeof(char) * (bloblen/chunksize)*SAFE_UNSEAL_SIZE);
	unsigned int datalen = 0;
        
        unsigned char tempdata[SAFE_UNSEAL_SIZE]; // decrypted data per loop iteration
        unsigned int tempdlen; // decrypted data length per loop iteration

        unsigned int remainingblob = bloblen; // loop condition
        unsigned int dataoffset = 0; // offset to read from data
        unsigned int bloboffset = 0; // offset to write into blob

        while (remainingblob >= chunksize) {
                if(DEBUG) printf("Unsealing %d bytes at blob[%d]\n",chunksize, bloboffset);
                ret = TPM_Unseal(srkkeyhandle, srkauth, newauth, &blob[bloboffset], chunksize, tempdata, &tempdlen);
                if (ret != 0) {
                        printf("TPM_UnSeal failed with error %p: %s\n", (int *)ret, TPM_GetErrMsg(ret));
                        free(data);
                        free(blob);
                        return 5;
                }

                if(DEBUG) printf("Copying %d bytes into data[%d]\n",tempdlen, dataoffset);
                memcpy(&data[dataoffset], tempdata, tempdlen);
                dataoffset += tempdlen;
                datalen += tempdlen;
                remainingblob -= chunksize;
                bloboffset += chunksize;
        }
        if (remainingblob != 0) {
                free(data);
                free(blob);
                printf("Deserialize failed due to corrupt blob.\n");
                return 6; // blob data length should be divisible by SEALED_BLOB_SIZE
        }
        printf("Unsealed data length: %d\n",datalen);

        ret = deserialize_lockbox(data, datalen);
        if (ret != 0) {
                printf("Deserialize failed.\n");
                free(data);
                free(blob);	
                return 7;
        }
	free(data);
	free(blob);	
	return 0;	
}

/** Test TPM DIR functionality */
static int nxkey_testdirs(void)
{
	char readdir[TPM_HASH_SIZE + TPM_DATA_OFFSET];
	char testdir[TPM_HASH_SIZE];
	uint32_t ret;
	int i;

	RAND_seed(nxkey_testdirs, 256);
	for (i = 0; i < 2; i++) {
	
		// write
		ret = TPM_DirWriteAuth(i, testdir, ownauth);
		if (ret) {
			fprintf(stderr, "write DIR %d failed\n", i);
			return 1;
		}

		// read back
		ret = TPM_DirRead(i, readdir, TPM_HASH_SIZE + TPM_DATA_OFFSET);
		if (ret) {
			fprintf(stderr, "read DIR %d failed\n", i);
			return 1;
		}
	
		// verify correctness
		if (memcmp(testdir, readdir + TPM_DATA_OFFSET, TPM_HASH_SIZE)) {
			fprintf(stderr, "data corruption in DIR %d\n", i);
			return 1;
		}
	}
		
	return 0;
}

/** Save state and cleanup
    (e.g., wipe keytable memory) */
int nxkey_shutdown(void)
{
	stop = 1;
	return 0;
}

/** 
    PRIVILEGED LOCKBOX FUNCTION TO SAVE STATE OF UNPRIVILEGED (NO LONGER USED)
    This is a method of the privileged lockbox which is called via IPC to encrypt and save some data.
    Code has been changed so that instead of just making this one IPC call, unprivileged lockboxes
    take care of doing everything required to save state except for encrypting the data.

    Handle a request to save application state 
    We always save with key 0 (or fail if it is absent) 
    Inputs:
        filepath - file to save lockbox to
        data - the serialized lockbox
        dlen - length of serialized data
    Return:
        0 for success, something else on failure
*/
int nxkey_save_app(const char *filepath, const char *data, int dlen)
{
        int i, j;
        printf("Child called save_app with: <%s, %s, %d>\n",filepath, data, dlen);

        // First we hash the data and verify the hashes to ensure IPC didn't corrupt data
	// Extract the hash
	unsigned char storedhash[SHA_DIGEST_LENGTH];
	memcpy(storedhash,data,SHA_DIGEST_LENGTH);

	// Hash the keystore data
	unsigned char datahash[SHA_DIGEST_LENGTH];
	TSS_sha1((unsigned char*)data + SHA_DIGEST_LENGTH, dlen - SHA_DIGEST_LENGTH, datahash);
	
	// Compare the hashes, exit if unequal
	if (memcmp(storedhash,datahash,SHA_DIGEST_LENGTH) != 0) {
		printf("Integrity check failed. Hashes are not identical.\n");
		printf("Stored hash:\n");
		for(i = 0; i < SHA_DIGEST_LENGTH; i++) {
			printf("%02X ",storedhash[i]);
		}
		printf("\n");
		printf("Data hash:\n");
		for(i = 0; i < SHA_DIGEST_LENGTH; i++) {
			printf("%02X ",datahash[i]);
		}
		printf("\n");
		return 1;
	}
         
	/* Create the blob to hold encrypted data */

        unsigned int tempdlen; // data encrypted per loop iteration

        unsigned int chunksize = ENCDEC_BLOCK_SIZE; // block size for nxkey_encrypt
	unsigned char * blob = malloc(sizeof(char) * ((dlen/chunksize)+1)*chunksize); // holds the entire encrypted blob
        unsigned int bloblen = 0;

        unsigned int remainingdata = dlen; // loop condition
        unsigned int dataoffset = 0; // offset to read from data
        unsigned int bloboffset = 0; // offset to write into blob

        // initialize the ivec for encryption. each chunk will get an incremented ivec
        unsigned char ivec[AES_BLOCK_SIZE];
        memset(ivec,0,AES_BLOCK_SIZE);

        while (remainingdata > 0) {
                // determine amount to encrypt this iteration
                if (remainingdata >= chunksize) {
                        tempdlen = chunksize;
                } else {
                        tempdlen = remainingdata;
                }

                unsigned char* encdata = nxkey_encrypt(0, &data[dataoffset], ivec);
                if (encdata == NULL) {
                        printf("Error encrypting data chunk.\n");
                        free(blob);
                        return 1;
                }

                if (DEBUG) {
                        printf("The ivec after encrypt:\n");
                        for (i=0; i<AES_BLOCK_SIZE; i++) {
                                printf("%d",ivec[i]);
                        }
                        printf("\n");
                }

                // fill in the blob with the current encryption
                memcpy(&blob[bloboffset], encdata, chunksize);
                // update the offsets
                bloboffset += chunksize;
                bloblen += chunksize;
                dataoffset += tempdlen;
                remainingdata -= tempdlen;
        }

        // check if the saved blob already exists
        if (DEBUG)
                printf("opening %s to check if exists\n",filepath);
        FILE * bfile = fopen(filepath,"r");
        if (DEBUG)
                printf("made the fopen(%s,\"r\") call.\n",filepath);
        if (bfile != NULL) {
                // delete it if it does
                if (DEBUG)
                        printf("deleting %s\n",filepath);
                fclose(bfile);
                unlink(filepath);
        }

        // open the blob file and write in the entire blob
        if (DEBUG)
                printf("opening %s to write. bloblen: %d\n",filepath,bloblen);
        bfile = fopen(filepath,"w");
        if (bfile == NULL) {
                printf("error opening file %s for write.\n", filepath);
                free(blob);
                return 1;
        }
        fwrite(blob, 1, bloblen, bfile);
        fclose(bfile);
        printf("wrote blob to %s\n",filepath);

        free(blob);

	return 0;
}

/*
    PRIVILEGED LOCKBOX FUNCTION TO RESTORE STATE OF UNPRIVILEGED (NO LONGER USED)
    This is a method of the privileged lockbox which is called via IPC to read stored data and decrypt it.
    Code has been changed so that instead of just making this one IPC call, unprivileged lockboxes
    take care of doing everything required to restore state except for decrypting the data.

 * Handle a request to restore application state 
 * We always restore with key 0 (or fail if it is absent) 
 * Returns the serialized lockbox data for child to deserialize
 */
char * nxkey_restore_app(const char *filepath)
{
        printf("Child called restore_app with: <%s>\n",filepath);
	// XXX use code from deserialize_from_disk
        // reads in the blob from disk
        // decrypts it into a data string
	int i;
	int j;

	FILE * blobfile = fopen(filepath,"r");	
	if (blobfile == NULL) {
		return NULL;
	}

	fseek (blobfile, 0, SEEK_END);
	unsigned int bloblen = ftell(blobfile);
	rewind(blobfile);
	if (bloblen == 0) {
		return NULL;
	}

	unsigned char * blob = malloc(bloblen);
	if (blob == NULL) {
		return NULL;
	}

	size_t elements_read = fread(blob, 1, bloblen, blobfile);
	if (elements_read != bloblen) {
		return NULL;
	}
	fclose(blobfile);	
	printf("nxkey_restore: Read blob file, bloblen: %d\n",bloblen);
	
        /* Retrieve the serialized lockbox data */
        unsigned int chunksize = ENCDEC_BLOCK_SIZE;

        unsigned char * data = malloc(sizeof(char) * (bloblen/chunksize)*chunksize);
	unsigned int datalen = 0;
        
        unsigned char * tempdata; // decrypted data per loop iteration

        unsigned int remainingblob = bloblen; // loop condition
        unsigned int dataoffset = 0; // offset to read from data
        unsigned int bloboffset = 0; // offset to write into blob

        unsigned char ivec[AES_BLOCK_SIZE];
        memset(ivec,0,AES_BLOCK_SIZE);

        while (remainingblob >= chunksize) {
                if(DEBUG) printf("Unsealing %d bytes at blob[%d]\n",chunksize, bloboffset);
                tempdata = nxkey_decrypt(0,&blob[bloboffset],ivec);
                if (tempdata == NULL) {
                        printf("Error decrypting data chunk.\n");
                        free(data);
                        free(blob);
                        return NULL;
                }

                memcpy(&data[dataoffset], tempdata, chunksize);
                dataoffset += chunksize;
                datalen += chunksize;
                remainingblob -= chunksize;
                bloboffset += chunksize;
        }
        if (remainingblob != 0) {
                free(data);
                free(blob);
                printf("Decrypting failed due to corrupt blob.\n");
                return NULL; // blob data length should be divisible by ENCDEC_BLOCK_SIZE
        }

	free(blob);	
	return data;
}

/*
 * nxkey_init:
 * Initialize the keystore.
 * Attempt to restore state from a stored file,
 * or create a new lockbox with INITIAL_NUM_SLOTS slots if file doesn't exist
 * Either of these may fail based on setting of the first_load flag
 * Inputs:
 *      bfilename -- blob file name that contains stored state.
 *      is_priv -- TRUE if being called by priviliged lockbox, else FALSE
 *      first_load -- TRUE if there is no state to restore, FALSE if state should be restored from a saved file
 * Return:
 *      0 on success. 
 */
int nxkey_init(const char * bfilename, bool is_priv, bool first_load)
{
        if (is_priv)
        {
                ret = nxkey_deserialize_from_disk(bfilename);
        } 
        else
        {
                ret = unpriv_deserialize_from_disk(bfilename, 0);
        }

	if (ret == 0) {
                if (first_load) {
                        printf("This was specified to be a new lockbox, but it managed to deserialize.\n \
                                \rShutting down because deserialization should have failed.\n \
                                \rIf this is not a new lockbox, please do not follow the 'p' or 'w filename' arguments with an 'f'.\n");
                        if (is_priv)
                                LockBoxSvc_Exit();
                        exit(1);
                }
		return 0;
	} else {
		printf("Deserialize failed with error value %d\n",ret);
                if (!first_load) {
                        printf("This was not specified to be a new lockbox.\n \
                                \rShutting down due to deserialize error.\n \
                                \rIf this is a new lockbox, please follow the 'p' or 'w filename' arguments with an 'f'.\n");
                        if (is_priv)
                                LockBoxSvc_Exit();
                        exit(1);
                }
	}

        // if we reach here, keystore failed to deserialize, so we create a new one
        create_new_keystore(INITIAL_NUM_SLOTS);
	
	return 0;
}

/* 
 * setup_lockbox:
 * Run some setup such as making IPC connections/bindings and initializing the keystore
 * Inputs:
 *      blobfilename -- filename of stored lockbox state
 *      is_priv -- TRUE if being called by privileged lockbox, else FALSE
 *      first_load -- TRUE is this is the first time this lockbox is starting up (i.e. should not be restored)
 * Return:
 *      0 on success
 */
int setup_lockbox(char* blobfilename, bool is_priv, bool first_load) {
        if (is_priv) {
        	printf("Nexus lockbox application [privileged]\n");
                LockBoxSvc_Init(primary_lockbox_port);
                printf("[lockbox] up at port %d\n", LockBox_server_port_num);
                if (LockBox_server_port_num != primary_lockbox_port) {
                        printf("Shutting down: lockbox started on a different port than %d\n",primary_lockbox_port);
                        LockBoxSvc_Exit();
                        exit(1);
                }
        } else {
                printf("Nexus lockbox application [unprivileged]\n");
                // connect unpriv to priv
                printf("Connecting to primary lockbox ...\n");
        }

        if (is_priv) {
                // set some passwords
                unsigned char *ownpass = "OWN PASS";
                unsigned char *srkpass = "SRK PASS";
                TSS_sha1(ownpass, strlen(ownpass), ownauth);
                TSS_sha1(srkpass, strlen(srkpass), srkauth);
        }

        // initialize the keystore from the master serialized file
        nxkey_init(blobfilename, is_priv, first_load);

        printf("Lockbox initialized.\n");

        // print out the keystore contents for debugging
	debug_print_lockbox();

        return 0;
}

/*
 * start_lockbox:
 * Start listening on the IPC port for commands
 * After receiving signal to stop listening, save state and exit
 * XXX -- there is currently no way to send lockbox a signal to terminate
 * Inputs:
 *      blobfilename -- name of file to save state to
 *      is_priv -- TRUE if called by privileged lockbox, else FALSE
 * Returns:
 *      void
 */
void start_lockbox(char* blobfilename, bool is_priv) {
        // DEBUG: skip request processing 
        // XXX remove
        if (is_priv) {
                stop = 0;
        } else {
                stop = 1;
        }
        
        // handle requests
        while (!stop)
                LockBox_processNextCommand();

        // close
        if (is_priv) {
                int bloblen; // to store the length of the sealed blob
                printf("Serializing keystore to disk...\n");
                if (nxkey_serialize_to_disk(blobfilename, &bloblen) != 0) {
                        printf("Error serializing keystore to disk!\n");
                } else {
                        printf("Serialized keystore to disk at %s, size:%d\n",blobfilename,bloblen);
                }
        } else {
                unsigned int bloblen;
                ret = unpriv_serialize_to_disk(blobfilename, &bloblen, 0);
                printf("Unpriv serialize to disk returned: %d. Bloblen: %d\n",ret, bloblen);
        }

	// shutdown
        if (is_priv) {
                // close the IPC port
                LockBoxSvc_Exit();
        } 

}

/*
 * main:
 * Start the keystore process.
 * Inputs:
 * argc: number of arguments
 * argv: argument array
 * Return:
 * 0 on a succesful run, 1 if there were any errors.
 */
int main(int argc, char **argv)
{
	char * command;
        int args_index = 1;

        // if no arguments were passed in
	if (argc < args_index+1) {
                printf("Please specify argument 'p' for privileged, or 'u filename' for unprivileged.\n");
                printf(USAGE);
		return 1;
	} else {
                char * lockbox_type = argv[args_index++];
                printf("lockbox_type: %s\n",lockbox_type);
                char * blobfilename;
                bool is_priv;
                bool first_load = false;

                if (!strcmp(lockbox_type,"p")) {
                        blobfilename = primary_blobfilename;
                        is_priv = true;
                        if (argc > args_index) {
                                // check to see if this is the first load
                                // first load is specified by following p or u with an f
                                if (!strcmp(argv[args_index],"f")) {
                                        first_load = true;
                                        args_index++;
                                }
                        }
                }
                else if (!strcmp(lockbox_type,"u")) {
                        if (argc > args_index) {
                                blobfilename = argv[args_index++];
                                is_priv = false;
                                if (argc > args_index) {
                                        // check to see if this is the first load
                                        // first load is specified by following p or u with an f
                                        if (!strcmp(argv[args_index],"f")) {
                                                first_load = true;
                                                args_index++;
                                        }
                                }
                        } else {
                                printf("Please specify a blob filename if running unprivileged.\n");
                                return 1; 
                        }
                }
                else {
                        printf("Please specify argument 'p' for privileged, or 'u filename' for unprivileged.\n");
                        return 1;
                }

                // run a bit of setup
                setup_lockbox(blobfilename, is_priv, first_load);
                
                // if at least two arguments are passed in
                if (argc > args_index) {
                        /* 
                         * Recognized commands:
                         * Add key 		(-a || --add)
                         * Clear keystore 	(-c || --clear)
                         * Encrypt data 	(-e || --encrypt)
                         * Help 		(-h || --help)
                         * Decrypt data 	(-d || --decrypt)
                         * Remove key 		(-r || --remove)
                         * Sign data 		(-s || --sign)
                         * Test keystore	(-t || --test)
                         * Verify data 		(-v || --verify)
                         */
                        command = argv[args_index++];
                        printf("Command: %s\n",command);
                        /* Help (-h) */
                        if (!strcmp(command,"-h")||!strcmp(command,"--help")) {
                                printf("AES options: %s\n",AES_options());
                                printf(USAGE);
                        }
                        /* Clear keystore (-c) */
                        else if (!strcmp(command,"-c")||!strcmp(command,"--clear")) {
                                printf("Clearing the keystore.\n");
                                if(remove(KEY_FILE)) {
                                        printf("Error clearing keystore.\n");
                                        return 1;
                                } else {
                                        printf("Keystore cleared.\n");
                                }
                        }
                        /* Test the keystore (-t) */
                        else if (!strcmp(command,"-t")||!strcmp(command,"--test")) {
                                printf("Running test:\n" \
                                "1. (-a) Insert key \"testkey\" into keystore\n" \
                                "2. (-e) Encrypt a block of data with \"testkey\"\n" \
                                "3. (-d) Decrypt the encrypted data with \"testkey\", and verify correctness\n" \
                                "4. (-s) Sign a block of data with \"testkey\"\n" \
                                "5. (-v) Verify the signed data with \"testkey\"\n" \
                                "6. (-r) Remove key \"testkey\" from keystore.\n" \
                                "7. (-e) Attempt to encrypt data with \"testkey\" and confirm failure\n" \
                                "8.      Attempt to write to and read from DIR\n" \
                                );
        
                                // XXX this test case is not fully written 

                                /*
                                int key_index;
                                int rm_key_index;
                                char * key = "testkey";

                                key_index = nxkey_insert(key);
                                assert(key_index != -1);
                                printf("test: using key_id %d\n",key_index);
                                */

                                //unsigned char* origtext = (unsigned char*)argv[3];

                                /* user can tell test which key to use, otherwise defaults to recently created key */
                                int key_id;
                                if (argc > args_index)
                                        key_id = nxkey_insert(-1, argv[args_index++], -1);
                                else
                                        key_id = nxkey_insert(-1, "testkey", -1);
                                

                                /* user can tell test which data to use, otherwise defaults to "testdata" */
                                //unsigned char* ptext;
                                unsigned char* ptext = malloc(ENCDEC_BLOCK_SIZE);
                                memset(ptext,'X',ENCDEC_BLOCK_SIZE);
                                if (argc > args_index) {
                                        //ptext = (unsigned char*)argv[3];
                                        memcpy(ptext,argv[args_index],strlen(argv[args_index]));
                                        args_index++;
                                } else {
                                        //ptext = (unsigned char*)"testdata";
                                        memcpy(ptext,"testdata",9);
                                }
                                //printf("test: Encrypting data: %s\n",ptext); // only need if DEBUG is off

                                unsigned char ivec[AES_BLOCK_SIZE];
                                memset(ivec,0,AES_BLOCK_SIZE);
                                unsigned char* enctext = nxkey_encrypt(key_id, ptext, ivec);
                                //printf("test: encrypted data: %s\n", enctext); // only need if DEBUG is off

                                unsigned char* dectext = nxkey_decrypt(key_id, enctext, ivec);
                                //printf("test: decrypted data: %s\n", dectext); // only need if DEBUG is off

                                /* free all the strings that got malloced */
                                free(ptext);
                                free(enctext);
                                free(dectext);

                                /*
                                rm_key_index = nxkey_delete(key_index);
                                assert(key_index == rm_key_index);
                                */
                        }
                        else if (!strcmp(command,"-t2")) {
                                int i;
                                char* testkey = malloc(10);
                                for (i = 0; i < 15; i++) {
                                        sprintf(testkey,"testkey%d",i);
                                        nxkey_insert(-1, testkey, -1);
                                }
                                free(testkey);
                        }
                        else if (!strcmp(command,"-t3")) {
                                nxkey_insert(-1, "romanlovestestkey", -1);
                                nxkey_insert(-1, "romanlovestestkey", -1);
                                nxkey_delete(0);
                                int bloblen;
                                debug_print_lockbox();
                                int retval = nxkey_serialize_to_disk(blobfilename, &bloblen);
                                nxkey_insert(-1, "romanhatestestkey", -1);
                                retval = nxkey_init(blobfilename, is_priv, first_load);
                                debug_print_lockbox();
                        }
                        else if (!strcmp(command,"-t4")) {
                                // test unprivleged save and restore functionality
                                nxkey_insert(-1, "romanlovestestkey", -1);
                                unsigned int datalen = 0;
                                unsigned char * data = serialize_lockbox(&datalen);
                                if (data == NULL || datalen == 0) {
                                        printf("Failed to serialize.\n");       
                                } else {
                                        ret = nxkey_save_app("whatever.txt", data, datalen);
                                        if (ret != 0) {
                                                printf("Failed to save.\n");
                                        } else {
                                                nxkey_insert(-1, "romanhatestestkey", -1);
                                                data = nxkey_restore_app("whatever.txt");
                                                deserialize_lockbox(data, datalen);
                                                if (data == NULL) {
                                                        printf("Failed to restore.\n");
                                                } else {
                                                        debug_print_lockbox();
                                                }
                                        }
                                }
                        }
                        else if (!strcmp(command,"-t5")) {
                                printf("testing DIRs..\n");
                                if (nxkey_testdirs())
                                        return 1;
                                printf("Ok. DIR test passed\n");
                        }
                        /* Add key (-a) */
                        else if (!strcmp(command,"-a")||!strcmp(command,"--add")) {
                                printf("Adding key.\n");
                                if (argc < args_index+1) {
                                        printf("Not enough arguments supplied.\n");
                                        printf(USAGE);
                                } else {
                                        int key_index = nxkey_insert(-1, argv[args_index++], -1);
                                        printf("main: inserted into index %d\n",key_index);
                                }
                        }
                        /* Remove key (-r) */
                        else if (!strcmp(command,"-r")||!strcmp(command,"--remove")) {
                                printf("Removing key.\n");
                                if (argc < args_index+1) {
                                        printf("Not enough arguments supplied.\n");
                                        printf(USAGE);
                                } else {
                                        int key_index = nxkey_delete(atoi(argv[args_index+1]));
                                        args_index+=1;
                                        printf("main: deleted from index %d\n",key_index);
                                }
                        }
                        /* Encrypt data (-e) */
                        else if (!strcmp(command,"-e")||!strcmp(command,"--encrypt")) {
                                printf("Encrypting data.\n");
                                if (argc < args_index+2) {
                                        printf("Not enough arguments supplied.\n");
                                        printf(USAGE);
                                } else {
                                        unsigned char ivec[AES_BLOCK_SIZE];
                                        unsigned char* enctext = nxkey_encrypt(atoi(argv[args_index+1]),(unsigned char*)argv[args_index+2], ivec);
                                        args_index+=2;
                                        free(enctext);
                                }
                        }
                        /* Decrypt data (-d) */
                        else if (!strcmp(command,"-d")||!strcmp(command,"--decrypt")) {
                                printf("Decrypting data.\n");
                                if (argc < args_index+3) {
                                        printf("Not enough arguments supplied.\n");
                                        printf(USAGE);
                                } else {
                                        unsigned char* dectext = nxkey_decrypt(atoi(argv[args_index+1]),(unsigned char*)argv[args_index+2], (unsigned char*)argv[args_index+3]);
                                        args_index+=3;
                                        free(dectext);
                                }
                        }
                        /* Sign data (-s) */
                        else if (!strcmp(command,"-s")||!strcmp(command,"--sign")) {
                                printf("Signing data.\n");
                                if (argc < args_index+3) {
                                        printf("Not enough arguments supplied.\n");
                                        printf(USAGE);
                                } else {
                                        unsigned char* hmac = nxkey_hmac_sign(atoi(argv[args_index+1]), argv[args_index+2], strlen(argv[args_index+3]));
                                        args_index+=3;
                                        free(hmac);
                                }
                        }
                        /* Verify data (-v) */
                        else if (!strcmp(command,"-v")||!strcmp(command,"--verify")) {
                                printf("Verifying data.\n");
                                if (argc < args_index+4) {
                                        printf("Not enough arguments supplied.\n");
                                        printf(USAGE);
                                } else {
                                        int verification = nxkey_hmac_verify(atoi(argv[args_index+1]), (unsigned char *)argv[args_index+2], strlen(argv[args_index+3]), (unsigned char*) argv[args_index+4]);
                                        args_index+=4;
                                        printf("main: signature correct: %s\n", verification?"True":"False");
                                }
                        }
                        /* Unknown command */
                        else {
                                printf("Unrecognized command: %s.\n",command);
                                printf(USAGE);
                                return 1;
                        }
                }

                // run the IPC and some cleanup
                start_lockbox(blobfilename, is_priv);

	}
        return 0;
}

