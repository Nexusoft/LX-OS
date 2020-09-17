/** NexusOS: cryptographic operation support for files 
             uses lockboxes underneath */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/aes.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/nexuscalls.h>
#include <nexus/LockBox.interface.h>

#include "io.private.h"

#define DISK_BLOCK_SIZE	(512)	///< required to match lockbox.c settings
#define HASH_BLOCK_SIZE	(1024)

/** Update the counter value in the combined <ivec, counter> structure 
    Convention is that the counter occupies the first 4bytes, to allow
    easy updating (which would not work with e.g., XOR) */
static void
__ivec_update(char *ivec, unsigned long counter)
{
	((unsigned long *) ivec)[0] = counter;
}

/** Initialize initialization vector */
static void
__ivec_init(char *ivec)
{
	// XXX initialize from stored ivec
	memset(ivec, 0, sizeof(AES_BLOCK_SIZE));

	__ivec_update(ivec, 0);
}

static void
__print_hex(const char *header, const void *_text, int bytelen)
{
	const unsigned long *text = _text;
	int q;

	printf("%s ", header);
	for (q = 0; q < bytelen/4; q++) {
		printf("%08lx ", text[q]);
		if (!((q+1) % 12))
			printf("\n");
	}

	printf("\n");
}
	
/** Read and decrypt a single block from disc
    @param plaintext must have room for a full block 
    @return -1 on error or number of bytes read */
static int
nxfile_enc_readblock(GenericDescriptor *d, char *plaintext, void *ivec)
{
	char ciphertext[DISK_BLOCK_SIZE];
	int ret;

	if (d->lockbox <= 0)
		ReturnError(1, "[crypto] invalid lockbox");
	
	// read block
  	ret = d->ops->read(d, ciphertext, DISK_BLOCK_SIZE);
	if (ret < 0)
		return -1;

	// pad zero bytes
	if (ret != DISK_BLOCK_SIZE)
		memset(ciphertext + ret, 0, DISK_BLOCK_SIZE - ret);

	// decrypt
#define DO_HACK
#ifdef DO_HACK
	char faketext[DISK_BLOCK_SIZE];
	if (LockBox_Decrypt_ext(d->lockbox, d->key_index, 
		VARLEN(ciphertext, DISK_BLOCK_SIZE),
		VARLEN(faketext, DISK_BLOCK_SIZE),
		VARLEN(ivec, AES_BLOCK_SIZE),
			DISK_BLOCK_SIZE, 0))
		return -1;
	memcpy(plaintext, ciphertext, DISK_BLOCK_SIZE);
#else
	if (LockBox_Decrypt_ext(d->lockbox, d->key_index, 
		VARLEN(ciphertext, DISK_BLOCK_SIZE),
		VARLEN(plaintext, DISK_BLOCK_SIZE),
		VARLEN(ivec, AES_BLOCK_SIZE),
			DISK_BLOCK_SIZE, 0))
		return -1;
#endif
	return ret;
}

/** Read and decrypt data using lockbox */
ssize_t
nxfile_enc_read(GenericDescriptor *d, void *buf, size_t count)
{
	char plaintext[DISK_BLOCK_SIZE];
	char ivec[AES_BLOCK_SIZE];

	unsigned long oldpos, counter, aligned, done, first_off;
	int ret;

	if (d->lockbox <= 0)
		ReturnError(1, "[crypto] invalid lockbox");
	
	if (count > PAGESIZE)
		count = PAGESIZE;
	
	// calculate offset in file
	oldpos = d->ops->lseek(d, 0, SEEK_CUR);
	counter = oldpos / DISK_BLOCK_SIZE;
	aligned = counter * DISK_BLOCK_SIZE;
	first_off = oldpos - aligned;

	// rewind to block boundary 
	if (first_off)
		d->ops->lseek(d, aligned, SEEK_SET);

	// repeatedly read blocks
	done = 0;
	__ivec_init(ivec);
	do {
		// read a whole block
		__ivec_update(ivec, counter);
		ret = nxfile_enc_readblock(d, plaintext, ivec);
		if (ret < 0)
			return -1;

		// special case: first block? skip to block offset
		ret -= first_off;
		if (!ret)
			break;
		
		// copy
		memcpy(buf + done, plaintext + first_off, ret);
		
		// update counters
		done += ret;
		counter++;
		first_off = 0;
	} while (done < count && ret == DISK_BLOCK_SIZE);

	// move to saved position + #bytes
	d->ops->lseek(d, oldpos + done, SEEK_SET);
	
	return done;
}

static ssize_t
nxfile_enc_writeblock(GenericDescriptor *d, const void *buf, size_t count)
{
	char plaintext[DISK_BLOCK_SIZE], ciphertext[DISK_BLOCK_SIZE];
	char ivec[AES_BLOCK_SIZE];
	const char *pbuf;
	unsigned long oldpos, counter, aligned, done, len;
	int ret;

	// calculate offset in file
	oldpos = d->ops->lseek(d, 0, SEEK_CUR);
	counter = oldpos / DISK_BLOCK_SIZE;
	aligned = counter * DISK_BLOCK_SIZE;

	// repeatedly write blocks
	done = 0;
	__ivec_init(ivec);
	while (done < count) {
		// calculate length (only shorter than full block for first and last block)
		len = DISK_BLOCK_SIZE;
		if (count - done < len)
			len = count - done;
		__ivec_update(ivec, counter);

		// partial write: read underlying block and/or pad end
		// can only occur on first and last blocks
		if (aligned + done < oldpos || len != DISK_BLOCK_SIZE) {
			
			// read underlying block
			d->ops->lseek(d, aligned + done, SEEK_SET);
			ret = nxfile_enc_readblock(d, plaintext, ivec);
			if (ret < 0)
				ret = 0; // failure is ok when appending. XXX properly extract that case
			d->ops->lseek(d, aligned + done, SEEK_SET);

			// add padding
			if (ret != DISK_BLOCK_SIZE)
				memset(plaintext + ret, 0, DISK_BLOCK_SIZE - ret);

			// overwrite with new data
			if (aligned < oldpos)
				memcpy(plaintext + oldpos - aligned, buf, len);
			else
				memcpy(plaintext, buf, len);
			pbuf = plaintext;
		}
		else
			pbuf = buf + done;

		if (LockBox_Encrypt_ext(d->lockbox, d->key_index, 
			VARLEN(plaintext, DISK_BLOCK_SIZE),
			VARLEN(ciphertext, DISK_BLOCK_SIZE),
			VARLEN(ivec, AES_BLOCK_SIZE), DISK_BLOCK_SIZE, 0))
			return -1;

		// write block
#ifdef DO_HACK
		if (d->ops->write(d, /* ciphertext */ pbuf, len) != len) 
#else
		if (d->ops->write(d, ciphertext, len) != len) 
#endif
			ReturnError(-1, "[crypto] write block");
		counter++;
		done += len;
	}

	// move to saved position
	d->ops->lseek(d, oldpos + done, SEEK_SET);

	return done;	
}

/** Write and encrypt data using lockbox */
ssize_t
nxfile_enc_write(GenericDescriptor *d, const void *buf, size_t count)
{
	int len, off, ret;

	if (d->lockbox <= 0)
		ReturnError(1, "[crypto] invalid lockbox");
	
	off = 0;
	while (off < count) {
		len = (count - off) < PAGESIZE ? (count - off) : PAGESIZE;
		ret = nxfile_enc_writeblock(d, buf + off, len);
		if (ret != len)
			return -1;
		off += len;
	
		// move to next position
		if (off < count)
			d->ops->lseek(d, ret, SEEK_CUR);
	}
	
	return off;
}

/** Calculate a file signature using a LockBox */
static int
sig_gen(GenericDescriptor *d, unsigned long *finaldigest)
{
	char block[HASH_BLOCK_SIZE];
	unsigned long digest[20 / sizeof(long)];
	unsigned long off, ret, i, total;

	if (!d->ops->read || !d->ops->lseek)
		return -1;

	// save offset
	off = d->ops->lseek(d, 0, SEEK_CUR);
	
	d->ops->lseek(d, 0, SEEK_SET);
	memset(finaldigest, 0, 20);

	// process entire file
	total = 0;
	do {
		// read a block
		ret = d->ops->read(d, block, HASH_BLOCK_SIZE);
		if (ret < 0)
			goto cleanup_error;
		if (!ret)
			break;
		// pad last block
		if (ret != HASH_BLOCK_SIZE)
			memset(block + ret, 0, HASH_BLOCK_SIZE - ret);

		// generate hash
		if (LockBox_Sign_ext(d->lockbox, VARLEN(block, HASH_BLOCK_SIZE), 
				HASH_BLOCK_SIZE, VARLEN(digest, 20)))
			goto cleanup_error;

		// integrate in global hash
		for (i = 0; i < 5; i++)
			finaldigest[i] ^= digest[i];
		total += ret;
	} while (ret == HASH_BLOCK_SIZE);

	// restore offset
	d->ops->lseek(d, off, SEEK_SET);
	return 0;

cleanup_error:
	d->ops->lseek(d, off, SEEK_SET);
	return 1;
}

/** Generate a file signature
  
    XXX switch to iterative update with Merkle trees
        - requires dirty bit accounting */
int 
nxfile_sig_gen(GenericDescriptor *d, int index)
{
	char digest[20];
	
	if (d->lockbox <= 0)
		ReturnError(1, "[crypto] invalid lockbox");
	
	if (sig_gen(d, (unsigned long *) digest))
		return -1;

	LockBox_Insert_ext(d->lockbox, index, VARLEN(digest, 20), 20);
	return 0;
}

/** Verify a file signature. 

    Works on any descriptor. 
    WARNING: since this functions reads the entire file, 
             it will never return on infinitely long files 
 
    XXX switch to Merkle trees
 */
int
nxfile_sig_check(GenericDescriptor *d, int index)
{
	unsigned long digest[20];
	
	if (d->lockbox <= 0)
		ReturnError(1, "[crypto] invalid lockbox");
	
	if (sig_gen(d, digest))
		return -1;

	if (LockBox_Verify_ext(d->lockbox, index, VARLEN(digest, 20)))
		return -1;
	
	return 0;
}

