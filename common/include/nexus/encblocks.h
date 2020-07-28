#ifndef __ENCBLOCKS_H__
#define __ENCBLOCKS_H__

#include <nexus/commontypedefs.h>

#define KEYSIZE    (32)
#define TWEAKSIZE  (16)
#define KTWEAKSIZE (16)

typedef enum EncBlockBufType EncBlockBufType;
enum EncBlockBufType{
  PLAIN = 1,
  CIPHER,
};

struct Keys{
  unsigned char aeskey[KEYSIZE];
  unsigned char tweakkey[KTWEAKSIZE];
};

enum EncBlocksErr{
  ERR_BAD_KEY = 2,
  ERR_BAD_SUBOFF,
  ERR_BAD_SUBLEN,
  ERR_BAD_TBC_LEN,
  ERR_BAD_TBC,
  ERR_NULL_BUF,
};

void encblocks_destroy(EncBlocks *enc);

/* Malloc a new type(PLAIN or CIPHER) buffer and set up structs */
EncBlocks *encblocks_create(EncBlockBufType type, int len, int blocksize, 
			    int suboff, int sublen);

/* create an encblocks but use the supplied buffer as PLAIN or CIPHER instead of
 * mallocing a buffer of type */
EncBlocks *encblocks_create_from_buf(EncBlockBufType type, int len, int blocksize, 
				     int suboff, int sublen, unsigned char *buf);


/* Compute a type buffer from an already created encblocks.  For
 * example, create a PLAIN and compute a CIPHER (or create CIPHER
 * compute PLAIN)
 */
int encblocks_compute(EncBlockBufType type, EncBlocks *enc, int suboff, int sublen);

/* compute the encblocks type, but instead of mallocing, use buf */
int encblocks_compute_to_buf(EncBlockBufType type, EncBlocks *enc, 
			     int suboff, int sublen, unsigned char *buf);


/* Return the internal buffer (PLAIN or CIPHER) of the encblocks */
unsigned char *encblocks_getbuf(EncBlockBufType type, EncBlocks *enc);

/* Generate an aes key and a tweak key from RAND_bytes */
int encblocks_generate_keys(EncBlocks * enc);

/* After keys have been generated or a key has been overwritten,
 * activate them.  XXX should probably have a set keys instead of *
 * letting memcpy overwrite 
 */
int encblocks_activate_keys(EncBlocks * enc);

/* Return a pointer to the current keys */
Keys *encblocks_get_keys(EncBlocks *enc);


/* return a length rounded up to fall on blocksize boundaries */
int encblocks_round_len(int len, int blocksize);
/* ensure the blocksize is at least AES_BLOCK_SIZE */
int encblocks_check_blocksize(int blocksize);

/* To notify that a change has happened and a block should be
 * recomputed */
void encblocks_set_bitmap(EncBlocks *enc, unsigned char *addr, int
			  size, unsigned char **changedptr, int
			  *changedsize);


/* encrypt(if type is CIPHER). Recompute dirty blocks by getting
 * offsets from queue */
int encblocks_update(EncBlockBufType type, EncBlocks *enc);


/* Write a backup log into the supplied buffer, but don't go over
 * buflen.  basefileoff is the offset of the data offset in the
 * encrypted file. */
int encblocks_update_backup_to_buf(EncBlockBufType type, EncBlocks *enc, 
				   char *buf, int buflen, int basefileoff);


/* zero an encblocks buffer */
void encblocks_zero(EncBlockBufType type, EncBlocks *enc);

#ifndef __NEXUSKERNEL__
/* encrypt(if type is CIPHER) and write updated blocks as a backup log
 * to fd.  fileoffset is the offset of the data in the file.  */
int encblocks_update_backup(EncBlockBufType type, EncBlocks *enc, 
			    int fd, int fileoffset);


/* encrypt(if type is CIPHER) and write all blocks to fd at fileoffset */
int encblocks_writeall(EncBlockBufType type, EncBlocks *enc, 
		       int fd, int fileoffset);
#endif


struct BackupBlock{
  int offset;
  int len;
  unsigned char data[0];
};

#endif
