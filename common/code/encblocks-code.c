
#include <nexus/defs.h>	// can be safely included in all environments

#define TWEAKLEN (16)

#define DBG_ENCBLOCKS (0)
#define printf_dbg(x...) if(DBG_ENCBLOCKS)printf(x)

struct EncBlocks{
  unsigned char *plain;
  unsigned char *cipher;
  unsigned char *allocplain;
  unsigned char *alloccipher;

  int len;
  int blocksize;

  int suboff;
  int sublen;

  Keys keys;
  int keyset;

  unsigned char *bitmap;
  UQueue *dirty;
};

#define ROUND_TO_BLOCK(o,b) ((o) - ((o) % (b)))
#define BLOCKNUM(e,i) (((i) + ((e)->blocksize - 1))/((e)->blocksize))

void encblocks_destroy(EncBlocks *enc){
  uqueue_destroy(enc->dirty);
  nxcompat_free(enc->bitmap);
  if(enc->allocplain != NULL)
    nxcompat_free(enc->allocplain);
  if(enc->alloccipher != NULL)
    nxcompat_free(enc->alloccipher);
  nxcompat_free(enc);
}

static void dump_keys(Keys *k){
  int i;
  printf("aeskey: ");
  for(i = 0; i < KEYSIZE; i++)
    printf("%02x ", k->aeskey[i]);
  printf("\ntweakkey: ");
  for(i = 0; i < KTWEAKSIZE; i++)
    printf("%02x ", k->tweakkey[i]);
  printf("\n");
}

#define BITMAPSIZE(e) (((e)->sublen + 7)/8)
#define BITMAPNUM(e,n) ((n) - BLOCKNUM(e,(e)->suboff))
#define BITMAPCHAR(e,n) ((e)->bitmap[(BITMAPNUM(e,n) + 7)/8])
#define BITMAPMASK(e,n) (1 << (7 - (BITMAPNUM(e,n) % 8)))

#define MARK(e,n) BITMAPCHAR(e,n) |= BITMAPMASK(e,n)
#define UNMARK(e,n) BITMAPCHAR(e,n) &= ~BITMAPMASK(e,n)

#define MARKED(e,n) ((BITMAPCHAR(e,n) & BITMAPMASK(e,n)) != 0)



static int check_align(int len, int blocksize, int suboff, int sublen){
  /* check subregions are aligned on block boundaries */
  if(ROUND_TO_BLOCK(suboff, blocksize) != suboff)
    return -1;
  if(suboff + sublen != len){
    if(ROUND_TO_BLOCK(suboff + sublen, blocksize) != suboff + sublen)
      return -1;
  }
  return 0;
}

EncBlocks *encblocks_create_from_buf(EncBlockBufType type, int len, int blocksize, 
				     int suboff, int sublen, unsigned char *buf){

  if(check_align(len, blocksize, suboff, sublen) < 0)
    return NULL;

  EncBlocks *new = (EncBlocks *)nxcompat_alloc(sizeof(EncBlocks));

  if(type == PLAIN){
    new->plain = buf;
    new->cipher = NULL;
  }
  if(type == CIPHER){
    new->cipher = buf;
    new->plain = NULL;
  }

  new->allocplain = new->alloccipher = NULL;
  new->keyset = 0;
  new->blocksize = blocksize;
  new->suboff = suboff;
  new->sublen = sublen;

  new->len = len;
  new->bitmap = (unsigned char *)nxcompat_alloc(BITMAPSIZE(new));
  memset(new->bitmap, 0, BITMAPSIZE(new));
  new->dirty = uqueue_new();
  assert(uqueue_len(new->dirty) == 0);

  printf_dbg("returning from encblocks_create\n");
  return new;
}

EncBlocks *encblocks_create(EncBlockBufType type, int len, int blocksize, 
			    int suboff, int sublen){
  unsigned char *buf;
  EncBlocks *new;

  if(check_align(len, blocksize, suboff, sublen) < 0)
    return NULL;
  
  buf = (unsigned char *)nxcompat_alloc(sublen);

  printf_dbg("nxcompat_alloced %s %d bytes at 0x%p\n", 
	     (type == PLAIN)?"PLAIN":"CIPHER", 
	     sublen, buf);

  new = encblocks_create_from_buf(type, len, blocksize, suboff, sublen, buf);
  if(new == NULL){
    nxcompat_free(buf);
    return new;
  }

  if(type == PLAIN){
    new->allocplain = buf;
  }else{
    new->alloccipher = buf;
  }

  return new;
}

void encblocks_zero(EncBlockBufType type, EncBlocks *enc){
  if(type == PLAIN)
    memset(enc->plain, 0, enc->sublen);
  if(type == CIPHER)
    memset(enc->cipher, 0, enc->sublen);
}

int encblocks_check_blocksize(int blocksize){
  return max(blocksize, AES_BLOCK_SIZE);
}

int encblocks_round_len(int len, int blocksize){

  if(len < AES_BLOCK_SIZE)
    return AES_BLOCK_SIZE;

  int lastblocksize = (len % blocksize);
  if((lastblocksize > 0) && (lastblocksize <= AES_BLOCK_SIZE)){
    /* tbc ciphertext stealing will need every misaligned block to be > 16 bytes */
    len += AES_BLOCK_SIZE - lastblocksize + 1;
  }
  return len;
}

unsigned char *encblocks_getbuf(EncBlockBufType type, EncBlocks *enc){
  if(type == PLAIN)
    return enc->plain;
  if(type == CIPHER)
    return enc->cipher;
  return NULL;
}

int encblocks_generate_keys(EncBlocks *enc){
  Crypto_GetRandBytes(enc->keys.aeskey, KEYSIZE);
  Crypto_GetRandBytes(enc->keys.tweakkey, KTWEAKSIZE);
  return 0;
}
int encblocks_activate_keys(EncBlocks * enc){
  enc->keyset = 1;
  return 0;
}
Keys *encblocks_get_keys(EncBlocks *enc){
  return &enc->keys;
}

static int compute_check(EncBlocks *enc, int suboff, int sublen){
  if(enc->keyset == 0)
    return -ERR_BAD_KEY;
  if(suboff < enc->suboff)
    return -ERR_BAD_SUBOFF;
  if(suboff + sublen > enc->suboff + enc->sublen)
    return -ERR_BAD_SUBLEN;
  return 0;
}

int encblocks_compute(EncBlockBufType type, EncBlocks *enc, 
			     int suboff, int sublen){
  unsigned char *buf = NULL;
  
  int ret;
  if((ret = compute_check(enc, suboff, sublen)) < 0)
    return ret;

  if(type == PLAIN){
    if(enc->cipher == NULL)
      return -ERR_NULL_BUF;
    if(enc->plain == NULL){
      buf = enc->allocplain = (unsigned char *)nxcompat_alloc(sublen);
      
      printf_dbg("nxcompat_alloced PLAIN during compute %d bytes at 0x%p\n", sublen, buf);
    }
  }
  if(type == CIPHER){
    if(enc->plain == NULL)
      return -ERR_NULL_BUF;
    if(enc->cipher == NULL){
      buf = enc->alloccipher = (unsigned char *)nxcompat_alloc(sublen);
      printf_dbg("nxcompat_alloced CIPHER during compute %d bytes at 0x%p\n", sublen, buf);
    }
  }

  return encblocks_compute_to_buf(type, enc, suboff, sublen, buf);
}

int encblocks_compute_to_buf(EncBlockBufType type, EncBlocks *enc, 
			     int suboff, int sublen, unsigned char *buf){
  int ret;

  if((ret = compute_check(enc, suboff, sublen)) < 0)
    return ret; 

  /* allocate other buffer if it hasn't already been allocated */
  if(type == PLAIN){
    if(enc->cipher == NULL)
      return -ERR_NULL_BUF;
    if(enc->plain == NULL){
      enc->plain = buf;
    }

    printf_dbg("CIPHER: ");
    int j;     
    for(j = 0; j < enc->blocksize; j++)
      printf_dbg("%02x ", (enc->cipher - enc->suboff)[j]);
    printf_dbg("\n");
  }
  if(type == CIPHER){
    if(enc->plain == NULL)
      return -ERR_NULL_BUF;
    if(enc->cipher == NULL){
      enc->cipher = buf;
    }

    printf_dbg("PLAIN: ");
    int j;     
    for(j = 0; j < enc->blocksize; j++)
      printf_dbg("%02x ", (enc->plain - enc->suboff)[j]);
    printf_dbg("\n");
  }
  
  if(DBG_ENCBLOCKS)
    dump_keys(&enc->keys);
  
  int i;
  for(i = suboff; i < suboff + sublen; i += enc->blocksize){
    int ret = 0;
    unsigned char tweak[TWEAKLEN];
    memset(tweak, 0, TWEAKLEN);
    *(unsigned int *)tweak = BLOCKNUM(enc, i);

    printf_dbg("i=%d\n", i);
    printf_dbg("tweak: ");
    int j;
    for(j = 0; j < TWEAKLEN; j++)
      printf_dbg("%02x ", tweak[j]);
    printf_dbg("\n");

    int declength = min(enc->blocksize, enc->len - i);

    printf_dbg("%s: ", (type == PLAIN)?"PLAIN":"CIPHER");
    if(type == PLAIN){
      printf_dbg("doing decrypt\n");
      ret = tbc_decrypt(enc->cipher + i - enc->suboff, declength,
			enc->plain + i - enc->suboff, &declength,
			enc->keys.aeskey, KEYSIZE,
			tweak, TWEAKLEN,
			enc->keys.tweakkey, KTWEAKSIZE);

      int j;     
      for(j = 0; j < enc->blocksize; j++)
	printf_dbg("%02x ", (enc->plain - enc->suboff)[j]);
      printf_dbg("\n");
    }
    if(type == CIPHER){
      printf_dbg("doing encrypt\n");
      ret = tbc_encrypt(enc->plain + i - enc->suboff, declength,
			enc->cipher + i - enc->suboff, &declength,
			enc->keys.aeskey, KEYSIZE,
			tweak, TWEAKLEN,
			enc->keys.tweakkey, KTWEAKSIZE);
      int j;     
      for(j = 0; j < enc->blocksize; j++)
	printf_dbg("%02x ", (enc->cipher - enc->suboff)[j]);
      printf_dbg("\n");
    }
    UNMARK(enc, BLOCKNUM(enc, i));
    printf_dbg("\n");
    if(declength != (min(enc->blocksize, enc->len - i)))
      return -ERR_BAD_TBC_LEN;
    if(ret < 0)
      return -ERR_BAD_TBC;
  }

  return 0;
}


/* encrypt block i */
static int encblocks_update_one(int i, EncBlockBufType type, EncBlocks *enc){
  int declength = min(enc->blocksize, enc->len - i);
  int ret = 0;
  unsigned char tweak[TWEAKLEN];
  memset(tweak, 0, TWEAKLEN);
  *(unsigned int *)tweak = BLOCKNUM(enc, i);

  if(type == CIPHER){
    ret = tbc_encrypt(enc->plain + i - enc->suboff, declength,
		      enc->cipher + i - enc->suboff, &declength,
		      enc->keys.aeskey, KEYSIZE,
		      tweak, TWEAKLEN,
		      enc->keys.tweakkey, KTWEAKSIZE);
  }

  if(declength != (min(enc->blocksize, enc->len - i)))
    return -ERR_BAD_TBC_LEN;
  if(ret < 0)
    return -ERR_BAD_TBC;

  UNMARK(enc, BLOCKNUM(enc, i));

  return declength;
}

/* perform updates then write them to fd at fileoffset */
static int encblocks_write_one_to_buf(int i, EncBlockBufType type, EncBlocks *enc, 
			       char *buf, int buflen){
  int written = 0;
  int len = encblocks_update_one(i, type, enc);

  if(len > buflen)
    return -1;

  memcpy(buf, encblocks_getbuf(type,enc) + i - enc->suboff, len);
  return written;
}


/* recompute dirty blocks by getting offsets from queue */
int encblocks_update(EncBlockBufType type, EncBlocks *enc){
  int written = 0;
  while(uqueue_len(enc->dirty) > 0){
    int i = (int)uqueue_dequeue(enc->dirty);
    written += encblocks_update_one(i, type, enc);
  }
  return written;
}

/* write the log of backup blocks into a buffer.  basefileoff is the data offset
 * of the encblocks in its file. */
int encblocks_update_backup_to_buf(EncBlockBufType type, EncBlocks *enc, 
				   char *buf, int buflen, int basefileoff){
  int filepos = 0;
  while(uqueue_len(enc->dirty) > 0){
    int written = 0;
    int i = (int)uqueue_dequeue(enc->dirty);
    BackupBlock *backup;

    if(filepos > basefileoff)
      return -1;

    backup = (BackupBlock *)&buf[filepos];

    written = encblocks_write_one_to_buf(i, type, enc, backup->data, 
					 buflen - filepos - sizeof(BackupBlock));
    
    if(written < 0)
      return -1;

    backup->offset = basefileoff + i;
    backup->len = written;

    filepos += written + sizeof(BackupBlock);
  }
  return filepos;
}


/* mark in bitmap which blocks are dirty, and add offsets to queue */
void encblocks_set_bitmap(EncBlocks *enc, unsigned char *addr, int size,
			  unsigned char **changedptr, int *changedsize){
  int start = (addr - enc->plain) + enc->suboff;
  int end = start + size;


  int starti = ROUND_TO_BLOCK(start, enc->blocksize);
  
  *changedptr = enc->cipher + starti - enc->suboff;
  *changedsize = 0;

  int i;
  for(i = starti;
      i <= ROUND_TO_BLOCK(end, enc->blocksize); 
      i += enc->blocksize){
    *changedsize += min(enc->blocksize, enc->len - i);

    if(!MARKED(enc, BLOCKNUM(enc, i))){
      MARK(enc, BLOCKNUM(enc, i));
      uqueue_enqueue(enc->dirty, (void *)i);
    }
  }
}
