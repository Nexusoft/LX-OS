#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include <nexus/queue.h>
#include <nexus/util.h>
#include <crypto/aes.h>

#include <nexus/Crypto.interface.h>

#include <nexus/encblocks.h>


/* include common encblocks functions */
#include <../code/encblocks-code.c>


/* The following functions use the filesystem for user processes only */


/* perform updates then write them to fd at fileoffset */
int encblocks_write_one(int i, EncBlockBufType type, EncBlocks *enc, 
			int fd, int fileoffset){
  int written = 0;
  int len = encblocks_update_one(i, type, enc);
  int dbg = 0;

  if(dbg)printf("seek to %d, write 0x%p %d\n", fileoffset, encblocks_getbuf(type,enc) + i - enc->suboff, len);
  lseek(fd, fileoffset, SEEK_SET);
  written += write(fd, encblocks_getbuf(type,enc) + i - enc->suboff, len);
  return written;
}

/* write a log of backup blocks to the disk.  The blocks are in random
 * order, so there is space wasted by not coalescing the changed
 * blocks into bigger entries.  This causes us to write out extra
 * block headers. */
int encblocks_update_backup(EncBlockBufType type, EncBlocks *enc, int fd, int fileoffset){
  int filepos = 0;
  int updated = 0;
  while(uqueue_len(enc->dirty) > 0){
    int written = 0;
    int i = (int)uqueue_dequeue(enc->dirty);
    BackupBlock backup;

    written = encblocks_write_one(i, type, enc, fd, filepos + sizeof(BackupBlock));
    backup.offset = fileoffset + i;
    backup.len = written;

    lseek(fd, filepos, SEEK_SET);
    written += write(fd, &backup, sizeof(BackupBlock));
    
    filepos += written;
    updated++;
  }
  printf_dbg("(%d blocks updated means %d bytes overhead)\n", updated, updated * sizeof(BackupBlock));
  return filepos;
}

/* recompute entire subregion by writing them to fd.
 * if fd == 0, things are recomputed but not written. */
int encblocks_writeall(EncBlockBufType type, EncBlocks *enc, int fd, int fileoffset){
  int written = 0;
  int i;

  for(i = enc->suboff; i < enc->sublen; i += enc->blocksize)
    written += encblocks_write_one(i, type, enc, fd, fileoffset + i);

  return written;
}

/* recompute dirty blocks by getting offsets from queue and writes them to fd. */
int encblocks_update_write(EncBlockBufType type, EncBlocks *enc, int fd, int fileoffset){
  int written = 0;
  while(uqueue_len(enc->dirty) > 0){
    int i = (int)uqueue_dequeue(enc->dirty);
    written += encblocks_write_one(i, type, enc, fd, fileoffset + i);
  }
  return written;
}
