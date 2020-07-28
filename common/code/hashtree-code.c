
#include <nexus/defs.h>	// for PAGESIZE. safe to include in user and kernel

#define DEBUGHT 0
#define DBGHT_OPT 0
#define VERBOSEHT 0

#define HASHSIZE 20

/* optimization in which the initial sha context does not need to be recomputed */
#define SHA1_ctx(s,l,d)						\
  do{								\
    SHA_CTX SHA_CTX_new;					\
    memcpy(&SHA_CTX_new, &initialctx, sizeof(SHA_CTX));         \
    SHA1_Update(&SHA_CTX_new, (s), (l));			\
    SHA1_Final((d), &SHA_CTX_new);				\
  }while(0)
   

enum HT_TIMING{
  TIMING_HT_UPDATE_LEAF = 0,
  TIMING_HT_UPDATE_INNER,
  TIMING_HT_UPDATE_LEAF_SHA,
  TIMING_HT_UPDATE_INNER_SHA,
  TIMING_HT_OPT,
  TIMING_HT_CREATE_INNER,
  TIMING_HT_CREATE_LEAF,
  TIMING_HT_CREATE_SETUP,
  TIMING_HT_CREATE,
  TIMING_HT_CREATE_INNER_SHA,
  TIMING_HT_CREATE_LEAF_SHA,  
  TIMING_HT_CREATE_TODO,
  TIMING_HT_CREATE_BITMAP_ALLOC,
  TIMING_HT_CREATE_BITMAP_MEMSET,

  TIMING_HT_SIZE,
};

struct Timing *httimings = NULL;
void ht_init_timings(void){
  httimings = timing_new_anon(TIMING_HT_SIZE);
}
struct Timing *ht_get_timings(int *numtimings){
  *numtimings = TIMING_HT_SIZE;
  return httimings;
}

SHA_CTX initialctx;
int ctx_done = 0;

/* hashtree attributes */
#define NUMPAGES(ht) ((ht->len + ((unsigned int)ht->reg % PAGESIZE))/PAGESIZE)
#define NUMBLOCKS(h) (((h)->logicalblocks) - ((h)->firstoffset))
#define NUMLEAVES(h) ((h)->leafblocks)

/* converts a logical index into an actual block array index */
#define TOINDEX(h,x) ((x) - ((h)->firstoffset))

/* returns the logical index of a block */
#define BLOCKINDEX_L(h,b) ((int)((((unsigned int)(b)-(unsigned int)((h)->blocks))/(sizeof(Block)))+((h)->firstoffset)))
#define PARENTINDEX_L(h,b) ((h)->logicalblocks - ((h)->logicalblocks - BLOCKINDEX_L(h,b))/2) 
#define SIBLINGINDEX_L(h,b) (((BLOCKINDEX_L(h,b) % 2) == 0)?(BLOCKINDEX_L(h,b)+1):(BLOCKINDEX_L(h,b)-1))
#define LEFTSIBINDEX_L(h,b) (min(BLOCKINDEX_L(h,b),SIBLINGINDEX_L(h,b)))
#define CHILDINDEX_L(h,b) ((h)->logicalblocks - ((h)->logicalblocks - BLOCKINDEX_L(h,b))*2) 
#define LEFTCHILDINDEX_L(h,b) (LEFTSIBINDEX_L(h,BLOCK(h,CHILDINDEX(h,b))))

/* returns the actual index of a block */
#define BLOCKINDEX(h,b) TOINDEX(h,BLOCKINDEX_L(h,b))
#define PARENTINDEX(h,b) TOINDEX(h,PARENTINDEX_L(h,b))
#define SIBLINGINDEX(h,b) TOINDEX(h,SIBLINGINDEX_L(h,b))
#define LEFTSIBINDEX(h,b) TOINDEX(h,LEFTSIBINDEX_L(h,b))
#define CHILDINDEX(h,b) TOINDEX(h,CHILDINDEX_L(h,b))
#define LEFTCHILDINDEX(h,b) TOINDEX(h,LEFTCHILDINDEX_L(h,b))

/* sanity check that something is a block */
#define ISBLOCK(h,b) ((BLOCKINDEX(h,b) >= 0) && (BLOCKINDEX(h,b) < NUMBLOCKS(h)))

/* sibling/parent relationships on blocks*/
#define PARENT(h,b) (&(h)->blocks[PARENTINDEX(h,b)])
#define SIBLING(h,b) (&(h)->blocks[SIBLINGINDEX(h,b)])
#define LEFTSIB(h,b) (&(h)->blocks[LEFTSIBINDEX(h,b)])
#define LEFTCHILD(h,b) (&(h)->blocks[LEFTCHILDINDEX(h,b)])

/* get the region and size that a leaf block is pointing to */
#define DATAPTR(h,b) (((h)->reg) + (BLOCKINDEX(h,b) * (h)->blocksize))
#define DATADIFF(h,b) (((h)->len) - (BLOCKINDEX(h,b) * (h)->blocksize))
#define DATASIZE(h,b) (min(DATADIFF(h,b),(h)->blocksize))

/* get block from blocknum.  BLOCK(h,0) = is the first block */
#define BLOCK(h,i) (&(((h)->blocks)[i]))

/* special types of blocks */
#define LEAFNODE(h,b) (BLOCKINDEX(h,b) < ((h)->leafblocks))
#define SECONDLEVELLEAF(h,b) (LEAFNODE(h,b) && (BLOCKINDEX_L(h,b) >= (((h)->logicalblocks + 1)/2)))
#define ROOTNODE(h,b) (BLOCKINDEX_L(h,b) == ((h)->logicalblocks - 1))

/* check if a block has been touched or not by using the bitmap */
#define TOUCHED(h,b) (((h)->bitmap[BLOCKINDEX((h),(b))/8] & (1 << (7 - (BLOCKINDEX((h),(b)) % 8)))) != 0)
#define UNTOUCHED(h,b) (!TOUCHED(h,b))
#define TOUCH(h,b) do{							\
    assert(BLOCKINDEX((h),(b))/8 < (h)->bitmapsize);		\
    (h)->bitmap[BLOCKINDEX((h),(b))/8] |= (1 << (7 - (BLOCKINDEX((h),(b)) % 8)));}while(0)
#define UNTOUCH(h,b) do{(h)->bitmap[BLOCKINDEX((h),(b))/8] &= ~(1 << (7 - (BLOCKINDEX((h),(b)) % 8)));}while(0)

/* get the data pointer and size, hash the block */
#define UPDATELEAF(h,b)							\
  do{									\
    timing_start(httimings, TIMING_HT_UPDATE_LEAF);			\
    timing_start(httimings, TIMING_HT_UPDATE_LEAF_SHA);			\
    if(DEBUGHT)printf("hashing %d bytes from 0x%p to 0x%p\n", DATASIZE((h),(b)),DATAPTR((h),(b)),DATAPTR((h),(b))+DATASIZE((h),(b))); \
    SHA1_ctx(DATAPTR((h), (b)), DATASIZE((h),(b)), (b)->hash);		\
    timing_end(httimings, TIMING_HT_UPDATE_LEAF_SHA);			\
    timing_end(httimings, TIMING_HT_UPDATE_LEAF);			\
  }while(0)

#define UPDATEINNER(h,b)						\
  do{									\
    timing_start(httimings, TIMING_HT_UPDATE_INNER_SHA);		\
    SHA1_ctx(LEFTSIB((h),(b)), 2 * HASHSIZE, PARENT((h),(b))->hash);	\
    timing_end(httimings, TIMING_HT_UPDATE_INNER_SHA);			\
  }while(0)

typedef struct BlockList BlockList; 
typedef struct Block Block;
struct Block{
  unsigned char hash[HASHSIZE];
};
struct BlockList{
  Block **list;
  int size;
  int tail;
  int head;
};

/* XXX move this stuff outside hashtree; it shouldn't need to know */
typedef enum HT_TYPE HT_TYPE;
enum HT_TYPE{
  HT_DIRTY_BITMAP = 1,
  XXXHT_MAPPED_BITMAP,
  XXXHT_DIRECT_BITMAP,
};

struct Hashtree{
  unsigned char *reg;
  int len;
  int blocksize;
  int leafblocks;
  int logicalblocks;
  int firstoffset;
  Block *root;
  Block *blocks;
  BlockList *todolevel1;
  BlockList *todolist;
  int bitmapsize;
  unsigned char *bitmap;
  char *nxcompat_allocedbuf;
  char **dirtypgs;
  HT_TYPE type;
};

int fastlog_2(int x){
  int i;
  for(i = 31; i >=0; i--){
    if((x & (1 << i)) != 0)
      return i;
  }
  return 0;
}
int fastpow_2(int x){
  if(x == 0)
    return 1;
  return (1 << x);
}

#define todo_asserts(l)				\
  assert(l->tail < l->size);			\
  assert(l->tail >= 0);				\
  assert(l->head < l->size);			\
  assert(l->head >= 0);
  

/* a queue for the blocks left to compute */
void todo_enqueue(BlockList *l, Block *new){
  int newtail;
  todo_asserts(l);

  l->list[l->tail] = new;
  newtail = (l->tail + 1) % l->size; 
  if(newtail == l->head){
    printf("BlockList is fuller than it should be!");
    assert(0);
  }
  l->tail = newtail;
}
Block *todo_dequeue(BlockList *l){
  Block *ret;
  todo_asserts(l);

  if(l->head == l->tail)
    return NULL;
  ret = l->list[l->head];
  l->head = (l->head + 1) % l->size; 
  return ret;
}
BlockList *todo_create(int listsize){
  BlockList *new;
  new = (BlockList *)nxcompat_alloc(sizeof(BlockList));
  new->size = listsize + 1;
  new->tail = new->head = 0;
  new->list = (Block **)nxcompat_alloc(sizeof(unsigned int) * new->size);

  todo_asserts(new);

  return new;
}
void todo_destroy(BlockList *l){
  nxcompat_free(l->list);
  nxcompat_free(l);
}
Block *todo_head(BlockList *l){
  todo_asserts(l);
  if(l->head == l->tail)
    return NULL;
  return l->list[l->head];
}
int todo_isempty(BlockList *l){
  todo_asserts(l);
  if(l->head == l->tail)
    return 1;
  return 0;
}
int todo_sanity_check(BlockList *l){
  int i = l->head;
  int count = 0;
  while(i != l->tail){
    count++;
    i = (i + 1) % l->size; 
    assert(count <= l->size + 2);
  }
  return count;
}

unsigned char *ht_get_root(Hashtree *ht){
  int dbg = 0;
  if(dbg)
    printf("root: %02x %02x %02x %02x %02x %02x\n", ht->root->hash[0], ht->root->hash[1], ht->root->hash[2], ht->root->hash[3], ht->root->hash[4], ht->root->hash[5]);
  return ht->root->hash;
}

int dbgblocknum;

/* Mark the bits in the bitmap that correspond to blocks between addr
 * and len and add the leaves to the todolist */
void ht_set_bitmap(Hashtree *ht, unsigned char *addr, int len){
  int numblocks, blocknum, i;
  int offset;
  int dbg = 0;

  if(DEBUGHT)
    dbg = 1;

  if(dbg){
    printf("reg=0x%p len=%d bs=%d leafs=%d logical=%d first=%d\n",
	   ht->reg, ht->len, ht->blocksize, ht->leafblocks, 
	   ht->logicalblocks, ht->firstoffset);
  }

  addr = (char*)max((unsigned int)addr,(unsigned int)ht->reg);
  if(dbg)printf("HT: setting %d bytes at 0x%p as marked..", len, addr);

  offset = ((unsigned int)addr - (unsigned int)ht->reg) % ht->blocksize;
  blocknum = ((((unsigned int)addr - (unsigned int)ht->reg) - offset) / ht->blocksize);
  numblocks = (len + offset + ht->blocksize - 1) / ht->blocksize;

  if(dbg)printf("setting %d blocks at blocknum %d of %d ", numblocks, blocknum, NUMBLOCKS(ht));
  
  int dbgtouchnum = 0;
  int dbgleaftouchnum = 0;
  for(i = blocknum; i < blocknum + numblocks; i++){

    /* only enqueue if not already in todolist */
    if(UNTOUCHED(ht,BLOCK(ht,i))){
      if(SECONDLEVELLEAF(ht,BLOCK(ht,i)))
	 todo_enqueue(ht->todolist, BLOCK(ht, i));
      else
	 todo_enqueue(ht->todolevel1, BLOCK(ht, i));
      dbgtouchnum++;
      if(LEAFNODE(ht,BLOCK(ht,i)))
	dbgleaftouchnum++;
      TOUCH(ht,BLOCK(ht,i));
    }
  }
  if(dbg)printf("%d actually touched (%d leaves)\n", dbgtouchnum, dbgleaftouchnum);

  if(dbg){
    int sanity_count, i, marked=0;
    sanity_count = todo_sanity_check(ht->todolist);
    printf("sanity checked todolist %d totalsize %d\n", sanity_count, ht->todolist->size);
    sanity_count = todo_sanity_check(ht->todolevel1);
    printf("sanity checked todolevel1 %d totalsize %d\n", sanity_count, ht->todolevel1->size);

    for(i = 0; i < ht->bitmapsize; i++)
      if(ht->bitmap[i] != 0)
	marked++;
    printf("%d now marked\n", marked);
  }

  dbgblocknum = blocknum;
}

    
int dbgleavestouched = 0;
int dbginnertouched = 0;

void ht_update_block(Hashtree *ht, Block *b){
  Block *sib;
  int dbg = 0;

  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

  /* check if this node has already been computed when computing the sibling */
  if(UNTOUCHED(ht,b))
    return;

  if(LEAFNODE(ht,b)){
    UPDATELEAF(ht,b);
    dbgleavestouched++;	
  }
  
  /* mark this block as done */
  UNTOUCH(ht,b);

  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

  if(ROOTNODE(ht,b)){
    if(!(todo_isempty(ht->todolevel1) && todo_isempty(ht->todolist))){
      printf("more nodes on todo!\n");
      assert(0);
    }
    return;
  }

  /* do inner hash with sibling */
  sib = SIBLING(ht,b);

  if(TOUCHED(ht,sib)){
    if(LEAFNODE(ht,sib)){
      UPDATELEAF(ht,sib);    
      dbgleavestouched++;	
    }
    /* mark sibling as done */
    UNTOUCH(ht,sib);
  }
  
  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

  /* inner hash is only done once even if both siblings are touched
   * because we marked the sibling as done. */
  timing_start(httimings, TIMING_HT_UPDATE_INNER);		

  UPDATEINNER(ht,b);

  TOUCH(ht,PARENT(ht,b));
  todo_enqueue(ht->todolist, PARENT(ht,b));			
  dbginnertouched++;					

  todo_sanity_check(ht->todolist);

  timing_end(httimings, TIMING_HT_UPDATE_INNER);			
}


/* If we are using the dirty bits on pages, we fill in the bitmap on
 * update.  In the other two cases, the bitmap is being set in the
 * user-level page fault handler, or on a direct function call.
 */
unsigned char *ht_update_hashtree(Hashtree *ht){
  Block *b;
  int dbg = 0;

  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

  if(ht->type == HT_DIRTY_BITMAP){
    int i = 0;
    /* XXX move ht->type completely out of hashtree.c.  it doesn't need to know */
    /* XXX where did this library call go? */
    //get_region_dirtylist(ht->dirtypgs, ht->reg, ht->len);
    while(ht->dirtypgs[i] != NULL){
      ht_set_bitmap(ht, ht->dirtypgs[i], PAGESIZE);
    }
  }

  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

  dbgleavestouched = 0;
  dbginnertouched = 0;

  /* Look through level 1 of the tree and add nodes to main todolist.
   * Level 1 is separate because some leaves are at level 2, causing a
   * possibility for a path to be computed once for a level 2 leaf,
   * then again for a nearby level 1 leaf.  */
  while((b = todo_dequeue(ht->todolevel1)) != NULL){
    ht_update_block(ht,b);
  }

  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

  /* Now that all nodes in the todolist (some leaves, some inner) are at level
   * 2, we won't compute any nodes twice */
  while((b = todo_dequeue(ht->todolist)) != NULL){
    ht_update_block(ht,b);
  }
  
  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

  if(DEBUGHT)printf("%d leaves updated, %d inner touched\n", dbgleavestouched, dbginnertouched);

  return ht_get_root(ht);
}


/* dump the hashtree as a graphical .dot file.  only useful for small hashtrees */
void dump_ht_dot(Hashtree *ht, char *filename){
  extern int writefile(char *filename, char *buffer, int size);
  Block *b, *x;
  int i;
  char *buffer;
  int off = 0;
  
  printf("DUMPING HT DOT %s...", filename);

  buffer = (char *)nxcompat_alloc(ht->len * 4);
  off += sprintf(buffer + off, "digraph ht {\n\tsize=\"6,6\";\n\tnode [color=lightblue2, style=filled];\n\t");

  for(i = 0; i < ht->logicalblocks - ht->firstoffset; i++){
    x = b = BLOCK(ht,i);

    if(i == ht->logicalblocks - ht->firstoffset -1){
      off += sprintf(buffer+off, "\"0x%p: %02x %02x %02x %02x ...\"%s;\n\t", 
		     x, x->hash[0], x->hash[1], x->hash[2], x->hash[3],
		     (((ht->bitmap[i/8] & (1 << (7 - (i % 8)))) != 0)?"[color=salmon2]":""));
      break;
    }
    
    if(LEAFNODE(ht,b)){
      off += sprintf(buffer+off, "\"%d: [0x%p - 0x%p] %02x %02x %02x %02x ...\"%s;\n\t", 
		     i , ht->reg + i*ht->blocksize, ht->reg + (i+1)*ht->blocksize,
		     b->hash[0], b->hash[1], b->hash[2], b->hash[3],
		     (((ht->bitmap[i/8] & (1 << (7 - (i % 8)))) != 0)?"[color=salmon2]":""));

      off += sprintf(buffer+off, "\"%d: [0x%p - 0x%p] %02x %02x %02x %02x ...\" -> \"0x%p: %02x %02x %02x %02x ...\";\n\t", 
		     i , ht->reg + i*ht->blocksize, ht->reg + (i+1)*ht->blocksize,
		     b->hash[0], b->hash[1], b->hash[2], b->hash[3],
		     PARENT(ht,x), PARENT(ht,x)->hash[0], PARENT(ht,x)->hash[1], PARENT(ht,x)->hash[2], PARENT(ht,x)->hash[3]);
    }else{
      off += sprintf(buffer+off, "\"0x%p: %02x %02x %02x %02x ...\"%s;\n\t", 
		     b, b->hash[0], b->hash[1], b->hash[2], b->hash[3],
		     (((ht->bitmap[i/8] & (1 << (7 - (i % 8)))) != 0)?"[color=salmon2]":""));
      off += sprintf(buffer+off, "\"0x%p: %02x %02x %02x %02x ...\" -> \"0x%p: %02x %02x %02x %02x ...\";\n\t", 
		     x, x->hash[0], x->hash[1], x->hash[2], x->hash[3],
		     PARENT(ht,x), PARENT(ht,x)->hash[0], PARENT(ht,x)->hash[1], PARENT(ht,x)->hash[2], PARENT(ht,x)->hash[3]);
    }
  }
  off+=sprintf(buffer+off, "}\n");
  writefile(filename, buffer, off);
  printf("done dump.\n");
}

static inline int calc_lognum(int leafblocks){
  int lognum = fastlog_2(leafblocks) + 1;
  lognum = fastpow_2(lognum);
  if(lognum < leafblocks)
    lognum *=2;
  return lognum;
}

#define CALC_LEAFBLOCKS(l,b) ((l + b - 1)/b)
#define CALC_LOGNUM(l) calc_lognum(l)
#define CALC_FIRSTOFFSET(l) (2 * (CALC_LOGNUM(l) - (l)))
#define CALC_LOGICAL(l) (2 * CALC_LOGNUM(l) - 1)

int ht_get_size(int len, int blocksize){
  if(DEBUGHT)printf("getting size %d bs %d\n", len, blocksize);
  if(len == 0)
    return 0;
  if(blocksize == 0){
    printf("can't have a blocksize of 0!!");
    return -1;
  }
  int leafblocks = CALC_LEAFBLOCKS(len, blocksize);
  int numblocks = CALC_LOGICAL(leafblocks) - CALC_FIRSTOFFSET(leafblocks);
  return numblocks * HASHSIZE;
}

/* round a suboffset, sublen to block boundaries */
void ht_round_to_block(int blocksize, int *suboff, int *sublen){
  int blockoff;
  if(DEBUGHT)
  printf("blocksize=%d, suboff=%d, sublen=%d\n", blocksize, *suboff, *sublen);

  /* round suboff down */
  blockoff = *suboff % blocksize;
  *suboff -= blockoff;
  *sublen += blockoff;

  if(DEBUGHT)
  printf("blockoff=%d, suboff=%d, sublen=%d\n", blockoff, *suboff, *sublen);

  /* round sublen up */
  blockoff = (*suboff + *sublen) % blocksize;
  if(blockoff != 0)
    *sublen += blocksize - blockoff;

  if(DEBUGHT)
  printf("blockoff=%d, suboff=%d, sublen=%d\n", blockoff, *suboff, *sublen);
}

/* create a hashtree for reg and place in internal buf */
Hashtree *ht_create_hashtree(unsigned char *reg, int len, int blocksize){
  int size = ht_get_size(len, blocksize);
  char *buf;
  Hashtree *ht;

  blocksize = min(blocksize, len);
  buf = (char *)nxcompat_alloc(size);

  ht = ht_create_hashtree_to_buf(reg, len, blocksize, buf, &size);
  ht->nxcompat_allocedbuf = buf;

  return ht;
}

/* create a hashtree for region and put in buf */
Hashtree *ht_create_hashtree_to_buf(unsigned char *reg, int len, 
				    int blocksize,
				    unsigned char *buf, int *buflen){
  Hashtree *new;
  int lognum;
  int dbg = 0;

  if(DEBUGHT)
    dbg = 1;

  if(ctx_done == 0)
    SHA1_Init(&initialctx);
  
  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

  timing_start(httimings, TIMING_HT_CREATE_SETUP);
  
  blocksize = min(blocksize, len);

  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

  new = (Hashtree *)nxcompat_alloc(sizeof(Hashtree));

  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

  new->reg = reg;
  new->len = len;
  new->blocksize = blocksize;
  //XXX 
  new->type = XXXHT_MAPPED_BITMAP;
  new->nxcompat_allocedbuf = NULL;
  
  if(dbg)printf("new hashtree 0x%p: reg=0x%p, len=%d, blocksize=%d\n", new, new->reg, len, blocksize);

  new->leafblocks = CALC_LEAFBLOCKS(len, blocksize);
  new->firstoffset = CALC_FIRSTOFFSET(new->leafblocks);
  new->logicalblocks = CALC_LOGICAL(new->leafblocks);

  if(dbg)printf("firstoffset=%d, logicalblocks=%d\n", new->firstoffset, new->logicalblocks);
  if(dbg)printf("len=%d, blocksize=%d, numblocks=%d leafblocks=%d\n", len, blocksize, NUMBLOCKS(new), new->leafblocks);

  if(*buflen < ht_get_size(len, blocksize)){
    printf("Not enough space in supplied buffer for hashtree\n");
    return NULL;
  }
  *buflen = ht_get_size(len, blocksize);

  new->blocks = (Block *)buf;

  timing_start(httimings, TIMING_HT_CREATE_TODO);
  lognum = CALC_LOGNUM(new->leafblocks);
  new->todolevel1 = todo_create(lognum - new->firstoffset + 1);
  new->todolist = todo_create(lognum / 2 + 1);
  timing_end(httimings, TIMING_HT_CREATE_TODO);
  new->bitmapsize = (NUMBLOCKS(new) + 7)/8;
  new->root = NULL;

  if(new->type == HT_DIRTY_BITMAP)
    new->dirtypgs = (char**)nxcompat_alloc(NUMPAGES(new));


  timing_start(httimings, TIMING_HT_CREATE_BITMAP_ALLOC);
  new->bitmap = (unsigned char *)nxcompat_alloc(new->bitmapsize * sizeof(unsigned char));
  timing_end(httimings, TIMING_HT_CREATE_BITMAP_ALLOC);

  new->root = BLOCK(new, NUMBLOCKS(new) - 1);

  timing_end(httimings, TIMING_HT_CREATE_SETUP);
  
  return new;
}

/* build a hashtree from a subsection of a memory region */
int ht_build_hashtree(Hashtree *new, int suboffset, int sublen){
  Block *b;
  int startoff, stopoff, startindex, stopindex;

  int leafhashed =0, innerhashed = 0;
  int leaftotalhashed = 0;
  int numblocks;

  int i;
  int dbg = 0, dbg_lots = 0;

  if(VERBOSEHT)
    dbg = 1;

  if(sublen <= 0)
    return -1;
  
  timing_start(httimings, TIMING_HT_CREATE);

  if(dbg)printf("new=0x%p firstoffset=%d, logicalblocks=%d\n", new, new->firstoffset, new->logicalblocks);

  startoff = suboffset % new->blocksize;
  stopoff = (new->blocksize - (suboffset + sublen) % new->blocksize) % new->blocksize;
  startindex = (suboffset - startoff)/new->blocksize;
  stopindex = (suboffset + sublen + stopoff)/new->blocksize;

  numblocks = stopindex - startindex;
  if(dbg)printf("suboffset=%d sublen=%d startindex=%d stopindex=%d\n", suboffset, sublen, startindex, stopindex);

  /* leaf hashes */
  timing_start(httimings, TIMING_HT_CREATE_LEAF);
  timing_start(httimings, TIMING_HT_CREATE_LEAF_SHA);

  /* initialize bitmap for leaves.  Make sure the siblings are also initialized as
   * untouched so we don't try and compute them later. */
  Block *startb = BLOCK(new,startindex);
  Block *stopb = BLOCK(new,stopindex);
  int startzero = min(BLOCKINDEX(new,startb),SIBLINGINDEX(new,startb))/8;
  int endzero = max(BLOCKINDEX(new,stopb),SIBLINGINDEX(new,stopb))/8;
  if(dbg)
    printf("startzero=%d endzero=%d blocks=%d leaves=%d endzero-startzero=%d\n", startzero, endzero, (NUMBLOCKS(new)+7)/8, NUMLEAVES(new), endzero-startzero);
  memset(new->bitmap + startzero, 0, endzero - startzero + 1);

  if(dbg_lots)printf("leaves:");
  /* Go straight through the leaves hashing them in order.  Each leaf
   * gets hashed exactly once. */
  for(i = startindex; i < stopindex; i++){
    b = BLOCK(new,i);
    assert((DATAPTR(new,b) >= new->reg) && (DATAPTR(new,b) < new->reg + new->len));
    assert((BLOCKINDEX(new,b) >= 0) && (BLOCKINDEX(new,b) < NUMBLOCKS(new)));
  
    SHA1_ctx(DATAPTR(new,b), DATASIZE(new,b), b->hash);
    //UNTOUCH(new,b);

    if(dbg_lots)printf("(%d->%02x %02x)",BLOCKINDEX(new,b),b->hash[0],b->hash[1]);
    if(dbg_lots)printf("hashing leaf=%d actual=%d dataptr=0x%p datasize=%d\n", BLOCKINDEX(new,BLOCK(new,i)), i, DATAPTR(new,BLOCK(new,i)), DATASIZE(new,BLOCK(new,i)));
    leaftotalhashed += DATASIZE(new,b);
    leafhashed++;
  }
  if(dbg_lots)printf("\n");
  
  timing_end(httimings, TIMING_HT_CREATE_LEAF_SHA);
  timing_end(httimings, TIMING_HT_CREATE_LEAF);
  
  /* inner hashes*/
  timing_start(httimings, TIMING_HT_CREATE_INNER);
  timing_start(httimings, TIMING_HT_CREATE_INNER_SHA);
  
  if(dbg_lots)printf("hashing:");
  while(startindex < BLOCKINDEX(new, new->root)){
    for(i = startindex; i <= stopindex;){
      b = LEFTSIB(new, BLOCK(new,i));

      innerhashed++;
      SHA1_ctx(b, HASHSIZE * 2, PARENT(new,b)->hash);
      UNTOUCH(new,PARENT(new,b));
      i = BLOCKINDEX(new, b) + 2;

      if(dbg_lots)printf("(%d,%d->%02x %02x)",BLOCKINDEX(new,b),BLOCKINDEX(new,b) + 1,PARENT(new,b)->hash[0],PARENT(new,b)->hash[1]);
    }
    /* Some parent blocks may have already been hashed as siblings,
     * but we can tell because all blocks with index < i have already
     * been hashed */
    startindex = max(PARENTINDEX(new, BLOCK(new,startindex)),i);
    stopindex = PARENTINDEX(new, BLOCK(new,stopindex));
  }
  if(dbg_lots)printf("\n");

  timing_end(httimings, TIMING_HT_CREATE_INNER_SHA);
  timing_end(httimings, TIMING_HT_CREATE_INNER);

  if(dbg)printf("numblocks=%d leafhashed=%d innerhashed=%d leaftotalhashed=%d\n", leafhashed, innerhashed, leaftotalhashed, numblocks);
  if(NUMBLOCKS(new) != 1)
    assert(leafhashed == numblocks);

  assert(new->root != NULL);
  if(dbg)printf("root: %02x %02x %02x %02x %02x %02x\n", new->root->hash[0], new->root->hash[1], new->root->hash[2], new->root->hash[3], new->root->hash[4], new->root->hash[5]);

  timing_end(httimings, TIMING_HT_CREATE);

  return 0;
}

void ht_destroy_hashtree(Hashtree *ht){
  todo_destroy(ht->todolevel1);
  todo_destroy(ht->todolist);
  if(ht->nxcompat_allocedbuf != NULL)
    nxcompat_free(ht->nxcompat_allocedbuf);
  nxcompat_free(ht->bitmap);
  nxcompat_free(ht);
}
