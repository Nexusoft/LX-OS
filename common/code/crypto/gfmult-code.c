/* multiplication in finite field GF(2^128): Z = X * Y*/
/* see lrw-aes draft proposal 1.00:00, Algorithm 1,2 */

#define OPSIZE (16)

static unsigned char p128[] = {0x0, 0x0, 0x0, 0x0,
			      0x0, 0x0, 0x0, 0x0,
			      0x0, 0x0, 0x0, 0x87};

#define CH(i) ((127 - i)/8)
#define MASK(i) (1 << i)
#define BIT(y,i) ((y[CH(i)] & MASK(i % 8)) != 0)

static void op_xor(int opsize, const unsigned char *x, const unsigned char *y, unsigned char *dest){
  int i;
  for(i = 0; i < opsize; i++){
    dest[i] = x[i]^y[i];
  }
}

static void op_rshift(unsigned char *x){
  int i;
  char carry = 0, nextcarry;
  for(i = 0; i < OPSIZE; i++){
    nextcarry = x[i] & 0x1;
    x[i] = (x[i] >> 1);
    if(carry == 1)
      x[i] |= 0x80;
    else
      x[i] &= ~0x80;
    carry = nextcarry;
  }
}

#define TABLESIZE (OPSIZE * 128)
#define TABLE(i) (&gftable[i * OPSIZE])
static unsigned char gftable[TABLESIZE];
static unsigned char kprecomp[OPSIZE];

static void gftable_add(int i, unsigned char *V){
  memcpy(TABLE(i), V, OPSIZE);
}

/* Algorithm 2: kprecomp is the key,
 * Y is the tweak, Z is the result */
static void gfmult_table(const unsigned char *Y, unsigned char *Z){
  int i;
  for(i = 0; i < 128; i++){
    if(BIT(Y,i)){
      op_xor(OPSIZE, Z, TABLE(i), Z);
    }
  }
}

/* Algorithm 1:  C is the key, Y is the tweak, Z is the result*/
void gfmult(const unsigned char *C, const unsigned char *Y, unsigned char *Z){
  unsigned char V[OPSIZE];
  int i;

  memset(Z, 0, OPSIZE);
  
  /* if the intermediate values are kprecomputed, skip to gfmult_table */
  if(memcmp(C, kprecomp, OPSIZE) == 0){
    gfmult_table(Y, Z);
    return;
  }

  memcpy(V, C, OPSIZE);
  memcpy(kprecomp, C, OPSIZE);
  
  for(i = 0; i < 128; i++){
    gftable_add(i, V);
    if(BIT(Y,i))
      op_xor(OPSIZE, Z, V, Z);
    if((V[0] & 0x80) == 0){
      op_rshift(V);
    }else{
      op_rshift(V);
      op_xor(OPSIZE, V, p128, V);
    }
  }
}
