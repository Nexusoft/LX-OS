/****************************************************************************/
/*                                                                          */
/*               TPM Specific HMAC routines                                 */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/
#include <nexus/defs.h>
#include <libtcpa/tcpa.h>
#include <libtcpa/hmac.h>

typedef char SHA1CTX[100]; // XXX hack - egs
typedef char HMAC_CTX[800]; // XXX hack -egs

/****************************************************************************/
/*                                                                          */
/* Validate the HMAC in an AUTH1 response                                   */
/*                                                                          */
/* This function validates the Authorization Digest for all AUTH1           */
/* responses.                                                               */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* buffer - a pointer to response buffer                                    */
/* command - the command code from the original request                     */
/* ononce - a pointer to a 20 byte array containing the oddNonce            */
/* key    - a pointer to the key used in the request HMAC                   */
/* keylen - the size of the key                                             */
/* followed by a variable length set of arguments, which must come in       */
/* pairs.                                                                   */
/* The first value in each pair is the length of the data in the second     */
/*   argument of the pair                                                   */
/* The second value in each pair is an offset in the buffer to the data     */
/*   to be included in the hash for the paramdigest                         */
/* There should NOT be pairs for the TCPA_RESULT or TCPA_COMMAND_CODE       */
/* The last pair must be followed by a pair containing 0,0                  */
/*                                                                          */
/****************************************************************************/
int checkhmac1(unsigned char *buffer, uint32_t command,
               unsigned char *ononce, unsigned char *key, int keylen, ...)
{
    uint32_t bufsize;
    uint16_t tag;
    uint32_t ordinal;
    uint32_t result;
    unsigned char *enonce;
    unsigned char *continueflag;
    unsigned char *authdata;
    unsigned char testhmac[20];
    unsigned char paramdigest[20];
    SHA1CTX sha;
    unsigned int dlen;
    unsigned int dpos;
    va_list argp;

    bufsize = htonl(*(uint32_t *) (buffer + 2));
    tag = htons(*(uint16_t *) (buffer + 0));
    ordinal = ntohl(command);
    result = *(uint32_t *) (buffer + TCPA_RETURN_OFFSET);

    if (tag == TPM_TAG_RSP_COMMAND)
      return 0;
    if (tag == TPM_TAG_RSP_AUTH1_COMMAND || tag == TPM_TAG_RSP_AUTH2_COMMAND){
      sha1_init(&sha);
      sha1_update(&sha, (unsigned char *)&result, 4);
      sha1_update(&sha, (unsigned char *)&ordinal, 4);
      va_start(argp, keylen);
      for (;;) {
        dlen = (unsigned int) va_arg(argp, unsigned int);
        if (dlen == 0)
	  break;
        dpos = (unsigned int) va_arg(argp, unsigned int);
        sha1_update(&sha, buffer + dpos, dlen);
      }
      va_end(argp);
      sha1_final(&sha, paramdigest);

      /* check first hmac */
      authdata = buffer + bufsize - TCPA_HASH_SIZE;
      continueflag = authdata - 1;
      enonce = continueflag - TCPA_NONCE_SIZE;
      rawhmac(testhmac, key, keylen, TCPA_HASH_SIZE, paramdigest,
	      TCPA_NONCE_SIZE, enonce,
	      TCPA_NONCE_SIZE, ononce, 1, continueflag, 0, 0);
      if (memcmp(testhmac, authdata, dlen) != 0)
        return -1;
      return 0;
    }
    return -1;
}
int checkhmac2(unsigned char *buffer, uint32_t command,
               unsigned char *ononce, /* XXX do we need two ononces? */
	       unsigned char *key, int keylen, 
	       unsigned char *key2, int keylen2, ...)
{
    uint32_t bufsize;
    uint16_t tag;
    uint32_t ordinal;
    uint32_t result;
    unsigned char *enonce;
    unsigned char *continueflag;
    unsigned char *authdata;
    unsigned char testhmac[20];
    unsigned char paramdigest[20];
    SHA1CTX sha;
    unsigned int dlen;
    unsigned int dpos;
    va_list argp;

    bufsize = htonl(*(uint32_t *) (buffer + 2));
    tag = htons(*(uint16_t *) (buffer + 0));
    ordinal = ntohl(command);
    result = *(uint32_t *) (buffer + TCPA_RETURN_OFFSET);

    if (tag == TPM_TAG_RSP_COMMAND)
      return 0;
    if (tag == TPM_TAG_RSP_AUTH1_COMMAND || tag == TPM_TAG_RSP_AUTH2_COMMAND){
      sha1_init(&sha);
      sha1_update(&sha, (unsigned char *)&result, 4);
      sha1_update(&sha, (unsigned char *)&ordinal, 4);
      va_start(argp, keylen2);
      for (;;) {
        dlen = (unsigned int) va_arg(argp, unsigned int);
        if (dlen == 0)
	  break;
        dpos = (unsigned int) va_arg(argp, unsigned int);
        sha1_update(&sha, buffer + dpos, dlen);
      }
      va_end(argp);
      sha1_final(&sha, paramdigest);

      /* check first hmac */
      authdata = buffer + bufsize - TCPA_HASH_SIZE;
      continueflag = authdata - 1;
      enonce = continueflag - TCPA_NONCE_SIZE;
      rawhmac(testhmac, key, keylen, TCPA_HASH_SIZE, paramdigest,
	      TCPA_NONCE_SIZE, enonce,
	      TCPA_NONCE_SIZE, ononce, 1, continueflag, 0, 0);
      if (memcmp(testhmac, authdata, dlen) != 0)
        return -1;

      if (tag == TPM_TAG_RSP_AUTH1_COMMAND)
	return 0;

      /* check second hmac */
      authdata = buffer + bufsize - 3*TCPA_HASH_SIZE -1;
      continueflag = authdata - 1;
      enonce = continueflag - TCPA_NONCE_SIZE;
      rawhmac(testhmac, key2, keylen2, TCPA_HASH_SIZE, paramdigest,
	      TCPA_NONCE_SIZE, enonce,
	      TCPA_NONCE_SIZE, ononce, 1, continueflag, 0, 0);
      if (memcmp(testhmac, authdata, dlen) != 0)
        return -1;

      return 0;
    }
    return -1;
}

/****************************************************************************/
/*                                                                          */
/* Calculate HMAC value for an AUTH1 command                                */
/*                                                                          */
/* This function calculates the Authorization Digest for all OIAP           */
/* commands.                                                                */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* digest - a pointer to a 20 byte array that will receive the result       */
/* key    - a pointer to the key to be used in the HMAC calculation         */
/* keylen - the size of the key in bytes                                    */
/* h1     - a pointer to a 20 byte array containing the evenNonce           */
/* h2     - a pointer to a 20 byte array containing the oddNonce            */
/* h3     - an unsigned character containing the continueAuthSession value  */
/* followed by a variable length set of arguments, which must come in       */
/* pairs.                                                                   */
/* The first value in each pair is the length of the data in the second     */
/*   argument of the pair                                                   */
/* The second value in each pair is a pointer to the data to be hashed      */
/*   into the paramdigest.                                                  */
/* The last pair must be followed by a pair containing 0,0                  */
/*                                                                          */
/****************************************************************************/
int authhmac(unsigned char *digest, unsigned char *key,
             unsigned int keylen, unsigned char *h1, unsigned char *h2,
             unsigned char h3, ...)
{
    unsigned char paramdigest[TCPA_HASH_SIZE];
    SHA1CTX sha;
    unsigned int dlen;
    unsigned char *data;
    unsigned char c;

    va_list argp;

    sha1_init(&sha);
    if (h1 == NULL || h2 == NULL)
        return -1;
    c = h3;
    va_start(argp, h3);
    for (;;) {
        dlen = (unsigned int) va_arg(argp, unsigned int);
        if (dlen == 0)
            break;
        data = (unsigned char *) va_arg(argp, int);
        if (data == NULL)
            return -1;
        sha1_update(&sha, data, dlen);
    }
    va_end(argp);
    sha1_final(&sha, paramdigest);
    rawhmac(digest, key, keylen, TCPA_HASH_SIZE, paramdigest,
            TCPA_NONCE_SIZE, h1, TCPA_NONCE_SIZE, h2, 1, &c, 0, 0);
    return 0;
}


/****************************************************************************/
/*                                                                          */
/* Calculate Raw HMAC value                                                 */
/*                                                                          */
/* This function calculates an HMAC digest                                  */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* digest - a pointer to a 20 byte array that will receive the result       */
/* key    - a pointer to the key to be used in the HMAC calculation         */
/* keylen - the size of the key in bytes                                    */
/* followed by a variable length set of arguments, which must come in       */
/* pairs.                                                                   */
/* The first value in each pair is the length of the data in the second     */
/*   argument of the pair                                                   */
/* The second value in each pair is a pointer to the data to be hashed      */
/*   into the paramdigest.                                                  */
/* The last pair must be followed by a pair containing 0,0                  */
/*                                                                          */
/****************************************************************************/
#define HMAC_BLOCKSIZE 64

int rawhmac(unsigned char *digest, unsigned char *key,
            unsigned int keylen, ...)
{
    SHA1CTX shain, shaout;
    unsigned int dlen;
    unsigned char *data;
    unsigned char mykey[HMAC_BLOCKSIZE];
    unsigned char mypad[HMAC_BLOCKSIZE];
    unsigned char scratch[HMAC_BLOCKSIZE];
    int i;
    va_list argp;

    sha1_init(&shain);
    sha1_init(&shaout);

    memset(mykey, 0, HMAC_BLOCKSIZE);
    memcpy(mykey, key, keylen);

    for (i=0; i<HMAC_BLOCKSIZE; i++)
      mypad[i] = 0x36 ^ mykey[i];
    sha1_update(&shain, mypad, HMAC_BLOCKSIZE);

    for (i=0; i<HMAC_BLOCKSIZE; i++)
      mypad[i] = 0x5c ^ mykey[i];
    sha1_update(&shaout, mypad, HMAC_BLOCKSIZE);

    va_start(argp, keylen);
    for (;;) {
        dlen = (unsigned int) va_arg(argp, unsigned int);
        if (dlen == 0)
            break;
        data = (unsigned char *) va_arg(argp, int);
        if (data == NULL)
            return -1;
	sha1_update(&shain, data, dlen);
    }
    sha1_final(&shain, scratch);
    sha1_update(&shaout, scratch, TCPA_HASH_SIZE); 
    sha1_final(&shaout, digest);
    va_end(argp);
    return 0;
}

/****************************************************************************/
/*                                                                          */
/* Perform a SHA1 hash on a single buffer                                   */
/*                                                                          */
/****************************************************************************/

void sha1(unsigned char *buffer, int len, unsigned char *hash) {
  SHA1CTX ctx;
  
  sha1_init(&ctx);
  sha1_update(&ctx, buffer, len);
  sha1_final(&ctx, hash);
}
