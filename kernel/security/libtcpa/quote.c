/****************************************************************************/
/*                                                                          */
/*                           TCPA Signature Routines                        */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/
#include <nexus/defs.h>
#include <libtcpa/tcpa.h>
#include <libtcpa/hmac.h>
#include <libtcpa/oiaposap.h>
#include <libtcpa/buildbuff.h>

/****************************************************************************/
/*                                                                          */
/* Sign some data                                                           */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the TCPA_KEY_HANDLE of the key to sign with                 */
/* keyauth   is the authorization data (password) for the parent key        */
/* data      is a pointer to the data to be signed                          */
/* datalen   is the length of the data being signed                         */
/* sig       is a pointer to an area to receive the signature (<=256 bytes) */
/* siglen    is a pointer to an integer to receive the signature length     */
/*                                                                          */
/****************************************************************************/
unsigned char quotedata[TCPA_MAX_BUFF_SIZE];

uint32_t TPM_Quote(uint32_t keyhandle, unsigned char *keyauth,
		   unsigned short pcrmap,
		   unsigned char *data,
		   unsigned char *sig, unsigned int *siglen,
		   unsigned char *pcrResult, unsigned int *pcrlen)
{
    unsigned char quote_fmt[] = "00 c2 T l l % % % l % o %";
    unsigned char c;
    uint32_t ordinal;
    uint32_t keyhndl;
    uint32_t authhandle;
    uint32_t datasize;
    uint32_t ret;
    unsigned char nonceodd[TCPA_NONCE_SIZE];
    unsigned char evennonce[TCPA_NONCE_SIZE];
    unsigned char pubauth[TCPA_HASH_SIZE];
    unsigned short pcrsize;

    TPMPCRComposite *p;
    unsigned int *sigsizeptr;
    unsigned int sigsize;
    unsigned char *recvsig;
    unsigned int psize;
    
    /* check input arguments */
    if (keyauth == NULL || data == NULL || sig == NULL)
        return -1;
    /* generate odd nonce */
    RAND_bytes(nonceodd, TCPA_NONCE_SIZE);
    /* Open OIAP Session */
    ret = TPM_OIAP(&authhandle, evennonce);
    if (ret != 0)
        return -1;
    /* move Network byte order data to variables for hmac calculation */
    ordinal = htonl(TPM_ORD_Quote);
    keyhndl = htonl(keyhandle);
    datasize = htonl(TCPA_NONCE_SIZE);
    c = 0;

    pcrsize = htons(2);
    
    /* calculate authorization HMAC value */
    ret = authhmac(pubauth, keyauth, TCPA_HASH_SIZE, evennonce, nonceodd, c, 
		   4, &ordinal, 
		   TCPA_NONCE_SIZE, data, 
		   2, &pcrsize,
		   2, &pcrmap,
		   0, 0);
    if (ret < 0) {
        TPM_Terminate_Handle(authhandle);
        return -1;
    }

    /* build the request buffer */
    /* 00 c2 T l l % % % l % o %  */
    ret = buildbuff(quote_fmt, quotedata,
                    ordinal,
                    keyhndl,
                    TCPA_NONCE_SIZE, data,
		    2, &pcrsize,
		    2, &pcrmap,
                    htonl(authhandle),
                    TCPA_NONCE_SIZE, nonceodd, 
		    c, 
		    TCPA_HASH_SIZE, pubauth);
    if (ret <= 0) {
        TPM_Terminate_Handle(authhandle);
        return -1;
    }

    /* transmit the request buffer to the TPM device and read the reply */
    printk("transmitting the quote request\n");
    ret = TPM_Transmit(quotedata, "Quote");
    if (ret != 0) {
        TPM_Terminate_Handle(authhandle);
        return ret;
    }
    TPM_Terminate_Handle(authhandle);

    p = (TPMPCRComposite *)(quotedata + TCPA_DATA_OFFSET);
    psize = sizeof(TPMPCRComposite) + ntohl(p->valueSize);

    sigsizeptr = (unsigned int *)(quotedata + TCPA_DATA_OFFSET + psize);
    sigsize = ntohl(*sigsizeptr);
    recvsig = (unsigned char *)sigsizeptr + sizeof(unsigned int);


#if 0
    printk("pcrs: ");
    for (i = 0; i < 20; i++)
      printk("%02x ", ((unsigned char *)p)[i]);
    printk("\n");
    printk("nonce: ");
    for (i = 0; i < 20; i++)
      printk("%02x ", ((unsigned char *)data)[i]);
    printk("\n");

    printk("p:");
    for (i = sizeof(TPMPCRComposite); i < psize; i++){
      if(((i - (sizeof(TPMPCRComposite))) % 20) == 0)
	printk("\n");
      printk("%02x ", ((unsigned char *)p)[i]);
    }

    printk("\nquotedata=0x%p p=0x%p sizsizeptr=0x%p sigsize=%d recvsig=0x%p psize=%d\n",
       quotedata, p, sigsizeptr, sigsize, recvsig, psize);
#endif

    /* check the HMAC in the response */
    ret = checkhmac1(quotedata, ordinal, nonceodd, keyauth, TCPA_HASH_SIZE, 
		     psize, TCPA_DATA_OFFSET,
                     4, TCPA_DATA_OFFSET + psize,
		     sigsize, TCPA_DATA_OFFSET + psize + 4, 
		     0, 0);
    if (ret != 0){
      printk("hmac check failed!\n");
      return -1;
    }
    memcpy(sig, recvsig, sigsize);
    *siglen = sigsize;
    
    memcpy(pcrResult, p, psize);
    *pcrlen = psize;
    return 0;
}
