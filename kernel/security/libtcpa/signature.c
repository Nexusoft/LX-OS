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
unsigned char tcpadata[TCPA_MAX_BUFF_SIZE];
unsigned char nonceodd[TCPA_NONCE_SIZE];
unsigned char evennonce[TCPA_NONCE_SIZE];
unsigned char pubauth[TCPA_HASH_SIZE];

uint32_t TPM_Sign(uint32_t keyhandle, unsigned char *keyauth,
                  unsigned char *data, int datalen,
                  unsigned char *sig, unsigned int *siglen)
{
    unsigned char sign_fmt[] = "00 c2 T l l @ l % o %";
    unsigned char c;
    uint32_t ordinal;
    uint32_t keyhndl;
    uint32_t authhandle;
    uint32_t datasize;
    uint32_t sigsize;
    uint32_t ret;

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
    ordinal = htonl(0x3C);
    keyhndl = htonl(keyhandle);
    datasize = htonl(datalen);
    c = 0;

    /* calculate authorization HMAC value */
    ret = authhmac(pubauth, keyauth, TCPA_HASH_SIZE, evennonce, nonceodd,
                   c, 4, &ordinal, 4, &datasize, datalen, data, 0, 0);
    if (ret < 0) {
        TPM_Terminate_Handle(authhandle);
        return -1;
    }

    /* build the request buffer */
    ret = buildbuff(sign_fmt, tcpadata,
                    ordinal,
                    keyhndl,
                    datalen, data,
                    htonl(authhandle),
                    TCPA_NONCE_SIZE, nonceodd, c, TCPA_HASH_SIZE, pubauth);
    if (ret <= 0) {
        TPM_Terminate_Handle(authhandle);
        return -1;
    }

    /* transmit the request buffer to the TPM device and read the reply */
    printk("transmitting the sign request\n");
    ret = TPM_Transmit(tcpadata, "Sign");
    if (ret != 0) {
        TPM_Terminate_Handle(authhandle);
        return ret;
    }
    TPM_Terminate_Handle(authhandle);
    sigsize = ntohl(*(uint32_t *) (tcpadata + TCPA_DATA_OFFSET));

    /* check the HMAC in the response */
    ret = checkhmac1(tcpadata, ordinal, nonceodd, keyauth,
                     TCPA_HASH_SIZE, 4, TCPA_DATA_OFFSET,
                     sigsize, TCPA_DATA_OFFSET + 4, 0, 0);

    if (ret != 0)
        return -1;
    memcpy(sig, tcpadata + TCPA_DATA_OFFSET + 4, sigsize);
    *siglen = sigsize;
    return 0;
}
