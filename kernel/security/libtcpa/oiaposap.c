/****************************************************************************/
/*                                                                          */
/*                             OAIP/OSAP protocols                          */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/
#include <nexus/defs.h>
#include <libtcpa/tcpa.h>
#include <libtcpa/hmac.h>
#include <libtcpa/oiaposap.h>
#include <libtcpa/buildbuff.h>
//#include <openssl/rand.h>

/****************************************************************************/
/*                                                                          */
/* Open an OIAP session                                                     */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_OIAP(uint32_t *handle, char *enonce)
{
    unsigned char oiap_open_fmt[] = "00 C1 T 00 00 00 0A";
    unsigned char *tcpadata = (unsigned char *)galloc(TCPA_MAX_BUFF_SIZE);
    uint32_t ret;

    /* check input arguments */
    if (handle == NULL || enonce == NULL){
      gfree(tcpadata);
      return 1;
    }
    /* build request buffer */
    ret = buildbuff(oiap_open_fmt, tcpadata);
    if (ret <= 0){
      gfree(tcpadata);
      return 1;
    }
    /* transmit request to TPM and get result */
    ret = TPM_Transmit(tcpadata, "TPM_OIAP");
    if (ret){
      gfree(tcpadata);
      return ret;
    }

    *handle = ntohl(*(uint32_t *)(tcpadata+TCPA_DATA_OFFSET));
    memcpy(enonce, &tcpadata[TCPA_DATA_OFFSET + 4], TCPA_NONCE_SIZE);

    gfree(tcpadata);
    return 0;
}

/****************************************************************************/
/*                                                                          */
/* Open an OSAP session                                                     */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_OSAP(osapsess *sess, unsigned char *key, uint16_t etype,
                  uint32_t evalue)
{
    unsigned char osap_open_fmt[] = "00 C1 T 00 00 00 0B S L %";
    unsigned char *tcpadata = (unsigned char *)galloc(TCPA_MAX_BUFF_SIZE);
    uint32_t ret;

    if (key == NULL){
      gfree(tcpadata);
      return 1;
    }
    RAND_bytes(sess->ononceOSAP, TCPA_NONCE_SIZE);

    ret = buildbuff(osap_open_fmt, tcpadata, etype, evalue,
                    TCPA_NONCE_SIZE, sess->ononceOSAP);

    if (ret <= 0){
      gfree(tcpadata);
      return 1;
    }

    ret = TPM_Transmit(tcpadata, "OSAP");
    //ret = TPM_Transmit_Emu(tcpadata, "OSAP");

    if (ret){
      gfree(tcpadata);
      return ret;
    }

    sess->handle = ntohl(*(uint32_t *) (tcpadata + TCPA_DATA_OFFSET));

    memcpy(sess->enonce, &(tcpadata[TCPA_DATA_OFFSET + 4]),
           TCPA_NONCE_SIZE);


    memcpy(sess->enonceOSAP,
           &(tcpadata[TCPA_DATA_OFFSET + 4 + TCPA_NONCE_SIZE]),
           TCPA_NONCE_SIZE);

    ret = rawhmac(sess->ssecret, key, TCPA_HASH_SIZE, TCPA_NONCE_SIZE,
                  sess->enonceOSAP, TCPA_NONCE_SIZE, sess->ononceOSAP, 0,
                  0);

    gfree(tcpadata);
    return ret;
}


/****************************************************************************/
/*                                                                          */
/* Terminate the Handle Opened by TPM_OIAPOpen, or TPM_OSAPOpen             */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Terminate_Handle(uint32_t handle)
{
    unsigned char hand_close_fmt[] = "00 C1 T 00 00 00 96 L";
    unsigned char *tcpadata = (unsigned char *)galloc(TCPA_MAX_BUFF_SIZE);
    uint32_t ret;

    ret = buildbuff(hand_close_fmt, tcpadata, handle);
    if (ret <= 0)
      ret = 1;
    else
      ret =  TPM_Transmit(tcpadata, "Terminate Handle");
    
    gfree(tcpadata);

    return ret;
}
