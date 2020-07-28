/****************************************************************************/
/*                                                                          */
/*                        TCPA PCR Processing Functions                     */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/
#include <nexus/defs.h>
#include <libtcpa/tcpa.h>
#include <libtcpa/pcrs.h>
#include <libtcpa/buildbuff.h>
//#include <openssl/sha.h>

typedef char SHA1CTX[100]; // XXX hack - egs

/* Extend digest into PCR */
int TPM_Extend(unsigned int pcrindex, unsigned char *digest){
  unsigned char extend_fmt[] = "00 c1 T L L % ";
  unsigned char *tcpadata = (unsigned char *)galloc(TCPA_MAX_BUFF_SIZE); /* request/response buffer */
  int ret;

  if (digest == NULL){
    gfree(tcpadata);
    return -1;
  }
  ret = buildbuff(extend_fmt, tcpadata, TPM_ORD_Extend, 
		  pcrindex, TCPA_HASH_SIZE, digest); 
  ret = TPM_Transmit(tcpadata, "Extend");

  gfree(tcpadata);
  return ret;
}

/****************************************************************************/
/*                                                                          */
/*  Read PCR value                                                          */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_PcrRead(uint32_t pcrindex, unsigned char *pcrvalue)
{
    unsigned char pcrread_fmt[] = "00 c1 T 00 00 00 15 L";
    unsigned char *tcpadata = (unsigned char *)galloc(TCPA_MAX_BUFF_SIZE); /* request/response buffer */
    uint32_t ret;

    if (pcrvalue == NULL){
      gfree(tcpadata);
      return -1;
    }
    ret = buildbuff(pcrread_fmt, tcpadata, pcrindex);
    if (ret < 0){
      gfree(tcpadata);
      return -1;
    }
    ret = TPM_Transmit(tcpadata, "PCRRead");
    if (ret != 0){
      gfree(tcpadata);
      return ret;
    }
    memcpy(pcrvalue, tcpadata + TCPA_DATA_OFFSET, TCPA_HASH_SIZE);

    gfree(tcpadata);
    return 0;
}

/****************************************************************************/
/*                                                                          */
/*  Create PCR_INFO structure using current PCR values                      */
/*                                                                          */
/****************************************************************************/
uint32_t GenPCRInfo(uint32_t pcrmap, unsigned char *pcrinfo,
                    unsigned int *len)
{
    struct pcrinfo {
        uint16_t selsize;
        unsigned char select[TCPA_PCR_MASK_SIZE];
        unsigned char relhash[TCPA_HASH_SIZE];
        unsigned char crthash[TCPA_HASH_SIZE];
    } myinfo;
    int i;
    int j;
    uint32_t work;
    unsigned char *valarray;
    uint32_t numregs;
    uint32_t ret;
    uint32_t valsize;
    SHA1CTX sha;

    /* check arguments */
    if (pcrinfo == NULL || len == NULL)
        return -1;
    /* build pcr selection array */
    work = pcrmap;
    memset(myinfo.select, 0, TCPA_PCR_MASK_SIZE);
    for (i = 0; i < TCPA_PCR_MASK_SIZE; ++i) {
        myinfo.select[i] = work & 0x000000FF;
        work = work >> 8;
    }
    /* calculate number of PCR registers requested */
    numregs = 0;
    work = pcrmap;
    for (i = 0; i < (TCPA_PCR_MASK_SIZE * 8); ++i) {
        if (work & 1)
            ++numregs;
        work = work >> 1;
    }
    if (numregs == 0) {
        *len = 0;
        return 0;
    }
    /* create the array of PCR values */
    valarray = (unsigned char *) galloc(TCPA_HASH_SIZE * numregs);
    /* read the PCR values into the value array */
    work = pcrmap;
    j = 0;
    for (i = 0; i < (TCPA_PCR_MASK_SIZE * 8); ++i, work = work >> 1) {
        if ((work & 1) == 0)
            continue;
        ret = TPM_PcrRead(i, &(valarray[(j * TCPA_HASH_SIZE)]));
        if (ret)
            return ret;
        ++j;
    }
    myinfo.selsize = ntohs(TCPA_PCR_MASK_SIZE);
    valsize = ntohl(numregs * TCPA_HASH_SIZE);
    /* calculate composite hash */
    sha1_init(&sha);
    sha1_update(&sha, (unsigned char *)&myinfo.selsize, 2);
    sha1_update(&sha, myinfo.select, TCPA_PCR_MASK_SIZE);
    sha1_update(&sha, (unsigned char *)&valsize, 4);
    for (i = 0; i < numregs; ++i) {
        sha1_update(&sha, &(valarray[(i * TCPA_HASH_SIZE)]),
                    TCPA_HASH_SIZE);
    }
    sha1_final(&sha, myinfo.relhash);
    memcpy(myinfo.crthash, myinfo.relhash, TCPA_HASH_SIZE);
    memcpy(pcrinfo, &myinfo, sizeof(struct pcrinfo));
    *len = sizeof(struct pcrinfo);
    gfree(valarray);

    return 0;
}
