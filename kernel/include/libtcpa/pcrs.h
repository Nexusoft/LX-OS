/****************************************************************************/
/*                                                                          */
/*  PCRS.H  03 Apr 2003                                                     */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/
#ifndef PCRS_H
#define PCRS_H

#define TCPA_PCR_NUM       16   /* number of PCR registers supported */
#define TCPA_PCR_MASK_SIZE  2   /* size in bytes of PCR bit mask     */

#pragma pack(1)
struct TPMPCRSelection{
  unsigned short size;  /* always 2 */
  unsigned char pcrSelect[TCPA_PCR_MASK_SIZE];
};

struct TPMPCRInfo{
  struct TPMPCRSelection pcrSelection;
  unsigned char digestAtRelease[TCPA_HASH_SIZE];
  unsigned char digestAtCreation[TCPA_HASH_SIZE];
};

struct TPMPCRComposite {
  struct TPMPCRSelection selection;
  unsigned int valueSize;
  unsigned char firstPcrValue[0];
};

struct TPMQuoteInfo{
  unsigned char version[4];
  unsigned char fixed[4];
  unsigned char digestValue[TCPA_HASH_SIZE];
  unsigned char externalData[TCPA_HASH_SIZE];
};

unsigned int GenPCRInfo(unsigned int pcrmap, unsigned char *pcrinfo,
                    unsigned int *len);

#pragma pack()

#endif
