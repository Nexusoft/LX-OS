/****************************************************************************/
/*                                                                          */
/* OIAPOSAP.H 03 Apr 2003                                                   */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/
#ifndef OIAPOSAP_H
#define OIAPOSAP_H

typedef struct osapsess {
  unsigned int handle;
  unsigned char enonce[TCPA_NONCE_SIZE];
  unsigned char enonceOSAP[TCPA_NONCE_SIZE];
  unsigned char ononceOSAP[TCPA_NONCE_SIZE];
  unsigned char ssecret[TCPA_HASH_SIZE];
  unsigned char ononce[TCPA_NONCE_SIZE];
} osapsess;

#endif
