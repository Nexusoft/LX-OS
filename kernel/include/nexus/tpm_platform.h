#ifndef __TPM_PLATFORM_H__
#define __TPM_PLATFORM_H__


/* actual definitions in nsk.sc */
extern char *tpm_platform_crt;
extern char *tpm_conformance_crt;
extern char *tpm_ek_crt;

extern int tpm_platform_crt_len;
extern int tpm_conformance_crt_len;
extern int tpm_ek_crt_len;

#define TPM_ENDORSEMENT_CRED tpm_ek_crt
#define TPM_PLATFORM_CRED    tpm_platform_crt
#define TPM_CONFORMANCE_CRED tpm_conformance_crt
#define TPM_ENDORSEMENT_CRED_SIZE tpm_ek_crt_len
#define TPM_PLATFORM_CRED_SIZE    tpm_platform_crt_len
#define TPM_CONFORMANCE_CRED_SIZE tpm_conformance_crt_len

#endif
