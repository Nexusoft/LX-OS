/** NexusOS: generate manufacturer certificate for TPM from FAKE manufacturer.
             TPMs are supposed to come with authenticity certificates, but
 	     few do.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

extern int generate_credential(X509 *new, RSA *pubkey, RSA *privkey,
			char *common_name, BIO* extcnf, char *outfile, char *subject);

RSA *rsa_from_pem(const char *filename, int public){
  FILE *fp = fopen(filename, "r");
  if(fp == NULL){
    printf("couldn't open %s!\n", filename);
    return NULL;
  }

  EVP_PKEY *pkey = NULL;
  if(public)
    PEM_read_PUBKEY(fp, &pkey, NULL, NULL);
  else
    PEM_read_PrivateKey(fp, &pkey, NULL, NULL);
    
  fclose(fp);
  return EVP_PKEY_get1_RSA(pkey);
}


/* this generates a tpm_endorsement_credential */
int generate_tpm_endorsement_credential(char *tpm_pubek_file, char *manu_key_file, 
					char * extcnf, char *outfile){
  X509 *crt;
  char *common_name = "TPM Endorsement Entity";

  crt = X509_new();
  if(!crt){
    printf("Could not create X509 structure!\n");
    return -1;
  }


  /* subject public key info: TPM pubek */
  RSA *pubek = rsa_from_pem(tpm_pubek_file, 1);
  if (!pubek) {
    printf("Could not open public tpm endorsement key\n");
    return -1;
  }
  RSA *manu = rsa_from_pem(manu_key_file, 0);
  if (!manu) {
    printf("Could not open public tpm manufacturer key\n");
    return -1;
  }

  BIO *extbio = BIO_new_file(extcnf, "r");
  generate_credential(crt, pubek, manu, common_name, extbio, outfile, NULL);
  BIO_free(extbio);

  printf("generated %s.\n", outfile);
  return 0;
}

int main(int ac, char **av){
 
  if (ac > 3 || (ac == 3 && strcmp(av[1], "-f"))) {
  	printf("usage: %s [-f] [output_file]\n", av[0]);
 	exit(1);
  }

  printf("TPM certificate maker\n"
         "generating endorsement credential for a TPM from a fake manufacturer\n"
	 "\n"
	 "The follow keys are required:\n"
	 "  1. manufacturer key 'manu.private.key'\n"
	 "  2. TPM endorsement public key 'ek.public.key'\n");

  int force = (ac >= 2 && !strcmp(av[1], "-f"));

  char *outfile;
  if (ac >= 3) outfile = av[2];
  else if (ac == 2 && av[1][0] != '-') outfile = av[1];
  else outfile = "tpm_platform.crt";

  if (!force) {
    int fd = open(outfile, O_RDONLY);
    if (fd > 0) {
      printf("%s already present; nothing to do\n", outfile);
      close(fd);
      exit(0);
    }
  }

  generate_tpm_endorsement_credential("ek.public.pem", "manu.private.pem", 
		  		      "tpm_platform_extensions.cnf", outfile);
  //generate_platform_credential(...);
  //generate_conformance_credential(...);
  return 0;
}

