#include <stdio.h>
#include <libtcpa/keys.h>
#include <nexus/Attestation.interface.h>
#include <string.h>
#include <../compat/tpmcompat.h>

int main(int argc, char **argv){
  if(argc != 2){
    printf("usage: get_pubek pubek_filename\n");
    return -1;
  }

  PubKeyData key;
  Attestation_GetPubek(&key);

  if(pem_from_pubkeydata(&key, argv[1]) < 0) {
    printf("couldn't save tpm public ek to file %s\n", argv[1]);
    exit(1);
  }

  printf("saved tpm public endorsement key as %s\n", argv[1]);
  return 0;
}
