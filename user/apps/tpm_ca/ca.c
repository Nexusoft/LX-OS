#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <libtcpa/identity_private.h>
#include <libtcpa/keys.h>

#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <string.h>

#include <nexus/util.h>
#include <nexus/ca.h>

#include "common.h"

#define TPM_CA_PORT 5893

RSA *priv;
char *common_name = "TPM Privacy CA";
char *extensionsfile;

/* get the chosen id hash and check the signature by the id key */
RSA *check_idbinding(IdentityReqData *req) {

  printf("label (%d bytes): %s\n", req->proof.labelSize, req->proof.labelArea);

  IdentityContentsData id;
  fillIdentityContentsData(&id, req->proof.labelArea, req->proof.labelSize,
			   &req->pubkey , &req->proof.identityKey);

  unsigned char idcontents[TCPA_IDCONTENTS_SIZE];
  int size = BuildIdentityContents(idcontents, &id);

  debug_show_data("idcontents", idcontents, size, 1, NULL);

  unsigned char hash[TCPA_HASH_SIZE];
  SHA1(idcontents, size, hash);

  RSA *pubidkey = rsa_from_pubkeydata(&req->proof.identityKey);
  if (!pubidkey) {
    printf("could not parse public identity key\n");
    return NULL;
  }

  debug_show_data("idbinding", req->proof.idbinding, req->proof.idbindingSize, 1, NULL);

  int ret = RSA_verify(NID_sha1, hash, TCPA_HASH_SIZE,
		       req->proof.idbinding, req->proof.idbindingSize, pubidkey);
  if (ret != 1) {
    printf("Error: identity binding signature didn't match \n");
    printf("Either you have the wrong public EK in your tpm_platform.crt\n");
    printf(" - you can run 'get_pubek /nfs/ek.public.pem' to write your actual pubek to disk\n");
    printf(" - then run 'openssl asn1dump -strparse 19 -in /tftpboot-${username}/ek.public.pem' to see it\n");
    printf(" - and compare with 'openssl x509 -text -in /tftpboot-${username}/tpm_platform.crt\n");
    printf("OR, you have the wrong TPM version in your kernel or userspace code\n");
    printf(" - you can run 'tpmdemo' from the kernel shell to see the actual version of your tpm\n");
    printf(" - and also compare against tcpa_version_buf_g[] in userspace\n");
    return NULL;
  }

  return pubidkey;
}

char *idlabel_to_filename(IdentityReqData *req) {
  int n = req->proof.labelSize;
  char *filename = malloc(n + 5);
  memcpy(filename, req->proof.labelArea, n);
  sprintf(filename + n, ".crt");
  for (n = 0; filename[n]; n++)
    if (filename[n] == ' ') filename[n] = '_';
  return filename;
}

X509 *create_idcred(RSA *pubidkey, char *filename) {

  X509 *idcred = X509_new();
  if (!idcred) {
    printf("could not create x509\n");
    return NULL;
  }

  BIO *extbio = BIO_new_file(extensionsfile, "r");
  if (!extbio) {
    printf("could not read x509 extensions from %s\n", extensionsfile);
    return NULL;
  }

  printf("Generating credential in %s\n", filename);
  int err = generate_credential(idcred, pubidkey, priv, common_name, extbio, filename, NULL);
  BIO_free(extbio);
  if (err) {
    printf("could not create credential\n");
    return NULL;
  }

  return idcred;
}

/* check the EK credential and return the public EK */
RSA *check_credentials(IdentityReqData *req) {

  debug_show_data("endorsement credential",
      req->proof.endorsementCred, req->proof.endorsementSize, 1, NULL);

  BIO *cert = BIO_new_mem_buf(req->proof.endorsementCred, req->proof.endorsementSize);
  if (!cert) {
    printf("could not read endorsement credential\n");
    return NULL;
  }

  X509 *ec = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
  if (!ec) {
    printf("could not parse endorsement credential\n");
    return NULL;
  }

  /* todo: check endorsement certificate */

  EVP_PKEY *pkey = X509_get_pubkey(ec);
  if (!pkey) {
    printf("could not parse public key\n");
    return NULL;
  }
  RSA *pubek = EVP_PKEY_get1_RSA(pkey);
  if (!pubek) {
    printf("could not parse public key into RSA format\n");
    return NULL;
  }

  return pubek;
}

IdentityRespData *handle_request(int conn, unsigned char *buf, int len) {
  IdentityReqData req;

  debug_show_data("request", buf, len, 1, "last_ca_request.dat");

  len = ExtractIdentityReq(&req, buf, priv);
  if (len < 0){
    printf("Could not parse request\n");
    return NULL;
  }

  printf("Checking credentials...\n");
  RSA *pubek = check_credentials(&req);
  if (!pubek) return NULL;

  printf("Checking identity binding...\n");
  RSA *pubid = check_idbinding(&req);
  if(pubid < 0) return NULL;

  printf("Creating identity credential...\n");
  char *filename = idlabel_to_filename(&req);
  X509 *idcred = create_idcred(pubid, filename);
  free(filename);
  if (!idcred) return NULL;

  printf("Creating response...\n");
  IdentityRespData *resp = malloc(sizeof(IdentityRespData));
  fillIdentityRespData(resp, &req.proof.identityKey, idcred, pubek);
  
  return resp;
}

int send_response(int fd, IdentityRespData *resp) {
  unsigned char response[TCPA_IDENTITY_RESP_SIZE];
  int len, ret = 0;
  if (resp) {
    printf("Request was successful, sending response\n");
    len = BuildIdentityResp(response, resp);
    debug_show_data("response", response, len, 1, "last_ca_response.dat");
  } else {
    printf("Request failed, sending response\n");
    *(int *)response = -1;
    len = sizeof(int);
    ret = -1;
  }
  if (send_data(fd, response, len))
    return -1;
  return ret;
}

void init_ca(char *privfile, char *extfile) {
  printf("Loading private key %s\n", privfile);

  FILE *f = fopen(privfile, "r");
  if (f < 0) {
    perror("could not load private key");
    printf("exiting");
    exit(1);
  }
  EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
  if (!pkey) {
    printf("could not parse private key\n");
    printf("exiting");
    exit(1);
  }
  priv = EVP_PKEY_get1_RSA(pkey);
  if (!priv) {
    printf("could not parse private key into RSA format\n");
    printf("exiting");
    exit(1);
  }

  printf("Will use certificate extensions from %s\n", extfile);
  extensionsfile = extfile;
}

int main(int ac, char **av) {

  if (ac != 3) {
    printf("usage: %s ca_private_key.pem certificate_extensions.cnf\n", av[0]);
    exit(1);
  }

  printf("Nexus TPM Attestation Identity Key Certificate Authority\n");

  init_ca(av[1], av[2]);

  int s = init_server(TPM_CA_PORT);

  int total_success = 0, total_failed = 0;

  for (;;) {
    int conn = server_wait(s, total_success, total_failed);

    unsigned char *buf = malloc(TCPA_IDENTITY_REQ_SIZE);
    int size = RecvIdentityReq(conn, buf);
    assert(size <= TCPA_IDENTITY_REQ_SIZE);
    printf("Received AIK request (%d bytes)\n", size);

    IdentityRespData *resp = handle_request(conn, buf, size);
    int err = send_response(conn, resp);
    if (err) total_failed++;
    else total_success++;

    if (resp) free(resp);
    free(buf);
    close(conn);

    printf("Finished AIK request\n\n\n");
  }

  return 0;
}

