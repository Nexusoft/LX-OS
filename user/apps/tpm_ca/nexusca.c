
#include "common.h"

#include <nexus/formula.h>
#include <nexus/vkey.h>

#define TPM_NEXUSCA_PORT 5892

RSA *priv;
char *common_name = "Nexus Vetting CA";
char *extensionsfile;
EVP_PKEY *pcaevp;

char *certify_to_filename(CertifyKeyData *req) {
  char *filename = malloc(2 * TCPA_NONCE_SIZE + 5);
  int i;
  for(i = 0; i < TCPA_NONCE_SIZE; i++)
    sprintf(filename+2*i, "%02x", req->nonce[i] & 0xff);
  sprintf(filename+2*TCPA_NONCE_SIZE, ".crt");
  return filename;
}

X509 *handle_request(unsigned char *certifybuf, int certifysize, 
		     unsigned char *aikbuf, int aiksize) {
  X509 *ret = NULL;
  CertifyKeyData certify;

  printf("extracing certifykeyreq\n");
  ExtractCertifyKeyReq(&certify, certifybuf);
  
  printf("getting aikcert\n");
  BIO *aikbio = BIO_new_mem_buf(aikbuf, aiksize);
  X509 *aikcert = PEM_read_bio_X509_AUX(aikbio, NULL, NULL, NULL);

  printf("getting aik keys (cert = 0x%p)\n", aikcert);
  EVP_PKEY *aikevp = X509_get_pubkey(aikcert);
  RSA *aik = EVP_PKEY_get1_RSA(aikevp);

  printf("XXX not checking aik cert validity");
  if(0) {
    printf("verifying 0x%p 0x%p\n", aikcert, pcaevp);
    /* check aik cert */
    int verifyret;
    if((verifyret = X509_verify(aikcert, pcaevp)) != 1){
      printf("could not verify aikcert!! %d\n", verifyret);
      ERR_load_crypto_strings();
      ERR_print_errors_fp(stdout);
      ret = NULL;
      goto out_aikcheck;
    }
  }

  printf("checking certifybuf\n");
  /* check certifybuf is signed by aik */
  unsigned char hash[TCPA_HASH_SIZE];
  unsigned char cbuf[TCPA_CERTIFY_INFO_SIZE];
  int csize = BuildCertifyKeyInfo(cbuf, &certify);
  SHA1(cbuf, csize, hash);

  int i;
  printf("certifykeyinfo hash: ");
  for(i = 0; i < TCPA_HASH_SIZE; i++){
    printf("%02x ", hash[i]);
  }
  unsigned char hash2[TCPA_HASH_SIZE];
  SHA1(certify.sig, TCPA_SIG_SIZE, hash2);
  printf("certifysig hash: ");
  for(i = 0; i < TCPA_HASH_SIZE; i++){
    printf("%02x ", hash2[i]);
  }

  printf("rsa:\n");
  BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
  RSA_print(bio_out, aik, 0);
  BIO_free(bio_out);

  printf("\n");
  if(RSA_verify(NID_sha1, hash, TCPA_HASH_SIZE,
  		certify.sig, TCPA_SIG_SIZE, aik) != 1) {
    printf("could not verify certifybuf's signature!!");
    ret = NULL;
    goto out_certifycheck;
  }

  /* check pcrinfo */
  //XXX
  printf("XXX Warning: not checking pcrinfo yet!\n");

  /* construct new X509 */
  RSA *pubnsk = rsa_from_pubkeydata(&certify.pub);
  X509 *nskcred = X509_new();
  char *filename = certify_to_filename(&certify);

  /* if we want extensions, get them from the extensions file */
  BIO *extbio = BIO_new_file(extensionsfile, "r");
  generate_credential(nskcred, pubnsk, priv, common_name, extbio, filename, "Trusted Nexus");
  free(filename);
  BIO_free(extbio);

  ret = nskcred;

  RSA_free(pubnsk);
out_aikcheck:
out_certifycheck:
  RSA_free(aik);
  EVP_PKEY_free(aikevp);
  X509_free(aikcert);
  BIO_free(aikbio);

  return ret;
}

SignedFormula *handle_request2(unsigned char *certifybuf, int certifysize, 
			       unsigned char *aikbuf, int aiksize) {

  printf("getting PCRs\n");
  assert(certifysize >= 8*20 + 1);
  int enc = certifybuf[certifysize - 8 * 20 - 1];
  unsigned char *pcrs = certifybuf + (certifysize - 8 * 20);
  int i;
  for (i = 0; i < 8; i++) {
    printf("pcr[%d] = ", i);
    int j;
    for (j = 0; j < 20; j++)
      printf("%02x", pcrs[i*20+j] & 0xff);
    printf("\n");
  }

  CertifyKeyData certify;
  ExtractCertifyKeyReq(&certify, certifybuf);
  RSA *openssl_nsk = rsa_from_pubkeydata(&certify.pub);

  VKey *k = vkey_openssl_import(openssl_nsk);
  if (!k) {
    printf("could not get nexus kernel key into vkey format\n");
    return NULL;
  }
  printf("setting key type as %s\n", enc ? "encryption" : "signing");
  vkey_set_algo(k, (enc ? ALG_RSA_ENCRYPT : ALG_RSA_SHA1));
  unsigned char *buf = (unsigned char *)vkey_serialize(k, 1);
  int len = der_msglen(buf);
  Form *nsk = term_fmt("der(%{bytes})", buf, len);

  Form *f = form_fmt("pcrs(%{term}) = {"
		     " %{bytes:20}, %{bytes:20},"
		     " %{bytes:20}, %{bytes:20},"
		     " %{bytes:20}, %{bytes:20},"
		     " %{bytes:20}, %{bytes:20} }",
		     nsk,
		     &pcrs[0*20], &pcrs[1*20],
		     &pcrs[2*20], &pcrs[3*20],
		     &pcrs[4*20], &pcrs[5*20],
		     &pcrs[6*20], &pcrs[7*20]);

  k = vkey_openssl_import(priv);
  if (!k) {
    printf("could not get nexus ca key into vkey format\n");
    return NULL;
  }
  vkey_set_algo(k, ALG_RSA_SHA1);

  Formula *der = form_to_der(f);
  if (!der) {
    printf("can't encode formula\n");
    return NULL;
  }

  SignedFormula *sf = formula_sign(der, k);
  if (!sf) {
    printf("can't sign formula\n");
    return NULL;
  }

  return sf;
}

void init_nexusca(char *privfile, char *cafile, char *extfile) {
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

  printf("Loading ca certificate %s\n", cafile);
  BIO *pcabio = BIO_new_file(cafile, "r");
  if (!pcabio) {
    printf("could not load ca certificate\n");
    printf("exiting");
    exit(1);
  }
  X509 *pcacert = PEM_read_bio_X509_AUX(pcabio, NULL, NULL, NULL);
  if (!pcabio) {
    printf("could not parse ca certificate\n");
    printf("exiting");
    exit(1);
  }
  pcaevp = X509_get_pubkey(pcacert);
  if (!pcaevp) {
    printf("could not parse ca public key from certificate\n");
    printf("exiting");
    exit(1);
  }
  BIO_free(pcabio);

  printf("Will use certificate extensions from %s\n", extfile);
  extensionsfile = extfile;
}

int send_response(int conn, X509 *cert, SignedFormula *sf) {
    if (!cert || !sf) {
      printf("Request failed, sending response\n");
      int fail = -1;
      send_data(conn, (unsigned char *)&fail, sizeof(int));
      return -1;
    } else {
      printf("Request was successful, sending responses\n");

      BIO *certbio = BIO_new(BIO_s_mem());
      unsigned char *certbuf = NULL;
      PEM_write_bio_X509(certbio, cert);
      int certsize = BIO_get_mem_data(certbio, &certbuf);

      printf("Sending certificate size = %d\n", certsize);
      int certsizetosend = htonl(certsize);
      if (send_data(conn, (unsigned char *)&certsizetosend, sizeof(int)))
	  return -1;

      int sformsize = der_msglen(sf->body);
      printf("Sending signed formula size = %d\n", sformsize);
      int sformsizetosend = htonl(sformsize);
      if (send_data(conn, (unsigned char *)&sformsizetosend, sizeof(int)))
	return -1;

      printf("Sending kernel attestation certificate\n");
      if (send_data(conn, certbuf, certsize))
	return -1;

      printf("Sending kernel attestation signed formula\n");
      if (send_data(conn, sf->body, sformsize))
	return -1;

      BIO_free(certbio);
      free(sf);

      return 0;
    }
}

int main(int ac, char **av){

  if(ac != 4){
    printf("usage: %s nexusca_private_key.pem ca_public.crt platform_extensions.cnf\n", av[0]);
    exit(1);
  }

  printf("Nexus Kernel Attestation Certificate Authority\n");

  init_nexusca(av[1], av[2], av[3]);

  printf("about to listen");
  int s = init_server(TPM_NEXUSCA_PORT);

  int total_success = 0, total_failed = 0;

  for (;;) {
    int conn = server_wait(s, total_success, total_failed);

    // XXX kwalsh: TCPA_IDENTITY_REQ_SIZE seems like the wrong constant here (it
    // is safe, however, because it is much larger than necessary)
    unsigned char *buf = (unsigned char *)malloc(TCPA_IDENTITY_REQ_SIZE + 8 * 20 + 1);
    int size = RecvCertifyReq(conn, buf);
    assert(size <= TCPA_IDENTITY_REQ_SIZE + 8 * 20 + 1);
    printf("Received tcpa identity request (%d bytes)\n", size);

    unsigned char *aikbuf = (unsigned char *)malloc(MAX_CRED_LEN);
    int aiksize = RecvAIKCert(conn, aikbuf);
    assert(aiksize <= MAX_CRED_LEN);
    printf("Received AIK certificate (%d bytes)\n", aiksize);

    X509 *cert = handle_request(buf, size, aikbuf, aiksize);
    SignedFormula *sf = handle_request2(buf, size, aikbuf, aiksize);
    int err = send_response(conn, cert, sf);
    if (err) total_failed++;
    else total_success++;

    free(buf);
    free(aikbuf);
    close(conn);

    printf("Finished kernel attestation request\n\n\n");
  }

  return 0;
}
