#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <assert.h>

#define FAIL(x...) do{				\
    printf(x);					\
    assert(0);					\
  }while(0)


static int serial_number = 0;

/* this generates a tpm_endorsement credential or a tpm_identity credential */
int generate_credential(X509 *new, RSA *pubkey, RSA *privkey,
			char *common_name, BIO* extcnf, char *outfile, char *subject){
  unsigned long chtype = MBSTRING_ASC;
  int days = 365 * 10;
  EVP_PKEY *evp_pubkey = EVP_PKEY_new();

  EVP_PKEY *evp_privkey = NULL;
  if(privkey != NULL){
    evp_privkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(evp_privkey, privkey);
  }

  EVP_PKEY_set1_RSA(evp_pubkey, pubkey);

  if(!X509_set_version(new, 2))
    FAIL("Could not set version!\n");

  ASN1_INTEGER *serial = ASN1_INTEGER_new();
  if(!ASN1_INTEGER_set(serial, serial_number++))
    FAIL("Could not set asn1 int!\n");
  if(!X509_set_serialNumber(new, serial))
    FAIL("Could not set serialNumber!\n");

  // signature algorithm : sha1WithRSAEncryption

  /* issuer name */
  X509_NAME *issuer_name = X509_NAME_new();
  if(!issuer_name)
    FAIL("Could not create issuer name\n!");
  if(!X509_NAME_add_entry_by_txt(issuer_name, "C", chtype, (unsigned char *)"US", -1, -1, 0))
    FAIL("Could not add entry C\n!");
  if(!X509_NAME_add_entry_by_txt(issuer_name, "ST", chtype, (unsigned char *)"New York", -1, -1, 0))
    FAIL("Could not add entry ST\n!");
  if(!X509_NAME_add_entry_by_txt(issuer_name, "L", chtype, (unsigned char *)"Ithaca", -1, -1, 0))
    FAIL("Could not add entry L\n!");
  if(!X509_NAME_add_entry_by_txt(issuer_name, "O", chtype, (unsigned char *)"Cornell University Nexus", -1, -1, 0))
    FAIL("Could not add entry O\n!");
  if(!X509_NAME_add_entry_by_txt(issuer_name, "OU", chtype, (unsigned char *)"NONE", -1, -1, 0))
    FAIL("Could not add entry OU\n!");
  if(!X509_NAME_add_entry_by_txt(issuer_name, "CN", chtype, (unsigned char *)common_name, -1, -1, 0))
    FAIL("Could not add entry CN\n!");
  if(!X509_set_issuer_name(new, issuer_name))
    FAIL("Could not set issuer name\n!");

  /* validity */
  X509_gmtime_adj(X509_get_notBefore(new),0);
  X509_gmtime_adj(X509_get_notAfter(new),(long)60*60*24*days);


  /* subject: no action */
  if(subject != NULL){
    //int X509_set_subject_name(X509 *x, X509_NAME *name)
    X509_NAME *subject_name = X509_NAME_new();
    if(!subject_name)
      FAIL("Could not create issuer name\n!");
    if(!X509_NAME_add_entry_by_txt(subject_name, "C", chtype, (unsigned char *)"US", -1, -1, 0))
      FAIL("Could not add entry C\n!");
    if(!X509_NAME_add_entry_by_txt(subject_name, "ST", chtype, (unsigned char *)"New York", -1, -1, 0))
      FAIL("Could not add entry ST\n!");
    if(!X509_NAME_add_entry_by_txt(subject_name, "L", chtype, (unsigned char *)"Ithaca", -1, -1, 0))
      FAIL("Could not add entry L\n!");
    if(!X509_NAME_add_entry_by_txt(subject_name, "O", chtype, (unsigned char *)"Cornell University Nexus", -1, -1, 0))
      FAIL("Could not add entry O\n!");
    if(!X509_NAME_add_entry_by_txt(subject_name, "OU", chtype, (unsigned char *)"NONE", -1, -1, 0))
      FAIL("Could not add entry OU\n!");
    if(!X509_NAME_add_entry_by_txt(subject_name, "CN", chtype, (unsigned char *)subject, -1, -1, 0))
      FAIL("Could not add entry CN\n!");
    if(!X509_set_subject_name(new, subject_name))
      FAIL("Could not set issuer name\n!");
  }


  /* subject public key info */
  if(!X509_set_pubkey(new, evp_pubkey))
    FAIL("Could not set pubkey\n!");

  //issuer unique id (omit)
  //subject unique id (omit)

  if(extcnf != NULL){
    //XXX fill in extension
    long errorline = -1;
    CONF *extconf = NULL;
    X509V3_CTX ctx2;
    char *extsect;

    //STACK_OF(CONF_VALUE) *nval;
    extconf = NCONF_new(NULL);
    //  if (!NCONF_load(extconf, extcnf, &errorline))
    if (!NCONF_load_bio(extconf, extcnf, &errorline))
      FAIL("NConf_load line %ld of config!\n", errorline);
    extsect = NCONF_get_string(extconf, "default", "extensions");
    if (!extsect){
      ERR_clear_error();
      extsect = "default";
    }

    X509V3_set_ctx_test(&ctx2);
    X509V3_set_nconf(&ctx2, extconf);

    printf("adding extensions\n");
    if (!X509V3_EXT_add_nconf(extconf, &ctx2, extsect, new))
      FAIL("couldn't add extension %s!\n", extsect);
  }

  /* sign with private key */
  const EVP_MD *digest = EVP_sha1();
  //printf("got digest pointer 0x%p\n", digest);
  if(privkey != NULL){
    if(!X509_sign(new, evp_privkey, digest))
      FAIL("Could not sign\n!");
  }

  if(outfile != NULL){
    BIO *out = BIO_new(BIO_s_file());
    if(BIO_write_filename(out,outfile) <= 0)
      FAIL("Could not BIO write!\n");
  
    PEM_write_bio_X509(out, new);
    BIO_flush(out);
    BIO_free(out);
    printf("wrote %s\n", outfile);
  }

  return 0;
}

