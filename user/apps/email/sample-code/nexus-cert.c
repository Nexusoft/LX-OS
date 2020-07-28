#include <openssl/ossl_typ.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/buffer.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <assert.h>

#include "nexus-cert.h"

// Nexus-style certificate signing for Linux

void openssl_print_error(void) {
	printf("error = %s\n", ERR_error_string(ERR_get_error(), NULL));
}

#define ASN1err(X,Y) printf("asn1err: %s %s\n", #X, #Y)
#define X509_sign_nexus(x,md) \
        ASN1_sign_nexus((int (*)())i2d_X509_CINF, x->cert_info->signature, \
                x->sig_alg, x->signature, (char *)x->cert_info,md)

int ASN1_sign_nexus(
		    int (*i2d)(),
		    X509_ALGOR *algor1,
		    X509_ALGOR *algor2,
		  ASN1_BIT_STRING *signature, char *data, 
		  const EVP_MD *type);

BIO *bio_err = NULL;
X509_NAME *nexus_issuer_name;
RSA *fake_nsk_rsa_key = NULL;

void nexus_cert_init(void) {
	if (bio_err == NULL)
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);
	nexus_issuer_name = create_x509_issuer_name("US", "Cornell University", "Nexus OS CA");

	fake_nsk_rsa_key = RSA_generate();
}

RSA *RSA_generate(void) {
	RSA *rsa = RSA_new();
	unsigned long f4=RSA_F4;
	// BN_GENCB cb;

	//if(!BN_set_word(bn, f4) || !RSA_generate_key(rsa, num, NULL)) {
	if((rsa = RSA_generate_key(2048, f4, NULL, NULL)) == NULL) {
		printf("Could not generate rsa kiey!\n");
		goto err;
	}
	printf("generated rsa key\n");
	return rsa;
 err:
	RSA_free(rsa);
	return NULL;
}

X509_NAME *create_x509_issuer_name(const char *country, 
			   const char *organization, const char *cn) {
	X509_NAME *nm;
	nm = X509_NAME_new();
	if (nm == NULL) {
		printf("could not create x509 name '%s' '%s' '%s'\n",
		       country, organization, cn);
		return NULL;
	}
	if (!X509_NAME_add_entry_by_txt(nm, "C", MBSTRING_ASC, country, -1, -1, 0)) {
		printf("could not add country\n");
		goto err;
	}
	if (!X509_NAME_add_entry_by_txt(nm, "O", MBSTRING_ASC, organization, -1, -1, 0)) {
		printf("could not add organization\n");
		goto err;
	}
	if (!X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, cn, -1, -1, 0)) {
		printf("could not add cn\n");
		goto err;
	}
	return nm;
 err:
	X509_NAME_free(nm);
	return NULL;

}

X509_NAME *create_x509_email_name(const char *address, const char *cn) {
	X509_NAME *nm;
	nm = X509_NAME_new();
	char cn_buf[4096];
	if (nm == NULL) {
		printf("could not create x509 name '%s' '%s'\n",
		       address, cn);
		return NULL;
	}
	sprintf(cn_buf, "%s/emailAddress=%s", cn, address);
#if 0
	if (!X509_NAME_add_entry_by_txt(nm, "emailAddress", MBSTRING_ASC, address, -1, -1, 0)) {
		printf("could not add email\n");
		printf("error = %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}
#endif
	if (!X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, cn_buf, -1, -1, 0)) {
		printf("could not add cn\n");
		goto err;
	}
	return nm;
 err:
	X509_NAME_free(nm);
	return NULL;

}

// generate an unsigned certificate, including a private key

void X509_print_cert(X509 *x509) {
	X509_print_ex(bio_err, x509, 0, 0);
}

X509 *X509_generate(X509_NAME *subject_name, EVP_PKEY **pkey_rv) {
	X509 *ret = NULL;
	RSA *rsa = RSA_generate();
	EVP_PKEY *pkey = EVP_PKEY_new();
	const EVP_MD *md = EVP_get_digestbyname("sha1");
	assert(md != NULL);

	EVP_PKEY_set1_RSA(pkey, rsa);
	
	ret = X509_new();

#if 1
	X509V3_CTX ctx;
	CONF *conf = NCONF_new(NULL);
	BIO  *bio_conf = BIO_new_file("ext.conf", "r");
	long eline = -1;
	NCONF_load_bio(conf, bio_conf, &eline);
	char *section = NCONF_get_string(conf, "default", "extensions");
	if(section == NULL) {
		printf("section error\n");
		openssl_print_error();
	}
	printf("section is %s, eline is %d\n", section, eline);
	X509_set_version(ret,2);
	X509V3_set_ctx(&ctx, ret, ret, NULL, NULL, 0);
	X509V3_set_nconf(&ctx, conf);
	if (!X509V3_EXT_add_nconf(conf, &ctx, section, ret)) {
		printf("error adding nconf\n");
		openssl_print_error();
		goto err;
	}
	NCONF_free(conf);
#endif

	X509_set_issuer_name(ret, nexus_issuer_name);
	int days = 1;
	X509_gmtime_adj(X509_get_notBefore(ret), (long) 0);
	X509_gmtime_adj(X509_get_notAfter(ret),(long)60*60*24*days);
	X509_set_subject_name(ret, subject_name);
	X509_set_pubkey(ret, pkey);

	// ret->signature->data = NULL;
	X509_sign_nexus(ret, md);

	unsigned long nameopt = 0;
	unsigned long certopt = 0;
	X509_print_ex(bio_err, ret, nameopt, certopt);

	RSA_free(rsa);
	*pkey_rv = pkey;
	return ret;
 err:
	if(ret != NULL)
		X509_free(ret);
	EVP_PKEY_free(pkey);
	return NULL;
}

#define NEXUS_PKEY_SIZE (256) // 2048 bits

struct NexusCtx {
	EVP_MD_CTX ctx;
};

void Nexus_SignInit(struct NexusCtx *ctx) {
	const EVP_MD *dgst = EVP_get_digestbyname("sha1");
	assert(dgst != NULL);
	EVP_MD_CTX_init(&ctx->ctx);
	if(!EVP_DigestInit(&ctx->ctx, dgst)) {
		printf("could not initialize sha1\n");
		assert(0);
	}
}

void Nexus_SignUpdate(struct NexusCtx *ctx, unsigned char *buf_in, 
		      unsigned int inl) {
	if(!EVP_DigestUpdate(&ctx->ctx, buf_in, inl)) {
		printf("couldn't update digest\n");
		assert(0);
	}
}

int Nexus_SignFinal(struct NexusCtx *ctx, unsigned char *buf_out,
		    unsigned int *outl) {
	int dgst_len = NEXUS_PKEY_SIZE;
	char dgst[NEXUS_PKEY_SIZE];
	if(!EVP_DigestFinal(&ctx->ctx, dgst, &dgst_len)) {
		printf("couldn't finalize digest\n");
		return 0;
	}
#if 0
	xxx call down to nexus for final signature;
#else
	// Do a RSA_sign operation
	if(!RSA_sign(NID_sha1, dgst, dgst_len, buf_out, outl, fake_nsk_rsa_key)) {
		printf("error doing rsa sign\n");
		return 0;
	}
#endif
	return 1;
}

void NexusCtx_cleanup(struct NexusCtx *ctx) {
	EVP_MD_CTX_cleanup(&ctx->ctx);
}

int ASN1_sign_nexus(int (*i2d)(), X509_ALGOR *algor1, X509_ALGOR *algor2,
	      ASN1_BIT_STRING *signature, char *data, 
	      const EVP_MD *type)
	{
	struct NexusCtx ctx;
	unsigned char *p,*buf_in=NULL,*buf_out=NULL;
	int i,inl=0,outl=0,outll=0;
	X509_ALGOR *a;

	Nexus_SignInit(&ctx);
	for (i=0; i<2; i++)
		{
		if (i == 0)
			a=algor1;
		else
			a=algor2;
		if (a == NULL) continue;
                if (type->pkey_type == NID_dsaWithSHA1)
			{
			/* special case: RFC 2459 tells us to omit 'parameters'
			 * with id-dsa-with-sha1 */
			ASN1_TYPE_free(a->parameter);
			a->parameter = NULL;
			}
		else if ((a->parameter == NULL) || 
			(a->parameter->type != V_ASN1_NULL))
			{
			ASN1_TYPE_free(a->parameter);
			if ((a->parameter=ASN1_TYPE_new()) == NULL) goto err;
			a->parameter->type=V_ASN1_NULL;
			}
		ASN1_OBJECT_free(a->algorithm);
		a->algorithm=OBJ_nid2obj(type->pkey_type);
		if (a->algorithm == NULL)
			{
			ASN1err(ASN1_F_ASN1_SIGN,ASN1_R_UNKNOWN_OBJECT_TYPE);
			goto err;
			}
		if (a->algorithm->length == 0)
			{
			ASN1err(ASN1_F_ASN1_SIGN,ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
			goto err;
			}
		}
	inl=i2d(data,NULL);
	buf_in=(unsigned char *)OPENSSL_malloc((unsigned int)inl);
	outll=outl=NEXUS_PKEY_SIZE;
	buf_out=(unsigned char *)OPENSSL_malloc((unsigned int)outl);
	if ((buf_in == NULL) || (buf_out == NULL))
		{
		outl=0;
		ASN1err(ASN1_F_ASN1_SIGN,ERR_R_MALLOC_FAILURE);
		goto err;
		}
	p=buf_in;

	i2d(data,&p);
	Nexus_SignUpdate(&ctx, (unsigned char *)buf_in,inl);
	if (!Nexus_SignFinal(&ctx,(unsigned char *)buf_out,
			(unsigned int *)&outl))
		{
		outl=0;
		ASN1err(ASN1_F_ASN1_SIGN,ERR_R_EVP_LIB);
		goto err;
		}
	if (signature->data != NULL) OPENSSL_free(signature->data);
	signature->data=buf_out;
	buf_out=NULL;
	signature->length=outl;
	/* In the interests of compatibility, I'll make sure that
	 * the bit string has a 'not-used bits' value of 0
	 */
	signature->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
	signature->flags|=ASN1_STRING_FLAG_BITS_LEFT;
err:
	NexusCtx_cleanup(&ctx);
	if (buf_in != NULL)
		{ OPENSSL_cleanse((char *)buf_in,(unsigned int)inl); OPENSSL_free(buf_in); }
	if (buf_out != NULL)
		{ OPENSSL_cleanse((char *)buf_out,outll); OPENSSL_free(buf_out); }
	return(outl);
	}

int ASN1_item_sign_nexus(const ASN1_ITEM *it, X509_ALGOR *algor1, X509_ALGOR *algor2,
	     ASN1_BIT_STRING *signature, void *asn,
	     const EVP_MD *type) {
	struct NexusCtx ctx;
	unsigned char *buf_in=NULL,*buf_out=NULL;
	int i,inl=0,outl=0,outll=0;
	X509_ALGOR *a;

	Nexus_SignInit(&ctx);
	for (i=0; i<2; i++)
		{
		if (i == 0)
			a=algor1;
		else
			a=algor2;
		if (a == NULL) continue;
                if (type->pkey_type == NID_dsaWithSHA1 ||
			type->pkey_type == NID_ecdsa_with_SHA1)
			{
			/* special case: RFC 3279 tells us to omit 'parameters'
			 * with id-dsa-with-sha1 and ecdsa-with-SHA1 */
			ASN1_TYPE_free(a->parameter);
			a->parameter = NULL;
			}
		else if ((a->parameter == NULL) || 
			(a->parameter->type != V_ASN1_NULL))
			{
			ASN1_TYPE_free(a->parameter);
			if ((a->parameter=ASN1_TYPE_new()) == NULL) goto err;
			a->parameter->type=V_ASN1_NULL;
			}
		ASN1_OBJECT_free(a->algorithm);
		a->algorithm=OBJ_nid2obj(type->pkey_type);
		if (a->algorithm == NULL)
			{
			ASN1err(ASN1_F_ASN1_ITEM_SIGN,ASN1_R_UNKNOWN_OBJECT_TYPE);
			goto err;
			}
		if (a->algorithm->length == 0)
			{
			ASN1err(ASN1_F_ASN1_ITEM_SIGN,ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
			goto err;
			}
		}
	inl=ASN1_item_i2d(asn,&buf_in, it);
	outll=outl=NEXUS_PKEY_SIZE;
	buf_out=(unsigned char *)OPENSSL_malloc((unsigned int)outl);
	if ((buf_in == NULL) || (buf_out == NULL))
		{
		outl=0;
		ASN1err(ASN1_F_ASN1_ITEM_SIGN,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	Nexus_SignUpdate(&ctx,(unsigned char *)buf_in,inl);
	if (!Nexus_SignFinal(&ctx,(unsigned char *)buf_out,
			(unsigned int *)&outl))
		{
		outl=0;
		ASN1err(ASN1_F_ASN1_ITEM_SIGN,ERR_R_EVP_LIB);
		goto err;
		}
	if (signature->data != NULL) OPENSSL_free(signature->data);
	signature->data=buf_out;
	buf_out=NULL;
	signature->length=outl;
	/* In the interests of compatibility, I'll make sure that
	 * the bit string has a 'not-used bits' value of 0
	 */
	signature->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
	signature->flags|=ASN1_STRING_FLAG_BITS_LEFT;
err:
	NexusCtx_cleanup(&ctx);
	if (buf_in != NULL)
		{ OPENSSL_cleanse((char *)buf_in,(unsigned int)inl); OPENSSL_free(buf_in); }
	if (buf_out != NULL)
		{ OPENSSL_cleanse((char *)buf_out,outll); OPENSSL_free(buf_out); }
	return(outl);
	}
