#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#include "nexus-cert.h"

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

#include <assert.h>


#define LOCAL_ADDR 0

//#define HAVE_TPM

unsigned char nonce[20];

//const char *from = "The Nexus <ashieh@cs.cornell.edu>";
const char *from = "ashieh@cs.cornell.edu";
const char *localdomain = "sbox2.cs.cornell.edu";
//const char *from_addr = "nexus@cs.cornell.edu";
const char *from_addr = "ashieh@cs.cornell.edu";
const char server_addr[4] = { 128, 84, 223, 143};

#define CLIENT_PORT (2000)

void send_email(char *recipients[], int num_recipients, char *codehashcert,
		char *cert, char *body, X509 *signcert,
		STACK_OF(X509) *cert_stack, EVP_PKEY *pkey);

char *bintostr(unsigned char *data, int len) {
  int i;
  char *rval = calloc(len * 2, 1);
  for(i=0; i < len; i++) {
    sprintf(rval + i * 2, "%02X", data[i]);
  }
  return rval;
}


const char *kernel_password = "foobar";
int kernel_password_callback(char *buf, int bufsiz, int verify,
			     void *cb_tmp) {
	int len = strlen(kernel_password);
	if(len > bufsiz) {
		printf("not enough space for kernel password!\n");
		len = bufsiz;
	}
	memcpy(buf, kernel_password, len);
	return len;
}

int main(){
  unsigned char *codehashcert;
  int codehashsize;
  unsigned char *cert;
  int size;
  int i;

  // XXX read one from filesystem
  ERR_load_crypto_strings();
  OpenSSL_add_all_digests();
  OpenSSL_add_all_algorithms();

  nexus_cert_init();

  X509 *test_cert;
  EVP_PKEY *test_pkey;
  STACK_OF(X509) *cert_stack = sk_X509_new_null();
#if 0
  // generate our own x509 key
  {
	  X509_NAME *from = create_x509_email_name(from_addr, "Nexus E-mail client");
	  test_cert = X509_generate(from, &test_pkey);
	  printf("test_cert = %p, pkey = %p\n", test_cert, test_pkey);
  }
#else
  // Load x509 certs, x509 keys from different files
  {
	  BIO *ca_crt_bio = BIO_new_file("nexus-ca.crt", "rb");
	  BIO *kernel_crt_bio = BIO_new_file("nexus-kernel.crt", "rb");
	  BIO *kernel_key_bio = BIO_new_file("nexus-kernel.key", "rb");
	  printf("BIO new");

	  X509 *ca_cert = PEM_read_bio_X509(ca_crt_bio, NULL, NULL, NULL);

	  if(ca_cert == NULL) {
		  printf("Could not load CA certificate!\n");
		  openssl_print_error();
		  assert(0);
	  }
	  if(!sk_X509_push(cert_stack, ca_cert)) {
		  printf("Could not add CA's X509 certificate to stack\n");
		  openssl_print_error();
		  assert(0);
	  }
	  test_cert = PEM_read_bio_X509(kernel_crt_bio, NULL, NULL, NULL);
	  if(test_cert == NULL) {
		  printf("could not load kernel certificate\n");
		  openssl_print_error();
		  assert(0);
	  }
	  test_pkey = PEM_read_bio_PrivateKey(kernel_key_bio, NULL, 
					      (pem_password_cb *)kernel_password_callback, NULL);
	  if(test_pkey == NULL) {
		  printf("could not load private key\n");
		  openssl_print_error();
		  assert(0);
	  }

	  BIO_free(ca_crt_bio);
	  BIO_free(kernel_crt_bio);
	  BIO_free(kernel_key_bio);
	  printf("BIO free");

	  // ca_crt_bio => cert_stack
	  // kernel_crt_bio => test_cert
	  // kernel_key_bio => test_pkey
  }
#endif
  
  for(i=0; i < 20; i ++)
    nonce[i] = i;

  printf("press windows key to prove you are a human, and send an e-mail\n");
  printf("using nonce of: ");
  for (i = 0; i < 20; i++)
    printf("%02x ", nonce[i]);
  printf("\n");

#ifdef HAVE_TPM
  codehashsize = getCodeHashChain(&codehashcert, nonce);
  size = getPresence(&cert, nonce);
  dumpPresence(cert, size);
#else
  static char buf[128];
  static char buf1[128];
  cert = buf;
  size = 64;
  for(i=0; i < size; i++) {
    cert[i] = i;
  }
  codehashcert = buf1;
  codehashsize = 64;
  for(i=0; i < codehashsize; i++) {
    codehashcert[i] = i;
  }
#endif

  // Construct a X509 certificate


  X509 *signing_cert;
  EVP_PKEY *signing_pkey;
#if 0 // load from file
  {
  X509 *signing_cert;
  EVP_PKEY *signing_pkey;
  
  PKCS12 *signing_pkcs12 = NULL;
  BIO *p12_bio = BIO_new_file("testcert.p12", "rb");
  printf("decoding pkcs12 from file\n");
  
  signing_pkcs12 = d2i_PKCS12_bio(p12_bio, NULL);
  printf("Parsing pkcs structure %d, macdata = \n", *(int*)signing_pkcs12->version);
  char *passphrase = "foobar";
  if(PKCS12_verify_mac(signing_pkcs12, passphrase, 6)) {
	  printf("mac verified\n");
  } else {
	  printf("wrong passphrase!\n");
	  printf("error = %s\n", ERR_error_string(ERR_get_error(), NULL));
  }  
  int rval = PKCS12_parse(signing_pkcs12, passphrase, &signing_pkey, &signing_cert, NULL);
  printf("%p parse rval = %d, signing cert = %p, signing key = %p\n", signing_pkcs12, rval, signing_cert, signing_pkey);
  if(rval == 0) {
	  printf("Could not parse pkcs12 file!\n");
	  printf("error %s\n", ERR_error_string(ERR_get_error(), NULL));
	  exit(-1);
  }

  X509_print_cert(signing_cert);
  }
#else
  signing_cert = test_cert;
  signing_pkey = test_pkey;
#endif

  char *recipients[] = 
    //    { "ashieh@cs.cornell.edu", "egs@cs.cornell.edu", "djwill@cs.cornell.edu" };
	  //{ "ashieh@cs.cornell.edu" };
	  { "ashieh@cs.cornell.edu", "egs@cs.cornell.edu" };
  char *body = "
Hello world (with physical presence)";
  char *physstr = bintostr(cert, size);
  char *hashstr = bintostr(codehashcert, codehashsize);

  printf("This email is being sent from email.c\n");
  send_email(recipients, sizeof(recipients) / sizeof(recipients[0]), hashstr, physstr, body, 
	     signing_cert, cert_stack, signing_pkey);
  free(physstr);
  free(hashstr);
  return 0;
}

enum SMTP_Class {
	SMTP_FULL,
	SMTP_INTERMEDIATE
};

void wait_for_smtp_ok(int fd, enum SMTP_Class class) {
	char buf[4096];
	int pos = 0;
	char classchar;
	switch(class) {
	case SMTP_FULL:
		classchar = '2';
		break;
	case SMTP_INTERMEDIATE:
		classchar = '3';
		break;
	}
	while(1) {
		int len = recv(fd, buf+pos, 4096 - pos, 0);
		if(len <= 0) continue;
		pos += len;
		// Scan what we've seen
		buf[pos] = 0;
		if(buf[0] == classchar) {
			int i;
			for(i=0; i < pos-1; i++) {
				if(buf[i] == '\r' && buf[i+1] == '\n') {
					buf[i] = '\0';
					// printf("got %s\n", buf);
					goto done;
				}
			}
		}
	}
 done:
	return;
}

void send_smtp_command(int fd, char *cmd, int len, enum SMTP_Class messageclass) {
	send(fd, cmd, len, 0);
	send(fd, "\r\n", 2, 0);
	wait_for_smtp_ok(fd, messageclass);
}

char *mime_boundary = "------------nexusboundary";

BIO *BIO_from_string(char *str) {
	BIO *rval = BIO_new(BIO_s_mem());
	BIO_puts(rval, str);
	return rval;
}


void send_email(char *recipients[], int num_recipients, char *codehashcert, char *cert, char *body,
		X509 *signcert, STACK_OF(X509) *cert_stack, EVP_PKEY *pkey) {
	int fd = socket(PF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	int err;

	printf("got socket %d\n", fd);

	addr.sin_addr.s_addr = LOCAL_ADDR;
	addr.sin_port = htons(CLIENT_PORT);
	err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));

	struct sockaddr_in dest;
	// char server_addr[4] = { 128, 84, 98, 19};
	dest.sin_family = AF_INET;
	memcpy(&dest.sin_addr.s_addr, server_addr, 4);
	dest.sin_port = htons(25);

	printf("pre connect, %p %d\n", &dest, sizeof(dest));
	err = connect(fd, (struct sockaddr *)&dest, sizeof(dest));
	printf("connect of %d returned %d\n", fd, err);

	// Start SMTP processing
	wait_for_smtp_ok(fd, SMTP_FULL);
	static char cmdbuf[4096];
	static char tobuf[4096];
	static char bodybuf[2048];
	sprintf(cmdbuf, "HELO %s", localdomain);
	send_smtp_command(fd, cmdbuf, strlen(cmdbuf), SMTP_FULL);

	sprintf(cmdbuf, "MAIL FROM: <%s>", from_addr);
	send_smtp_command(fd, cmdbuf, strlen(cmdbuf), SMTP_FULL);
	
	int i;
	for(i=0; i < num_recipients; i++) {
		sprintf(cmdbuf, "RCPT TO: <%s>", recipients[i]);
		send_smtp_command(fd, cmdbuf, strlen(cmdbuf), SMTP_FULL);
	}
	int j = 0;
	for(i=0, j=0; i < strlen(body) + 1; i++, j++) {
		if(body[i] != '\n') {
			bodybuf[j] = body[i];
		} else {
			bodybuf[j++] = '\r';
			bodybuf[j] = '\n';
		}
	}

	printf("gen sig %p %p\n", signcert, pkey);
	BIO *bio_body = BIO_from_string(bodybuf);
#if 0
	 STACK_OF(X509) *cert_stack = sk_X509_new_null();
	if(!sk_X509_push(cert_stack, signcert)) {
		printf("Could not add x095 certificate to stack\n");
		assert(0);
	}
#endif
#if 1
	PKCS7 *sig_p7 = PKCS7_sign(signcert, pkey, cert_stack, bio_body, PKCS7_DETACHED);
#else
	PKCS7 *sig_p7 = PKCS7_sign(signcert, pkey, NULL, bio_body, PKCS7_DETACHED);
#endif
	//PKCS7 *sig_p7 = PKCS7_sign(signcert, pkey, cert_stack, bio_body, PKCS7_DETACHED);
	BIO_free(bio_body);

	sprintf(cmdbuf, "DATA");
	send_smtp_command(fd, cmdbuf, strlen(cmdbuf), SMTP_INTERMEDIATE);

	tobuf[0] = 0;
	for(i=0; i < num_recipients; i++) {
		sprintf(tobuf + strlen(tobuf), "%s%s", recipients[i],
			i != num_recipients - 1 ? ", " : "");
	}
#if 0
	sprintf(cmdbuf, 
"From: %s
User-Agent: Nexus
X-Nexus-Hash-Certificate: %s
X-Nexus-Presence-Certificate: %s
To: %s
Subject: A test message
Content-Type: multipart/signed; protocol=\"application/x-pkcs7-signature\"; micalg=sha1; boundary=\"%s\"

This is a cryptographically signed message in MIME format.

",
		from, codehashcert, cert, tobuf, mime_boundary);
	printf("send0\n");
	send(fd, cmdbuf, strlen(cmdbuf), 0);
	printf("send1\n");
#else
	sprintf(cmdbuf, 
		"From: %s
User-Agent: Nexus
X-Nexus-Hash-Certificate: %s
X-Nexus-Presence-Certificate: %s
To: %s
Subject: A test message
",
		from, codehashcert, cert, tobuf);
	printf("send0\n");
	send(fd, cmdbuf, strlen(cmdbuf), 0);
	printf("send1\n");
#endif

#if 0
	// Output body text
	sprintf(cmdbuf, 
"%s
Content-Type: text/plain; charset=ISO-8859-1; format=flowed
Content-Transfer-Encoding: 7bit

",
		mime_boundary);
	send(fd, cmdbuf, strlen(cmdbuf), 0);
	send(fd, bodybuf, strlen(bodybuf), 0);

	// Output the signature
	sprintf(cmdbuf, 
"%s
Content-Type: application/x-pkcs7-signature; name=\"smime.p7s\"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename=\"smime.p7s\"
Content-Description: S/MIME Cryptographic Signature

",
		mime_boundary);
	send(fd, cmdbuf, strlen(cmdbuf), 0);
	xxx sigbuf;
	send(fd, sigbuf, strlen(sigbuf), 0);
#else
	BIO *bio_signature = BIO_new(BIO_s_mem());
	bio_body = BIO_from_string(bodybuf);
	if(!SMIME_write_PKCS7(bio_signature, sig_p7, bio_body, PKCS7_DETACHED)) {
		printf("smime_write failed\n");
		return 0;
	}
	BIO_free(bio_body);
	char *smime_text;
	int len = BIO_get_mem_data(bio_signature, &smime_text);
	printf("sending %d for text\n", len);
	send(fd, smime_text, len, 0);
	BIO_free(bio_signature);
#endif
	printf("send2\n");

	// Output end of message token for SMTP
	send(fd, "\r\n.\r\n", 5, 0);
	printf("send3\n");
}
