/** NexusOS: application that signs statements on behalf of the Nexus kernel
             
  	     This application, sign.app, is part of the TCB and may only be
	     invoked by the kernel.
	     The key it uses to sign is called the Nexus Signing Key, or NSK.

	     For trustworthy remote attestation, the NSK can be sent to a
	     remote certificate authority, signed by a local attestation 
	     identity key. The CA will return a certificate that states that
	     the 
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/rsa.h>

#include <nexus/sigform.h>
#include <nexus/formula.h>
#include <nexus/guard.h>
#include <nexus/test.h>
#include <nexus/pem.h>

#define STMT_SIGN 	    "pem(%%{bytes:%d}) says %s"
#define STMT_DELEGATE	"pem(%%{bytes:%d}) says name.kernel speaksfor pem(%%{bytes:%d})"

/** Create a new signing key and write it to filepath */
static int
nsk_create(const char *filepath)
{
	RSA *key;

    /* XXX: rsakey_create calls rand_init() which has a weird bug of hanging the
     * process cleanup routine
     */
	key = rsakey_create();
	if (rsakey_private_export_file(key, filepath)) {
		fprintf(stderr, "Key export failed\n");
		return 1;
	}
	rsakey_destroy(key);
	return 0;
}

/** Load an existing signing key from disk */
static RSA *
nsk_load(const char *filepath)
{
	return rsakey_private_import_file(filepath);
}

/** Register the key with a remote nexus certificate authority
    to receive an X509 certificate of Nexus authenticity */
static int
nsk_register(RSA *key, const char *hostname)
{
	if (!key)
		return 1;

	// XXX implement
	fprintf(stderr, "not implemented: register\n");
	rsakey_destroy(key);
	return 1;
}

static int
__nsk_sign(char *template, RSA *key, const char *filepath)
{
	Form *form;
	char *pubkey, *der, *sder, *spem;
	int fd;

	if (strlen(template) > 1024) {
		fprintf(stderr, "statement exceeds maximum size (1024B)\n");
		return 1;
	}

	// serialize public key
	pubkey = rsakey_public_export(key);
	if (!pubkey)
		ReturnError(1, "Error at pubkey export");

	// create formula
	form = form_fmt(template, pubkey, pubkey);
	if (!form)
		ReturnError(1, "Error at create statement");

	// serialize into DER form
	der = (char *) form_to_der(form);
	if (!der)
		ReturnError(1, "Error at create DER");

	// create signed version
	sder = sigform_create(der, key);
	if (!sder)
		ReturnError(1, "Error at create sDER");
	spem = der_to_pem(sder);
	if (!spem)
		ReturnError(1, "Error at create sPEM");
	
	// write PEM encoded signed statement to file
	fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		ReturnError(1, "Error opening file");
	write(fd, spem, strlen(spem));
	write(fd, "\n", 1);
	close(fd);

	// cleanup
	free(sder);
	free(der);
	form_free(form);
	rsakey_destroy(key);
	return 0;
}

/** Output a signed statement ``pem(nsk) says <stmt>''
    XXX may want to switch to ``name.kernel says <stmt>'' */
static int
nsk_sign(RSA *key, const char *outfile, const char **stmts)
{
	char buf[4000];
    int i, off = 0;

    if (!stmts)
        return 1;

    off += snprintf(buf, 3999, STMT_SIGN, PUBKEY_LEN, "");
    /* XXX: fix parsing error (form_fmt) above and change this */
    for (i = 0; i < 64 && stmts[i]; i++) 
        off += snprintf(buf + off, 3999 - off,
                        i ? " and %s" : "%s", stmts[i]);

    buf[off] = 0;
  	return __nsk_sign(buf, key, outfile);
}

/** Output a delegation statement 
    ``pem(nsk) says name.kernel speaksfor pem(nsk)'' 
    XXX may want to cache the signed formula */
static int
nsk_delegate(RSA *key, const char *outfile)
{
	char buf[2000];

	snprintf(buf, 1999, STMT_DELEGATE, PUBKEY_LEN, PUBKEY_LEN);
  	return __nsk_sign(buf, key, outfile);
}

static int
usage(const char *execpath)
{
	fprintf(stderr, "Usage: %s -c <keyfile>           to create a new key\n"
			"       %s -r <keyfile> <host>            to register a key with a remote CA\n"
			"       %s -s <keyfile> <outfile> <stmts> to create signed statements\n" 
			"       %s -d <keyfile> <outfile>         to create a delegation statement\n"
			"\n"
			"where a signed statement is 'name.kernel says <stmt>' plus crypto hash\n"
			"and a delegation statement is 'pem(NSK) says name.kernel speaksfor pem(NSK)\n",
			execpath, execpath, execpath, execpath);
	return 1;
}

int
main(int argc, char **argv)
{
	if (argc < 3)
		return usage(argv[0]);

	switch (argv[1][1]) {
	case 'c': return nsk_create(argv[2]);
	case 'r': return nsk_register(nsk_load(argv[2]), argv[3]);
	case 's': return nsk_sign(nsk_load(argv[2]), argv[3], 
                              (const char **)&argv[4]);
	case 'd': return nsk_delegate(nsk_load(argv[2]), argv[3]);
	default : return usage(argv[0]);
	}
}

