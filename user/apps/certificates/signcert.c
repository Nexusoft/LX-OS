/** NexusOS: create signed certificates on behalf of the Nexus kernel

    This application, signcert.app, is part of the TCB and may only be
    invoked by the kernel.

    Creates an X509 cert with extended attributes of the type
    ``process.$pid says S''

    The certificate is signed with the kernel's private key (NSK),
    in effect generating the label 
    ``kernel says process.%pid says S''
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/guard.h>
#include <nexus/ca.h>

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <Thread.interface.h>

#define EXTENSIONS_FILE    "/tmp/exts.cnf"
// X509 wants it in the #.#. ... format, maybe something more meaningful
// such as OS version
#define EXT_PREFIX         "1.0."
#define COMMON_NAME        "sysinfo"

// SHA1 calculated on devbox with sha1sum on build/kernel/init/nexus
#define KERNEL_SHA1        "a5796949bfc2d6d4ee5d4177ba7e4794bf07e585"

static int
usage(const char *execpath)
{
    fprintf(stderr, "Usage: %s -s <keyfile> <outfile> <name> <stmts> to create a signed certificate of statements\n", execpath);
    return 1;
}

static int
gen_cert(const char *privpath, const char *certpath, const char **stmts)
{
    RSA *privkey = NULL, *pubkey = NULL;
    X509 *cert = NULL;
    BIO *exts = NULL;
    FILE *exts_file;
    int ret, i;
    char buf[1024], *ptr;
    
    if (!stmts)
        return 1;

    privkey = rsakey_private_import_file(privpath);
    if (!privkey) {
        fprintf(stderr, "Private key import failed\n");
        ret = 2;
        goto cleanup;
    }

    pubkey = rsakey_public_import(rsakey_public_export(privkey));
    if (!pubkey) {
        fprintf(stderr, "Public key export failed\n");
        ret = 2;
        goto cleanup;
    }

    cert = X509_new();
    if (!cert) {
        fprintf(stderr, "X.509 certificate creation error\n");
        ret = 3;
        goto cleanup;
    }

    exts_file = fopen(EXTENSIONS_FILE, "w+");
    for (i = 0; i < 64 && stmts[i]; i++) 
        fprintf(exts_file, "%s%d=ASN1:UTF8String:%s\n",
                EXT_PREFIX, i, stmts[i]);

    /* If there is no statement, there is no need for delegation */
    if (stmts[0]) {
        snprintf(buf, 1023, "%s", stmts[0]);
        /* Read the process.<pid> part of the statement */
        strtok(buf, " ");
        strtok(NULL, " ");
        ptr = strtok(NULL, " ");
        if (ptr && !strncmp("process.", ptr, 8))
            fprintf(exts_file, "%s%d=ASN1:UTF8String:name.kernel says %s speaksfor sha1.<<%s>>",
                    EXT_PREFIX, i, ptr, KERNEL_SHA1);
    }

    fclose(exts_file);

    exts = BIO_new_file(EXTENSIONS_FILE, "r");
    if (!exts) {
        fprintf(stderr, "Cannot read the extensions file\n");
        ret = 3;
        goto cleanup;
    }

    ret = generate_credential(cert, pubkey, privkey, "name.kernel",
                              exts, (char *)certpath, basename(certpath)); 

cleanup:
    rsakey_destroy(privkey);
    rsakey_destroy(pubkey);
    BIO_free(exts);
    X509_free(cert);
    return ret;
}

int
main(int argc, char **argv)
{
    if (argc < 5)
        return usage(argv[0]);

    switch (argv[1][1]) {
        case 's' : return gen_cert(argv[2], argv[3], (const char **)&argv[4]);
        default  : return usage(argv[0]);
    }

    return 0;
}
