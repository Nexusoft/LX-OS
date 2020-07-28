#ifndef __CA_H__
#define __CA_H__

/* XXX this should go away and be replaced with x509 construct */

/* generate an x509 from "common_name" certifying pubkey*/
int generate_credential(X509 *newid, RSA *pubkey, RSA *privkey,
			char *common_name, BIO* extcnf, char *outfile, char *subject);

#endif
