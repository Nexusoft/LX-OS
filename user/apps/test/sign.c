/** NexusOS: test kernel signature generation */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <nexus/test.h>
#include <nexus/pem.h>
#include <nexus/guard.h>
#include <nexus/formula.h>
#include <nexus/sigform.h>
#include <nexus/Thread.interface.h>

#define STMTLEN 3000

/** Read, verify and present a label from a PEM encoded file */
static int
read_labelfile(void)
{
	Form *form;
	char filepath[128], pem[2000];
	char *sder, *der, *pretty;
	int len, fd;

	// open label file
	snprintf(filepath, 127, "/tmp/label.process.%d.pem", getpid());
	fd = open(filepath, O_RDONLY);
	if (fd < 0)
		ReturnError(1, "error at open labelfile");

	// read label from disk
	len = read(fd, pem, 2000);
	if (len < 1 || len == 2000)
		ReturnError(1, "error reading labelfile");

	// verify label 
	sder = der_from_pem(pem);
	if (!sder)
		ReturnError(1, "error decoding sDER");
	if (sigform_verify(sder))
		ReturnError(1, "not a valid label");

	// extract formula
	der = sigform_get_formula(sder);
	if (!der)
		ReturnError(1, "error decoding DER");
	form = form_from_der((void *) der);
	if (!form)
		ReturnError(1, "error decoding formula");
	pretty = form_to_pretty(form, 80);
	if (!pretty)
		ReturnError(1, "error generating printable formula");

	// print formula
	printf("signed: %s\n", pretty);

	// cleanup
	free(pretty);
	form_free(form);
	free(der);
	free(sder);
	
	printf("[OK]\n");
	return 0;
}

int
main(int argc, char **argv)
{
	char filepath[128], *statements[2];
	int i, off, len;

	test_skip_auto();

	if (argc > 64) {
		fprintf(stderr, "usage: %s <stmts>\n", argv[0]);
		return 1;
	}
	
	if (argc > 1)
		statements[0] = argv[1];
	else
		statements[0] = "a=b";
	statements[1] = NULL;

	printf("Assure that /usr/etc/nsk.priv.pem exists.\n"
	       "To generate, run 'sign.app -c /usr/etc/nsk.priv.pem'\n");

	// request label
	Thread_Sha1_Says(statements, filepath);
	
	return read_labelfile();
}

