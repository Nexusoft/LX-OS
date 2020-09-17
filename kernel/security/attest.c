/** NexusOS: attestation by the kernel */

#include <nexus/defs.h>
#include <nexus/elf.h>
#include <nexus/thread.h>
#include <nexus/guard.h>

#include <nexus/attest.h>

// SHA1 hash calculated on devbox with sha1sum build/boot/bin/sign.app
static const char signapp_sha1[20] = {0x8a, 0x77, 0xc5, 0x51, 0x0a,
		      		      0x24, 0xc6, 0x63, 0x5b, 0x1b,
		   		      0x69, 0x3c, 0xda, 0x65, 0x7e,
		 		      0xe4, 0x72, 0x91, 0x7c, 0xf0};

static const char certapp_sha1[20] = {0x8a, 0x77, 0xc5, 0x51, 0x0a,
		      		      0x24, 0xc6, 0x63, 0x5b, 0x1b,
		   		      0x69, 0x3c, 0xda, 0x65, 0x7e,
		 		      0xe4, 0x72, 0x91, 0x7c, 0xf0};

/** Write the parameter sha1 into parameter hex in hexadecimal format
    @param hex must be a buffer of at least 41B
    @param sha1 must be a buffer holding a 160b sha1 */
static void
nxattest_sha1hex(char *hex, const char *sha1)
{
    int i;
    
    for (i = 0; i < 20; i++) 
        sprintf(hex + 2*i, "%02x", sha1[i]);
    hex[40] = 0;
}

/** Add a credential that a process speaksfor its process hash:
    sha1.<<bytes>> says process.<pid> speaksfor sha1.<<bytes>> */
int 
nxattest_sha1_addcred(void)
{
	const char header[] = "sha1.<<";
	const char middle[] = ">> says process.%d speaksfor sha1.<<";
	const char footer[] = ">>";
	char buf[256];
	int off;

	// write header
	off = sizeof(header) - 1;
	memcpy(buf, header, off);
	nxattest_sha1hex(buf + off, curt->ipd->sha1);
	off += 40; // sha1 length

	// write middle and footer
	off += sprintf(buf + off, middle, curt->ipd->id);
	nxattest_sha1hex(buf + off, curt->ipd->sha1);
	off += 40;
	memcpy(buf + off, footer, sizeof(footer));

	// write footer
	nxguard_cred_add_raw(buf);
	return 0;
}

/** Return a process hash to the process 
    NB: leaking this is not a privacy issue, as Unix 'ps' and 'top'
        similarly expose (the name of) any user's processes on a
 	multiuser system */
int 
nxattest_sha1_get(int pid, char * user_sha1)
{
	IPD *ipd;

	if (pid < 0)
		return -1;

	// lookup process by passed id.
	if (pid == 0)
		ipd = curt->ipd;
	else
		ipd = ipd_find(pid);
	if (!ipd)
		return -1;
	// no need for copy_to_user. memcpy to curt is safe w/o virtual mem 
	memcpy(user_sha1, ipd->sha1, sizeof(ipd->sha1));
	return 0;
}

/** Helper to call sign.app or signcert.app 
    XXX change the crazy call sematics (filepath, id, ..) 
 
    @param class is used to define a filepath, e.g., 'process' 
    @param id is used to define a filepath
    @param filepath must be at least 128B long
           on successful return it will hold the filepath
    @param attestations is a NULL terminated array of
           NAL statements that will written
    @param do_cert selects between generation of 
           X509 cert or NAL 'signed formula' */
static int
__says_upcall(const char *class, int id, const char **attestations, 
	      char *filepath, int do_cert)
{
	UThread *ut;
	const char *argv[70], *app, *app_sha1, *extension;
	int i;

	// select based on goal (label or certificate)
	if (do_cert) {
		app = "signcert.app";
		app_sha1 = certapp_sha1;
		extension = "crt";
	}
	else {
		app = "sign.app";
		app_sha1 = signapp_sha1;
		extension = "pem";
	}

	// create label-specific filepath
	snprintf(filepath, 127, "/tmp/label.%s.%d.%s", class, id, extension);

	// setup arguments
	argv[0] = app;
	argv[1] = "-s";
	argv[2] = "/bin/nsk.priv.pem";
	argv[3] = filepath;
	for (i = 4; i < 68 && attestations[i-4]; i++) 
		argv[i] = attestations[i-4];
	argv[i] = 0;

	// create process
	ut = elf_load(argv[0], 1, i, (char **) argv);
	if (!ut) {
		printkx(PK_PROCESS, PK_WARN, "[sha1] could not start sign app\n");
		return -1;
	}

#if 0
	// verify sign.app signature: it is part of the TCB
	for (i = 0; i < 20; i++)
		if (ut->ipd->sha1[i] != app_sha1[i]) {
			printkx(PK_PROCESS, PK_WARN, "[sha1] incorrect sign app\n");
			return 1;
		}
#else
	// XXX disabled as long as app keeps changing
	printk("XXX reenable signing app SHA1 verification\n");
#endif

	// execute
	if (elf_exec_direct(ut, PROCESS_WAIT | PROCESS_QUIET)) {
		printkx(PK_PROCESS, PK_WARN, "[sha1] sign app failed\n");
		return 1;	
	}

	return 0;
}

/** Generate an X506 with attribute 
    ``kernel says process.X speaksfor sha1<<0xab...>>>' */
int 
nxattest_sha1_getcert(int pid, char * filepath)
{
	IPD *ipd;
	char **attestations;
        char sha1hex[40];
	int ret;

	if (pid < 0)
		return -1;

	// lookup process by passed id.
	if (pid == 0)
		ipd = curt->ipd;
	else
		ipd = ipd_find(pid);
	if (!ipd)
		return -1;

	attestations = galloc(2 * sizeof(void *));
        attestations[0] = galloc(256);
        attestations[1] = NULL;

	// create label
        nxattest_sha1hex(sha1hex, ipd->sha1);
        snprintf(attestations[0], 255, 
                 "name.kernel says process.%d speaksfor sha1<<%40s>>", 
                  ipd->id, sha1hex);

        // call certificate generation process
        ret = __says_upcall("getcert", ipd->id, (const char **)attestations, 
                            filepath, 1);

	gfree(attestations[0]);
	gfree(attestations);
	return ret;
}

/** Return ``kernel says process.X says sha1(<sha1 of stmt>)'' 
    @param do_cert toggles between generation of a certificate or a label
    @return 0 on success, failure otherwise */
int 
nxattest_sha1_says(IPD *ipd, char **stmts, char *filepath, int cert)
{
	// easy allocation, also upper limits number of statements
    	char *attestations[64];
	int alen, i, j, ret;

	// sanity check input
	if (!stmts)
		return -1;

    	for (i = 0; i < 64 && stmts[i]; i++) {
	    	// create NAL statement
		attestations[i] = (char *)galloc(1024);
	    	alen = snprintf(attestations[i], 1023, 
		    	"name.kernel says process.%d says %s",
		    	ipd->id, stmts[i]);
		// guard against overflow
		if (alen == 1023) {
			i++;
			ret = -1;
			goto cleanup;
		}
	}

	// too many statements
	if (i == 64) {
		ret = -1;
		goto cleanup;
	}

	attestations[i] = 0;
	ret =  __says_upcall("process", ipd->id, (const char **)attestations, filepath, cert);

cleanup:
    for (j = 0; j < i; j++)
        gfree(attestations[j]);
    
    return ret;
}

/** Generate label 'kernel says account:x owns quantum:y' */
int
nxattest_sched_quantum(int quantum)
{
	char *attestations[2];
	char attestation[256];
	char filepath[128];
	int account, ret;

	account = nxsched_quantum_getaccount(quantum);

	// do not generate credential for best effort account 0, as that may be replaced
	// at any time by a real reservation account
	if (account == 0)
		return -1;

	snprintf(attestation, 255, "name.kernel says name.kernel.resmgr.account.%d "
			           "owns name.kernel.resmgr.cpusched.quantum.%d\n", 
		 account, quantum);

	attestations[0] = attestation;
	attestations[1] = NULL;

	return __says_upcall("account", account, (const char **)attestations, 
			     filepath, 1);
}

/* vim: set ts=8 sw=8: */
