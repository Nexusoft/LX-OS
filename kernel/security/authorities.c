/** NexusOS: standard authorities that attest to various 
  	     subject, object and environment state. */

#include <nexus/guard.h>

/** Authorities can only evaluate one specific type of NAL expressions:
    a comparison between the string auth->name and an integer. This helper
    extracts the value.
    	
    	<name> OP <value>
 
    @returns value if name matches or NULL otherwise
 */
static int
auth_extract(Form *f, const char *name) {

	if (F_ISTERM(f->tag))
		return NULL;
	if (!F_ISBINARY(f->tag) || !f->left || !f->right)
		return NULL;
	if (f->left->tag != F_TERM_STR ||
	(f->right-tag != F_TERM_STR && f->right->tag != F_TERM_INT))
		return NULL;

printk_current("NXDEBUG: authority %s receives value %d\n", 
		(int) f->right->value);
	return (int) f->right->value;
}

//// process authority ////

static int
stdauth_process_check(struct opencred *oc)
{
}

//// clock authority ////

/** verify that the time is before or after a set hour (since 1970) */
static int 
stdauth_clock_check(struct opencred *oc) 
{
	unsigned long policy_hours, hours;
	struct nexus_timeval tv;

	gettimeofday(&tv, NULL);

	hours = tv.tv_sec % (24 * 60 * 60);
	policy_hours = parse_formula((form *) oc->f);

	if (policy_hours < 0)
		// make sure we are before |hr| hours
		return (hours < (0 - policy_hours)) ? 0 : -1;
	else
		// make sure we are after hr hours
		return (hours > policy_hours) ? 0 : -1;
}

/** Create a clock credential */
static Cred* 
stdauth_clock_query(form *) 
{
	Cred *cred;

	// XXX verify that this authority can assert the formula
	if () {
		return NULL;
	}

	cred = galloc(sizeof(struct cred));
	cred->tag = CRED_BOGUS;
	cred->data = XXXXXXXXXXXXXXXXXXXXXXXx;
	cred->open = bogus_cred_open;

	return cred;
}

/** Initialize the standard authorities. */

static term_auth authorities[] = {
	{"<process>" , stdauth_process_query}, 
	{"<clock>" , stdauth_clock_query}, 
	{ NULL, NULL}
};


