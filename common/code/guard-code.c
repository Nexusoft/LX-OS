/** NexusOS: the default reference monitor, or 'guard'

    The guard evaluates a deducation and check assumptions, where assumptions 
    are supported either by stored credentials or active authorities
 */

#include <nexus/log.h>
#include <nexus/rdtsc.h>

// UGLY XXX: move to header file
void judge_free(Judge *f);

// HACK: give embedded guards access to proof tuple (a case of introspection)
__thread struct nxguard_tuple *tuple_active;

/** Lookup an authority from an assumption.
    Can be one of
  	pem(..) says S
  	ipc.x   says S
 	name.z  says S 
 
    @return the ipc port for this authority or -1 on failure */
static int 
auth_lookup(Form *f)
{
	int portnum;

	// no "principal says S"
	if (f->tag != F_STMT_SAYS || !f->left)
		return -1;

	// ipc.X or name.Y
	if (f->left->tag == F_TERM_CSUB && 
	    f->left->left &&
	    f->left->left->data &&
	    f->left->right &&
	    (f->left->left->tag == F_TERM_SVAR)) {

		// ipc
		if (f->left->right->tag == F_TERM_INT &&
		    !strcmp(f->left->left->data, "ipc")) {
			// parameter safety is checked on use
			return f->left->right->value;	
		}
	
		// name
		if (f->left->right->tag == F_TERM_SVAR && 
		    !strcmp(f->left->left->data, "name")) {
			portnum = nxguardsvc_name_get(f->left->right->data);
			return portnum ? portnum : -1;
		}

		return -1;
	}

	// pem(..)
	if (f->left->tag == F_TERM_PEM && 
	    f->left->left && 
	    (f->left->left->tag & F_IS_DATA) &&
	    f->left->left->len == PUBKEY_LEN) {
		portnum = nxguardsvc_name_get((char *) f->left->left->data);
		return portnum ? portnum : -1;
	}

	return -1;
}


static unsigned long
__guard_get_nonce(Form *f, int type)
{
	// parse goal, must be of form ("X.i says ...")
	if (f->tag != F_STMT_SAYS || !f->left)
		return -1;

	// it seems the last subprincipal (z in X.y.z) is not last, but second
	f = f->left;
	
	if (!f->left || !f->right)
		return -1;

	// good: found the version
	if (f->right->tag != type) 
		return -1;

	return (type == F_TERM_INT) ? f->right->value : (unsigned long) f->right->data;
}

/** Make sure a deduction is sound and leads to the goal as single conclusion 

    reusing the evaluator (eval_reset()) avoids regenerating all axioms, 
    but is not reentrant-safe (required) and showed NO performance gain.

    @return proof on success or NULL on error */
Judge *
guard_check_proof(struct goal *goal, const char *proof)
{
	static struct eval *eval;
	Judge *shown;
	int ret, dlen;

	eval = eval_create();

	if (guard_check_deduction(eval, proof)) {
		eval_free(eval);
		nxlog_write_ex(3, "BLOCKED: unsound proof\n");
		return NULL;
	}

	// compared to saved conclusion
	shown = PointerVector_deleteAt(&eval->stack, 0);
	eval_free(eval);
	
	if (form_cmp(goal->form, shown->concl)) {
		nxlog_write_ex(3, "BLOCKED: conclusion does not match goal\n");
		return NULL;
	}

	return shown;
}

/** precompute the information needed when querying authorities:
    the statements to ask authorities to attest to and
    the port that each authority is listening on

    @return 0 on success, -1 on failure */
static int
nxguard_auth_precompute(struct proof *proof, PointerVector *premises)
{
	int i;

	proof->num_auth = PointerVector_len(premises);
	nxlog_write_ex(4, "%d premise(s) to ask authorities about", proof->num_auth);

	if (proof->num_auth) {

		// allocate room for the two lists
		proof->auth_req = nxcompat_alloc(sizeof(char *) * proof->num_auth);
		proof->auth_der = nxcompat_calloc(proof->num_auth, sizeof(char *));
		proof->auth_form = nxcompat_calloc(proof->num_auth, sizeof(Form *));
		proof->auth_ports = nxcompat_alloc(sizeof(int) * proof->num_auth);

		// populate
		for (i = 0; i < proof->num_auth; i++) {
			Form *f;

			f = PointerVector_nth(premises, i);
			proof->auth_req[i] = form_to_pretty(f, 0);
			proof->auth_ports[i] = auth_lookup(f);

			// update: do not fail hard if there are missing creds:
			// these may be added (as tickets or authorities) at 
			// any moment, so set them to unresolved (port == -1)
			if (proof->auth_ports[i] == -1) {
				proof->auth_der[i] = (void *) form_to_der(f);
				proof->auth_form[i] = form_dup(f);
			}
		}
	}

	return 0;
}

/** Ask all authorities to reattest to their statements 
    @return AC_ALLOW_CACHE   if nothing to check
	    AC_ALLOW_NOCACHE if all authorities agree or
  	    AC_BLOCK_NOCACHE otherwise */
static int
nxguard_auth_check(struct proof *proof)
{
	int todo, i; 
	
	// no authorities? then allow and cache
	if (!proof->num_auth)
		return AC_ALLOW_CACHE;

	todo = proof->num_auth;
	for (i = 0; i < proof->num_auth; i++) {

		// if no authority is registered, this is a missing credential.
		// see if there is a suitable newly created ticket or authority
		if (proof->auth_ports[i] == -1) {
			assert(proof->auth_der[i]);
			assert(proof->auth_form[i]);

			// try to find a ticket
			if (!nxguardsvc_cred_chk(proof->auth_der[i])) {
				// set to -2: an ugly way to say that it was resolved
				// Note that it could be possible that all credentials
				// are now resolved by ticket and the decision can be cached.
				// This is NOT implemented (XXX).
				proof->auth_ports[i] = -2;

				// reclaim some space
				free(proof->auth_der[i]);
				proof->auth_der[i] = NULL;
				form_free(proof->auth_form[i]);
				proof->auth_form[i] = NULL;
			}
			else {
				// try to find an authority
				proof->auth_ports[i] = auth_lookup(proof->auth_form[i]);

				if (proof->auth_ports[i] >= 0) {
					// reclaim some space
					free(proof->auth_der[i]);
					proof->auth_der[i] = NULL;
					form_free(proof->auth_form[i]);
					proof->auth_form[i] = NULL;
				}
			}
		}

		// still not found
		if (proof->auth_ports[i] == -1)
			continue;

		// initially unresolved premise has since been resolved by ticket
		if (proof->auth_ports[i] == -2) {
			todo--;
			continue;
		}

		// special case: if the auth is the guard (i.e., us), skip IPC
		if (proof->auth_ports[i] == guard_authority_port) {
			if (nxguardsvc_auth_embedded(proof->auth_req[i]))
				todo--;
		}
		// common case: ask the authority over the IPC channel
		else if (nxguardsvc_auth_ask(proof->auth_ports[i], 
					     proof->auth_req[i])) {
			todo--;
		}
	}

	if (todo)
		nxlog_write_ex(3, "BLOCKED: %d unsupported assumption(s)\n", todo);

	return todo ? AC_BLOCK_NOCACHE : AC_ALLOW_NOCACHE;
}

/** Check correctness of an not yet verified proof
    This has two parts: 
    	(1) verify soundness of deduction and 
	(2) assert that all assumptions are substantiated by credentials 
            Nexus knows two types of credentials: 
	    (a) stored, cacheable, tickets and
 	    (b) fleeting authority requests (over IPC) 
 
    This function caches (1) and (2a). Only (2b) cannot be cached. 
   
    @return 0 on success */
int 
guard_check_full(struct goal *goal, struct proof *proof)
{
	PointerVector *premises;
	Judge *shown;
	int npremises, i;

	// verify soundness of deduction
	shown = guard_check_proof(goal, proof->deduction);
	if (!shown) {
		proof->status = PF_UNSOUND;
		return 0;
	}

	// verify premises of deduction ("assume X") 
	// 1: try to match against stored credentials
	premises = &shown->hyp;
	npremises = PointerVector_len(premises);
	for (i = 0; i < npremises; i++) {
		char *der;
		Form *f;
		
		f = PointerVector_nth(premises, i);
		der = (char *) form_to_der(f);
		if (!nxguardsvc_cred_chk(der)) {
			form_free(f);
			PointerVector_deleteAt(premises, i);
			i--;
			npremises--;
		}
		free(der);
	}

	// verify premises
	// (2): need to ask authorities 
	//      this must be done at each call. precompute as much as possible
	// update proof for faster subsequent runs
	// deduction and tickets are cached, only need to rerun auth requests
	if (nxguard_auth_precompute(proof, premises)) {
		proof->status = PF_UNSOUND;
		return 0;
	}

	proof->status = PF_SOUND;
	judge_free(shown);
	return 0;
}

/** Check correctness of a proof. Try to use cached results.
    @return 0 to ALLOW, all else to BLOCK */
int 
guard_check(struct goal *goal, struct proof *proof)
{
	char *pretty;
	int ret, npremises, i;

	tuple_active = &proof->hash;

	// invalidate if goal was changed
	if (goal->id != proof->goal_id) {
		proof->status = PF_UNKNOWN;
		proof->goal_id = goal->id;
	}

	if (proof->status == PF_UNKNOWN) {
		guard_check_full(goal, proof);
	}

	if (proof->status == PF_UNSOUND) {
		return AC_BLOCK_CACHE;
	}
	
	return nxguard_auth_check(proof);
}

