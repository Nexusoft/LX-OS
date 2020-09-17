/** NexusOS: core of both guard_eval and bench_proof 
    One of those uses nexus libraries and is more complete,
    the other avoids libraries to also build on Linux. */

#define REPEAT		101
#define MAXPROOFLEN	20

typedef char *(*gfunc)(int, const char **);

/** Generate a proof with @param len delegations */
static char *
proof_generate_delegation(int len, const char **goal)
{
	const char *blueprint1 = "assume p%03d says p%03d speaksfor p%03d;\n";
	const char *blueprint2 = "pushdown 1; delegate; sfor test=1; impe;\n";
	
	char *proof;
	int plen, off, i;
		
	// allocate memory
	plen = 100 + (len * (strlen(blueprint1) + strlen(blueprint2)));
	proof = malloc(plen);
	off = 0;

	// assumptions: each delegation needs one
	for (i = 0; i < len; i++)
		off += sprintf(proof + off, blueprint1, i, i + 1, i);
	// root assumption: someone says the base statement
	off += sprintf(proof + off, "assume p%03d says test=1;\n", len);
	// delegation derivation
	for (i = 0; i < len; i++)
		off += sprintf(proof + off, "%s", blueprint2);
	proof[off] = 0;
		
	assert(off < plen);
	*goal = "p000 says test=1";
	return proof;
}

/** Set a goal with double negations and derive it from a shorter assumption */
static char *
proof_generate_negation(int len, const char **goal)
{
	const char *goalstr = "not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not principal says test=1"; // 20x not-not
	const char *rule1 = "not-not;";
	const int maxrules = 20;
	
	char *proof;
	int plen, i, off;

	if (len >= maxrules)
		return NULL;

	// allocate memory
	plen = strlen(goalstr) + (len * strlen(rule1) + 100);
	proof = malloc(plen);
	off = 0;

	// assumption: assume 'not not'{maxrules - len} + 'principal says test=1'
	off += sprintf(proof, "assume ");
	for (i = maxrules; i > len; i--)
		off += sprintf(proof + off, "not not ");
	off += sprintf(proof + off, "principal says test=1;\n");
	
	// rules: add len * 'not-not' to build up to goal string
	for (i = 0; i < len; i++)
		off += sprintf(proof + off, "%s\n", rule1);
	proof[off] = 0;

	assert(off < plen);
	*goal = goalstr;
	return proof;
}

/** Boolean elimination: (P says p1 and p2 and ... and pn => P says pa) */
static char *
proof_generate_boolean(int len, const char **goal)
{
	const char *goalstr = "principal says p1=1 ";
	const char *rule1 = "and p%d=1 ";
	const char *rule2 = "says_ande_l;";

	char *proof;
	int plen, off, i;
	
	// allocate memory
	plen = strlen(goalstr) + len * (strlen(rule1) + strlen(rule2)) + 100;
	proof = malloc(plen);
	off = 0;

	// initial assumption: assume p1 and p2 and ... and pn;
	off += sprintf(proof + off, "assume %s ", goalstr);
	for (i = 0; i < len; i++) 
		off += sprintf(proof + off, rule1, i + 2);
	off += sprintf(proof + off, ";\n");

	// rule: remove one of the conjunctions
	for (i = 0; i < len; i++)
		off += sprintf(proof + off, "%s\n", rule2);
	proof[off] = 0;

	assert(off < plen);
	*goal = goalstr;
	return proof;
}

// proof_generate_sets (x in union ...)

// proof_generate_deduction ( {a says A => B, a says A } -> a says B )

// proof_generate_group ?

// proof_generate_quantifier

static int 
test_inner(const char *testname, gfunc generator, int full_eval)
{
	struct nxmedian_data *profile;
	struct goal goal;
	struct eval *eval;
	Judge *res;
	char *proof, runname[50];
	const char *goalstr;
	int i, j, plen, ret;

	profile = nxmedian_alloc(REPEAT);
	eval = eval_create();

	for (j = 0; j < MAXPROOFLEN; j++) {
		nxmedian_reset(profile);

		// generate proof. Not all generators generate up to MAXPRO..
		proof = generator(j, &goalstr);
		if (!proof)
			continue;

		// set goal: first in chain says test=1
		goal.form = form_from_pretty(goalstr);
		goal.id = 0;

		// test
		for (i = 0; i < REPEAT; i++) {
#ifdef ENABLE_LIBRARY
			if (full_eval) {
				nxmedian_begin(profile);
				res = guard_check_proof(&goal, proof);
				nxmedian_end(profile);
				if (!res)
					ReturnError(1, "deduction failed\n");
				judge_free(res);
			}
			else 
#endif
			{
				nxmedian_begin(profile);
				ret = eval_run(eval, proof, NULL);
				nxmedian_end(profile);
				if (ret)
					ReturnError(1, "deduction failed\n");
			}
			eval_reset(eval);
		}
	
		snprintf(runname, 49, "%s.%c.%2d ", testname, full_eval ? 'f' : 'e', j);
		nxmedian_show(runname, profile);
		snprintf(runname, 49, "/tmp/proof.%s.%s.data ", 
			 testname, full_eval ? "full" : "eval");
		nxmedian_write(runname, j, profile);
	
		free(proof);
	}
		
	eval_free(eval);
	nxmedian_free(profile);
	return 0;
}

static int
test_outer(const char *testname, gfunc generator)
{
	if (test_inner(testname, proof_generate_delegation, 0))
		return 1;

#ifdef ENABLE_LIBRARY
	if (test_inner(testname, proof_generate_delegation, 1))
		return 1;
#endif

	return 0;
}
