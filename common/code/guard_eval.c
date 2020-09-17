/** NexusOS: NAL proofchecker (together with guard-code.c and guad_pf.c) */

// eval_run() takes the "hintcode" and rebuilds the
// evaluation tree from it, typechecking the tree as it goes (i.e. structural
// integrity).
//
// The result is zero or more elements left on the stack.
//
// It is up to the caller (e.g. guard.c) to check that the stack contains
// exactly one element, that this one element matches the policy goal formula,
// and that all of the assumptions of the final element are simultaneously true.

// these are things we have to do natively, instead of just adding rules
enum {
	HC_PUSHDOWN = 1,
	HC_PULLUP,
	HC_ASSUME, /* aka "given" */
	HC_EFE, /* should this have a closed(P) premise ? */
	HC_IMPI,
	HC_DUP,
	HC_POP, /* only really useful for debugging and interactive input */
	HC_RENAME,
	HC_CONST,
	HC_EXTERN,
	HC_FORALLI,
	HC_FORALLE,
	HC_SAYSFORALL,
	HC_FORALLSAYS,
	HC_EXISTSI,
	HC_GROUPI, // todo: update interactive help with these last few new rules...
	HC_RULE, /* found in rule table */
};

#define HC_MAX_INLINEARGS 3

struct hc {
  int tag;
  int nstackargs;
  int argi; /* some native rules take an int as an argument */
  Form *argf; /* some native rules take a term or stmt as argument */
  struct _Lemma *rule; /* non-native rules are stored in lemmas */
};

static int __isspace(char x) 
{ 
	return (x == '\t' || x == '\n' || x == ' ' ||
	        x == '\v' || x == '\f' || x == '\r') ? 1 : 0;
}

static const char *skipws(const char *s) { while (s && __isspace(*s)) s++; return s; }
static const char *rtrim(const char *s) { while (s && __isspace(*s)) s--; return s; }
static void guard_add_axioms(struct eval *eval);
static void guard_del_axioms(struct eval *eval);

////////  stack manipulation routines  ////////

Judge *eval_pop(struct eval *eval) {
	int n = PointerVector_len(&eval->stack);
	if (n <= 0)
	  return NULL;
	Judge *f = PointerVector_deleteAt(&eval->stack, n-1);
	PointerVector_append(&eval->recentstack, f);
	return f;
}

static Judge *eval_peek(struct eval *eval) {
	int n = PointerVector_len(&eval->stack);
	if (n <= 0)
	  return NULL;
	return PointerVector_nth(&eval->stack, n-1);
}


static void done(struct eval *eval, int failed) {
  int i, n = PointerVector_len(&eval->recentstack);
  if (failed) {
    // push back recent items to recover
    for (i = n-1; i >= 0; i--) {
      Judge *f = PointerVector_deleteAt(&eval->recentstack, i);
      PointerVector_append(&eval->stack, f);
    }
  } else {
    // should have been consumed by judge_new(...) or right after judge_free(...)
    assert(n == 0);
  }
}

static void kill(struct eval *eval) {
  done(eval, 1);
  //dump_eval_stack(eval);
  printf("(%d errors so far)\n", eval->errors + 1);
}

static void push(struct eval *eval, Judge *f) {
	PointerVector_append(&eval->stack, f);
	done(eval, 0);
}

static void slipin(struct eval *eval, Judge *f, int offset) {
	PointerVector_insertAt(&eval->stack, f, PointerVector_len(&eval->stack) - offset);
	done(eval, 0);
}

static Judge *slipout(struct eval *eval, int offset) {
	int n = PointerVector_len(&eval->stack);
	Judge *f = PointerVector_deleteAt(&eval->stack, n - offset - 1);
	PointerVector_append(&eval->recentstack, f);
	return f;
}


////////  struct eval create/destroy  ////////

struct eval * 
eval_create(void) 
{
	struct eval * eval;

	eval = nxcompat_calloc(1, sizeof(struct eval));
	
	// allocate room for deduction 
	PointerVector_init(&eval->stack, 16, POINTERVECTOR_ORDER_PRESERVING);
	PointerVector_init(&eval->recentstack, 16, POINTERVECTOR_ORDER_PRESERVING);

	// populate ruleset of standard axioms
	eval->rules = hash_new_vlen(16, hash_strlen);
	PointerVector_init(&eval->rules_sorted, 16, POINTERVECTOR_ORDER_PRESERVING);
	guard_add_axioms(eval);

	return eval;
}

/** Reset evaluator to the state after an eval_create(..) call.
    Enables reuse across many deductions, amortizing guard_add_axioms cost */
void 
eval_reset(struct eval *eval) 
{
	Judge *f;
	int vlen;

	assert(PointerVector_len(&eval->recentstack) == 0);

	vlen = PointerVector_len(&eval->stack);
	for (; vlen; vlen--) {
		f = PointerVector_deleteAt(&eval->stack, vlen - 1);
		judge_free(f);
	}
	assert(PointerVector_len(&eval->stack) == 0);

	// reinitialize simple variables
	eval->code = NULL;
	eval->flags = 0;
	eval->errors = 0;
}

void 
eval_free(struct eval *eval) 
{
	eval_reset(eval);
//	guard_del_axioms(eval);

	PointerVector_dealloc(&eval->recentstack);
	PointerVector_dealloc(&eval->stack);
	
	PointerVector_dealloc(&eval->rules_sorted);
	hash_destroy(eval->rules);
	nxcompat_free(eval);
}

////////  Standard NAL axioms  ////////

void guard_lemma_print(struct _Lemma *lemma) {
  if (!strcmp(lemma->name, "goal"))
    printf("goal statement:\n");
  else
    printf("%s %s:\n", (lemma->pf ? "lemma" : "rule"), lemma->name);
  int i;
  for (i = 0; i < lemma->numprems; i++) {
    char *s = form_to_pretty(lemma->prems[i], 0);
    printf(" %3d: %s\n", i, s);
    nxcompat_free(s);
  }
  char *s = form_to_pretty(lemma->concl, 0);
  printf("   /  %s\n", s);
  nxcompat_free(s);
  if (lemma->pf)
    printf("  proof: %s\n", lemma->pf);
}

/** Verify a deduction. 
    Does not reset the evaluators state
 
    @return 0 on success; error otherwise */
int 
guard_check_deduction(struct eval *eval, const char *proof)
{
	Judge *shown;
	int ret;

	// check proof
	ret = eval_run(eval, (char *) proof, NULL);
	if (ret < 0) {
		printf("[guard] Deny. proof is not well formed (%d)\n", ret);
		return 1;
	}
	
	// a single conclusion?
	if (PointerVector_len(&eval->stack) != 1) {
		printf("[guard] Deny. no single proven statement\n");
		return 1;
	}

	return 0;
}

// combine with guard_check_proof
int guard_axiom_verify(struct eval *eval, struct _Lemma *lemma)
{
	Judge *shown;
	Form *f;
	int i, j, hlen;
	
	if (!lemma->pf || guard_check_deduction(eval, lemma->pf)) {
	  printf("failed: in deduction\n");
	  return -1;
	}

	// make sure conclusion matches
	shown = PointerVector_deleteAt(&eval->stack, 0);
	if (form_cmp(shown->concl, lemma->concl)) {
	  printf("failed: lemma is has wrong conclusion\n");
	  judge_free(shown);
	  return -1;
	}

	// make sure all hypotheses are matched by a premise
	hlen = PointerVector_len(&shown->hyp);
	for (i = 0; i < hlen; i++) {
	  f = PointerVector_nth(&shown->hyp, i);

	  for (j = 0; j < lemma->numprems; j++) {
	    if (!form_cmp(f, lemma->prems[j]))
	      break;
	  }

	  if (j == lemma->numprems) {
	    printf("failed: lemma is missing required premise\n");
	    judge_free(shown);
	    return -1;
	  }
	}

	// XXX cleanup axioms related data (currently witnesses double free()s)
	// judge_free(shown);
	return 0;
}

/** Insert a lemma into the list of axioms for evaluation 
    Lemmas have the form [P1, .., Pn] => C, with premises Px and conclusion C 

    @param prems: a NULL terminated list of premises. FREED before return */
static int
guard_axiom_parse(struct eval *eval, struct _Lemma *lemma, char *name,
	      char *conclstr, char **premises)
{
  Form **prems, *concl;
  char *c, **p;
  int i, nprems;
 
  // translate conclusion into formula and replace parameters
  concl = form_from_pretty(conclstr);
  if (!concl) {
    printf("guard: conclusion is malformed:\n  %s\n", conclstr);
    return -1;
  }

  // parse optional rule argument ("saysi %s")
  c = strchr(name, ' ');
  if (c) {
    lemma->arg = form_or_term_from_pretty(c + 1);
    if (!lemma->arg) {
      printf("guard: argument is malformed:\n  %s\n", c+1);
      return -1;
    }
  } else
    lemma->arg = NULL;

  // calculate number of premises
  nprems = 0;
  p = premises;
  while (*p) {
  	nprems++;
	p++;
  }

  // translate parameters into formulae and replace parameters
  prems = nxcompat_alloc((nprems ? nprems : 1) * sizeof(Form *));
  for (i = 0; i < nprems; i++) {
    prems[i] = form_from_pretty(premises[i]);

    // error handling
    if (!prems[i]) {
      printf("guard: premise %d is malformed (%s)\n", i, premises[i]);
      form_free(concl);
      while (i > 0) 
	      form_free(prems[--i]);
      nxcompat_free(prems);
      return -1;
    }
  }

  // populate lemma structure
  lemma->name = strdup(name);
  if (lemma->arg) 
	  strchr(lemma->name, ' ')[0] = '\0';

  lemma->concl = concl;
  lemma->numprems = nprems;
  lemma->prems = prems;
  lemma->pf = NULL;

  return 0;
}

/** Inverse of guard_axiom_parse */
static void 
guard_axiom_free(struct _Lemma *lemma) 
{
  int i;
  
  for (i = 0; i < lemma->numprems; i++)
    form_free(lemma->prems[i]);
  nxcompat_free(lemma->prems);

  if (lemma->name)
    nxcompat_free(lemma->name);
  if (lemma->pf)
    nxcompat_free(lemma->pf);
  if (lemma->concl)
    form_free(lemma->concl);
  nxcompat_free(lemma);
}


/** Add a rule to the set of axioms in an evaluator.
    @return 0 on success or -1 on failure */
static int
guard_axiom_add(struct eval *eval, char *name, char *conclstr, 
	        char *pf, char **premises) 
{
  struct _Lemma *lemma;
  
  // create new lemma structure
  lemma = nxcompat_calloc(1, sizeof(struct _Lemma));
  if (guard_axiom_parse(eval, lemma, name, conclstr, premises)) {
    nxcompat_free(lemma);
    return -1;
  }

  // verify a lemma (a rule that has a proof)
  if (pf) {
    lemma->pf = strdup(pf);
#if 0
    if (guard_axiom_verify(eval, lemma)) {
      guard_axiom_free(lemma);
      return -1;
    }
#endif
  }

  // add to ruleset
  hash_insert(eval->rules, lemma->name, lemma);
  PointerVector_append(&eval->rules_sorted, lemma->name);
  
  return 0;
}

/** Inverse of guard_axiom_add */
static int
guard_axiom_del(struct eval *eval, const char *name)
{
  struct _Lemma *lemma;

  lemma = hash_delete(eval->rules, name);
  if (!lemma)
	  return -1;

  PointerVector_delete(&eval->rules_sorted, lemma->name);
  guard_axiom_free(lemma);
  return 0;
}

char *nal_stdrules[] = {
  "andi", "%F and %G", "%F", "%G", 0,
  "ande_l", "%F", "%F and %G", 0,
  "ande_r", "%G", "%F and %G", 0,
  "true", "true", 0,
  "false %S", "%S", "false", 0,
  "impe", "%G", "%F", "%F imp %G", 0,
  "saysi %a", "%a says %F", "%F", 0,
  "sayse", "%a says %F", "%a says (%a says %F)", 0,
  "idemp %a", "%a speaksfor %a", 0 ,
  "deduce", "%a says %G", "%a says %F", "%a says (%F imp %G)", "closed(%a)", 0,
  "imp-says", "%a says (%F imp %G)", "(%a says %F) imp (%a says %G)", "closed(%a)", 0, /* necessary ??? */
  "prin_pem %k", "prin(pem(%k))", 0, 
  "prin_der %k", "prin(der(%k))", 0, 
  "prin_csp %a.%t", "prin(%a.%t)", "prin(%a)", 0, 
  "prin_osp %a.%t", "prin(%a:%t)", "prin(%a)", 0, 
  "closed_pem %k", "closed(pem(%k))", 0, 
  "closed_der %k", "closed(der(%k))", 0, 
  "closed_sp %a.%t", "closed(%a.%t)", 0, 
  "open_sp %a:%t", "open(%a:%t)", 0, 
  "closed_notopen", "not open(%a)", "closed(%a)", "prin(%a)", 0, 
  "open_notclosed", "not closed(%a)", "open(%a)", "prin(%a)", 0, 
  "cspi %a.%e", "%a speaksfor (%a.%e)", 0,
  "ospi %a:%e", "%a speaksfor (%a:%e)", 0,
  /* "sforany", "%a on \"*\" speaksfor %b", "%a speaksfor %b", 0, */
  /* "sfor", "(%a says %F) imp (%b says %F)", "%a on %p speaksfor %b", "match(%p, %F)", 0, */
  "speaksfor_on", "%b says %F", "%a says %F", "%a on true speaksfor %b",  0,
  "sfor %F", "(%a says %F) imp (%b says %F)", "%a speaksfor %b", 0, 
  "says_ande_l", "%a says %F", "%a says %F and %G", 0,
  /* "matchany", "match(\"*\", %F)", 0, */
  /* "delegate", "%b on %p speaksfor %a", "%a says (%b on %p speaksfor %a)", 0, */
  "delegate", "%b speaksfor %a", "%a says (%b speaksfor %a)", 0,
  "eqi %t", "%t = %t", 0,
  "defi_not", "not %F", "%F imp false", 0,
  "defe_not", "%F imp false", "not %F", 0,
  "defi_iff", "%F iff %G", "(%F imp %G) and (%G imp %F)", 0,
  "defe_iff", "(%F imp %G) and (%G imp %F)", "%F iff %G", 0,
  "defi_or", "%F or %G", "(%F imp %G) imp %G", 0,
  "defe_or", "(%F imp %G) imp %G", "%F or %G", 0,

  "cases", "(%F or %G) imp %H", "%F imp %H", "%G imp %H", 0,

  "prin_cgrp [[ $v : %S ]]" , "prin([[ $v : %S ]])", 0,
  "prin_ogrp [( $v : %S )]" , "prin([( $v : %S )])", 0,
  "closed_grp [[ $v : %S ]]", "closed([[ $v : %S ]])", 0,
  "open_grp [( $v : %S )]", "open([( $v : %S )])", 0,

  "defi_in", "%z in { %x }", "%z = %x", 0,
  "defe_in", "%z = %x", "%z in { %x }", 0,
  "in_i %x", "%x in { %x }", 0,
  "in_union %x in union(%s1, %s2)", "(%x in union(%s1, %s2)) iff ((%x in %s1) or (%x in %s2))", 0,
  "or-in-union", "(%x in union(%s1, %s2))", "((%x in %s1) or (%x in %s2))", 0,
  "in-union-or", "(%x in union(%s1, %s2))", "((%x in %s1) or (%x in %s2))", 0,

  0
};

char *nal_stdlemmas[] = {
  // equation inversion
  "eq_swap", "%x = %y",
      "given %y = %x; "
      "eqi %x; "
      "efe %x = %y; ",
      "%y = %x", 0,

  // double negation introduction
  "not-not", "not not %S",
      "given %S; "
      "assume not %S; "
      "defe_not; " // %S imp false
      "impe; " // false
      "impi not %S; " // not %S imp false
      "defi_not; ", // not not %S
      "%S", 0,

  // transitive implicatino
  "imp-imp", "%F imp %H",
      "assume %F; "
      "given %F imp %G; " 
      "impe; " // %G
      "given %G imp %H; " 
      "impe; " // %H
      "impi %F; ", // %F imp %H
      "%F imp %G", "%G imp %H", 0,

  "says-imp", "(%a says %F) imp (%a says %G)",
      "assume %a says %F; "
      "given %a says (%F imp %G); "
      "given closed(%a); "
      "deduce; " // %a says %G
      "impi %a says %F; ", // (%a says %F) imp (%a says %G)
      "%a says (%F imp %G)", "closed(%a)", 0,

  // OR introduction (F => F or G)
  "ori_l %G", "%F or %G",
      "given %F; "
      "assume %F imp %G; "
      "impe; "
      "impi %F imp %G; "
      "defi_or; ", 
      "%F", 0,

  // OR introductino (G => F or G)
  "ori_r %F", "%F or %G",
      "given %G; "
      "impi %F imp %G; "
      "defi_or; ",
      "%G", 0,

  // iff elimination ( {F iff G, G} => F )
  "iffe_r", "%F",
      "given %G; "
      "given %F iff %G; "
      "defe_iff; "
      "ande_r; "
      "impe; ",
      "%G", "%F iff %G", 0,

  // iff elimination ( {F iff G, F} => G )
  "iffe_l", "%G",
      "given %F; "
      "given %F iff %G; "
      "defe_iff; "
      "ande_l; "
      "impe; ",
      "%F", "%F iff %G", 0,

  "and_swap", "%G and %F",
      "given %F and %G; "
      "dup; "
      "ande_r; "
      "pushdown 1; "
      "ande_l; "
      "andi; ",
      "%F and %G", 0,

  "or_swap", "%G or %F",
      "given %F or %G; "
      "assume %G; "
      "ori_l %F; "
      "impi %G; "
      "assume %F; "
      "ori_r %G; "
      "impi %F; "
      "pushdown 1; "
      "cases; "
      "impe; ",
      "%F or %G", 0,

  "iff_swap", "%G iff %F",
      "given %F iff %G; "
      "defe_iff; "
      "and_swap; "
      "defi_iff; ",
      "%F iff %G", 0,

  "or-in-union", "%x in union(%s1, %s2)",
      "given (%x in %s1) or (%x in %s2); "
      "in_union %x in union(%s1, %s2); "
      "defe_iff; "
      "ande_r; "
      "impe; ", 0,

  "in-union-or", "(%x in %s1) or (%x in %s2)",
      "given %x in union(%s1, %s2); "
      "in_union %x in union(%s1, %s2); "
      "defe_iff; "
      "ande_l; "
      "impe; ",
      "%x in union(%s1, %s2)", 0,

#if 0
  /* this whole lemma seems prone to variable capture issues: e.g. what if %a uses $v ? */
  // now replaced by saysforall and forallsays built-in rules
  "says-forall (forall $v : %S)", 
      "(%a says forall $v : %S) iff (forall $v : %a says %S)",
      "assume %a says (forall $v : %S); "
      "assume forall $v : %S; "
      "foralle $v; " /* note: this step shouuld be forbiden except when we use $v as the dummy */
      "impi forall $v : %S; "
      "saysi %a; "
      "assume closed(%a); "
      "deduce; "
      "foralli $v; " /* is variable capture a problem here with pvar %S ? */
      "impi %a says forall $v : %S; "

      "assume forall $v : %a says %S; "
      "foralle $v; "
      "assume %S; "
      "foralli $v; "
      "impi %S; "
      "saysi %a; "
      "assume closed(%a); "
      "deduce; "
      "impi forall $v : %a says %S; "
     
      "andi; defi_iff; ",
      "closed(%a)", 0,
#endif

/** Parse a hintcode statement.
    s is one of a HC_ statement or an axiom in the NAL logic */
  "says-and",
      "%a says (%F and %G)",
      "given %a says %F; "
      "given %a says %G; "
      "assume %F; "
      "assume %G; "
      "andi; "
      "impi %F; "
      "impi %G; "
      "saysi %a; "
      "given closed(%a); "
      "deduce; "
      "given closed(%a); "
      "deduce; ",
      "%a says %F", "%a says %G", "closed(%a)", 0,

// won't parse (because of %x?)
#if 0 
  "in-union-3 %x in union(union(%x1, %x2), %x3)", 
      "%x in union(union(%x1, %x2), %x3) imp (%x in %x1 or %x in %x2 or %x in %x3)",
      "given %x in union(union(%x1, %x2), %x3); "
      "in-union-or; "

      "assume %x in %x3; "
      "ori_r (%x in %x1) or (%x in %x2); "
      "impi %x in %x3; "

      "assume %x in union(%x1, %x2); "
      "in-union-or; "
      "ori_l %x in %x3; "
      "impi %x in union(%x1, %x2); "

      "pushdown 1; cases; "
      "impe; "
      "impi %x in union(union(%x1, %x2), %x3); ",
      0,

  "in-union-or-3", "(%x in %x1 or %x in %x2 or %x in %x3)",
      "given %x in union(union(%x1, %x2), %x3); "
      "in-union-or; "

      "assume %x in %x3; "
      "ori_r (%x in %x1) or (%x in %x2); "
      "impi %x in %x3; "

      "assume %x in union(%x1, %x2); "
      "in-union-or; "
      "ori_l %x in %x3; "
      "impi %x in union(%x1, %x2); "

      "pushdown 1; cases; "
      "impe; ",
      "%x in union(union(%x1, %x2), %x3)", 0,
#endif

  0
};

/** Add all NAL axioms (rules and lemmas) to an evaluation engine */
static void 
guard_add_axioms(struct eval *eval) 
{
  struct _Lemma *lemma;
  char **p;

  for (p = nal_stdrules; *p != 0; p++) {
    if (guard_axiom_add(eval, p[0], p[1], NULL, &p[2]))
      fprintf(stderr, "error in rule .. => %s\n", p[1]); 
   
    // skip until next whitespace (the rule separator)
    while (*p) p++;
  }

  for (p = nal_stdlemmas; *p != 0; p++) {
    if (guard_axiom_add(eval, p[0], p[1], p[2], &p[3]))
      fprintf(stderr, "error in lemma .. => %s\n", p[1]);

    // skip until next whitespace (the rule separator)
    while (*p) p++;
  }
}

static void
guard_del_axioms(struct eval *eval)
{
  struct _Lemma *lemma;
  char **p;

  for (p = nal_stdrules; *p != 0; p++) {
    if (guard_axiom_del(eval, p[0])) {
      fprintf(stderr, "rule delete %s failed\n", p[0]); 
    }
   
    // skip until next whitespace (the rule separator)
    while (*p) p++;
  }

  for (p = nal_stdlemmas; *p != 0; p++) {
    if (guard_axiom_del(eval, p[0])) {
      fprintf(stderr, "lemma delete %s failed\n", p[0]);
      exit(1);
    }

    // skip until next whitespace (the rule separator)
    while (*p) p++;
  }
}

////////  rule matching  ////////

/** Match a line against the known hintcode ('hc') rules */
static int 
hc_match(const char *s, int n, struct hc *hc, 
	 PointerVector *args, struct HashTable *rules) 
{
	int ac = -1, opsize = -1, fromargs = 0;

	memset(hc, 0, sizeof(struct hc));
	if (!s || !*s)
		return 0;

	n = (rtrim(s + n) - s);

	/** Lookup rule */
	int hc_match_op(int oplabel, char *opname, int k, int ss)
	{
		int olen;
		
		olen = strlen(opname);
		if (n >= olen + (2 * k) && !strncmp(opname, s, olen)) {
			hc->tag = oplabel;
			ac = k;
			hc->nstackargs = ss;
			opsize = olen;
			if (olen > 1 && s[olen] == '*') {
				olen++;
				fromargs = 1;
			}

			return 1;
		}
		else
			return 0;
	}

	if (!hc_match_op(HC_PUSHDOWN, "pushdown", 1, 2) && 
	    !hc_match_op(HC_PULLUP, "pullup", 1, 2) &&
	    !hc_match_op(HC_ASSUME, "assume", 1, 0) &&
	    !hc_match_op(HC_ASSUME, "given", 1, 0) &&
	    !hc_match_op(HC_EFE, "efe", 0 /*1 arg optional*/, 2) &&
	    !hc_match_op(HC_IMPI, "impi", 1, 1) &&
	    !hc_match_op(HC_DUP, "dup", 0, 1) &&
	    !hc_match_op(HC_POP, "pop", 0, 1) &&
	    !hc_match_op(HC_RENAME, "rename", 1, 1) &&
	    !hc_match_op(HC_CONST, "const", 1, 0) &&
	    !hc_match_op(HC_EXTERN, "extern set-theory", 1, 0) &&
	    !hc_match_op(HC_FORALLI, "foralli", 1, 1) &&
	    !hc_match_op(HC_FORALLE, "foralle", 1, 1) &&
	    !hc_match_op(HC_SAYSFORALL, "says-forall", 0, 1) &&
	    !hc_match_op(HC_FORALLSAYS, "forall-says", 0, 1) &&
	    !hc_match_op(HC_EXISTSI, "existsi", 1, 1) &&
	    !hc_match_op(HC_GROUPI, "groupi", 1, 2)) {
	
	  char *op, *p;
	  
	  // create temporary private copy of rule
	  op = nxcompat_alloc(n+1);
	  memcpy(op, s, n);
	  op[n] = '\0';

	  // look for optional argument beyond first token
	  p = op + 1;
	  while (*p && !__isspace(*p))
		  p++;
	  if (*p) {
	    ac = 1;
	    opsize = p - op;
	    *p = '\0';
	  } else {
	    ac = 0;
	    opsize = n;
	  }

	  // positional notation into arguments array
	  if (opsize > 1 && op[opsize-1] == '*') {
	    op[opsize-1] = '\0';
	    fromargs = 1;
	  }

	  // lookup rule in rulebase
	  struct _Lemma *rule = hash_findItem(rules, op);
	  if (!rule) {
	    nxcompat_printf("[warning]: no rule [%s]\n", op);
	    nxcompat_free(op);
	    return -1;
	  }
	  nxcompat_free(op);

	  if (!!ac != !!rule->arg) 
	    return -3;

	  hc->tag = HC_RULE;
	  hc->nstackargs = rule->numprems;
	  hc->rule = rule;
	}
	assert(ac == 0 || ac == 1);

	// special case: efe takes an optional argument
	if (hc->tag == HC_EFE) {
	  if (opsize == n) return 0;
	  else ac = 1;
	} 

	if (!ac) {
	  if (opsize != n) return -4;
	  return 0;
	}

	const char *p = s + opsize;
	char *end;

	// move to start of argument
	assert(ac == 1);
	if ((p == s + n) || !__isspace(*p++)) 
		return -2;
	while (__isspace(*p)) 
		if (++p > s + n) return -4;

	// if pushdown or pullup, interpret as int
	if (hc->tag == HC_PUSHDOWN || hc->tag == HC_PULLUP) {
	  hc->argi = strtoul(p, &end, 10);
	  if (end == p) return -3;
	  if (end != s +  n) return -4;
	}
	// if index notation, get from arguments[index]
	else if (fromargs) {
	  if (!args) {
	    nxcompat_printf("[guard] error: arguments missing\n");
	    return -3;
	  }
	  hc->argi = strtoul(p, &end, 10);
	  if (end == p) return -3;
	  if (end != s +  n) return -4;
	  if (hc->argi < 0 || hc->argi >= PointerVector_len(args)) return -5;

	  hc->argf = PointerVector_nth(args, hc->argi);
	} 
	// parse term or formula (depending on rule) using yacc parser
	else {
	  hc->argi = -1;

	  // copy token
	  char *fstr = nxcompat_alloc(n - opsize);
	  memcpy(fstr, s + opsize + 1, n - opsize - 1);
	  fstr[n - opsize - 1] = '\0';

	  // call yacc
	  if (hc->tag == HC_CONST || hc->tag == HC_EXTERN)
	    hc->argf = form_or_term_from_pretty(fstr);
	  else if (hc->tag == HC_FORALLE || hc->tag == HC_FORALLI || hc->tag == HC_GROUPI ||
	      (hc->tag == HC_RULE && F_ISTERM(hc->rule->arg->tag)))
	    hc->argf = term_from_pretty(fstr);
	  else {
	    hc->argf = form_from_pretty(fstr);
	  }
	  nxcompat_free(fstr);
	  if (!hc->argf) return -5;
	}
	return 0;
}

int efe_cmp(Form *f, Form *g, Form *t1, Form *t2) {
  /* char *fs = form_to_pretty(f, 80);
  char *gs = form_to_pretty(g, 80);
  char *t1s = form_to_pretty(t1, 80);
  char *t2s = form_to_pretty(t2, 80);
  printf("oops: in efe_cmp\n f = %s\n g = %s\n t1 = %s\n t2 = %s\n",
      fs, gs, t1s, t2s);
  nxcompat_free(fs); nxcompat_free(gs); nxcompat_free(t1s); nxcompat_free(t2s); */
  return (form_cmp(f, t1) || form_cmp(g, t2))
	/* && (form_cmp(f, t2) || form_cmp(g, t1)) */; // don't do swapping
						       // until we are sure it is okay
}

int cmp_replace(Form *f, Form *g, Form *t1, Form *t2, HashTable *fv1, HashTable *fv2) {
  if (f->tag != g->tag) {
    // printf("tag mismatch\n");
    return efe_cmp(f, g, t1, t2);
  }
  // todo: variable capture for group expressions too
  if (f->tag == F_STMT_FORALL || f->tag == F_STMT_EXISTS) {
    if (!f->left || !g->left || !f->right || !g->right) // bad structure
      return efe_cmp(f, g, t1, t2);
    if (form_cmp(f->left, g->left) || f->left->tag != F_TERM_QVAR) // bound variable renaming disallowed
      return efe_cmp(f, g, t1, t2);
    if (hash_findItem(fv1, f->left->data) || hash_findItem(fv2, f->left->data)) // disallow subst so free var in t1 or t2 doesn't get bound
      return form_cmp(f->right, g->right); // identical is still okay in capture case
    else
      return cmp_replace(f->right, g->right, t1, t2, fv1, fv2); // compare bodies instead
  }
  switch (f->tag & F_ARITY_MASK) {
    case F_IS_TERNARY:
      if (!f->mid != !g->mid) break;
      if (f->mid && cmp_replace(f->mid, g->mid, t1, t2, fv1, fv2)) break;
      // fall through
    case F_IS_BINARY:
      if (!f->right != !g->right) break;
      if (f->right && cmp_replace(f->right, g->right, t1, t2, fv1, fv2)) break;
      // fall through
    case F_IS_UNARY:
      if (!f->left != !g->left) break;
      if (f->left && cmp_replace(f->left, g->left, t1, t2, fv1, fv2)) break;
      return 0;
    case F_IS_EMPTY:
      return 0;
    case F_IS_VALUE:
      if (f->value != g->value) break;
      return 0;
    case F_IS_DATA:
      if (f->len != g->len) break;
      if (f->len == 0) return 0;
      if (f->len < 0) {
	if (strcmp(f->data, g->data)) break;
      } else if (f->len > 0) {
	if (memcmp(f->data, g->data, f->len)) break;
      }
      return 0;
    default:
      break;
  }
  //printf("structure or sub mismatch\n");
  return efe_cmp(f, g, t1, t2); 
}

// check if there is a statement S such that
// f = S[$v/t1], g = S[$v/t2]
// Terms t1 and t2 should have no free variables (so no worry about variable
// capture), and the variable $v is fresh, so no worry about shadowing or
// anything. 
// todo: We could also allow for t1 and t2 to be swapped as needed, i.e., we
// could instead by satisfied if f = S[$v1/t1, $v2/t2], g = S[$v1/t1, $v2/t2]
int form_cmp_replace(Form *f, Form *g, Form *t1, Form *t2) {
  HashTable *fv1 = form_free_qvars(t1);
  HashTable *fv2 = form_free_qvars(t2);
  int err = cmp_replace(f, g, t1, t2, fv1, fv2);
  hash_destroy(fv1);
  hash_destroy(fv2);
  return err;
}

int appears_free_in(Form *var, Form *f) {
  assert(var->tag == F_TERM_QVAR);
  HashTable *fv = form_free_qvars(f);
  int ret = (hash_findItem(fv, var->data) != 0);
  hash_destroy(fv);
  return ret;
}

static int kill_map_entry(void *item, void *arg) {
  form_free((Form *)item);
  return 0;
}

static int print_map_entry(void *entry, void *arg) {
  /* char *paramname = hash_entryToKey(entry);
  Form *paramval = hash_entryToItem(entry);
  form_printf(" subst %s as %s\n", paramname, form_s(paramval)); */
  return 0;
}

// match the first n stack args to n premises
static int apply_rule(struct eval  *eval, struct _Lemma *rule, Form *arg) {
  struct HashTable *reps;
  char *s;
  int i;
  
  reps = hash_new_vlen(16, hash_strlen);
  if (rule->arg && form_unify_params(arg, rule->arg, reps)) {
      printf("failed to apply rule: can't unify argument\n");
      hash_iterate(reps, &kill_map_entry, NULL);
      hash_destroy(reps);
      kill(eval);
      return -1;
  }
  for (i = rule->numprems-1; i >= 0; i--) {
    Judge *g = eval_pop(eval);
    if (form_unify_params(g->concl, rule->prems[i], reps)) {
      hash_iterate(reps, &kill_map_entry, NULL);
      hash_destroy(reps);
      kill(eval);
      return -1;
    }
  }

  Form *concl = form_dup(rule->concl);
  int used = form_replace_all(concl, reps);
  hash_iterate(reps, &kill_map_entry, NULL);
  hash_destroy(reps);

  if (used < 0) {
    printf("can't substitute into rule conclusion\n");
    form_free(concl);
    kill(eval);
    return -1;
  }
      
  push(eval, judge_new(eval, concl));
  return 0;
}

/* find_alpha_equiv algorithm:
 * We essentially compute the de Bruijn indexes for each f and g, then compare.
 * Some tricky bits are doing this simply, reasonably quickly, and handling the
 * implicit universal quantifiers for free variables.
 * We maintain a depth, a freevar count, and a map m: qvar -> int. At the time a
 * qvar is visited, it is assigned a de Bruijn index
 *    b = (m[qvar] > 0) ? (depth - m[qvar]) : (nfv + depth + m[qvar]).
 * The number of free vars (nfv) is not actually known until the end of the
 * pass, but it is constant for the entire expression, and checked to be equal
 * in both f in g, and so can be safely ignored.
 * Example:
 *       y > x imp (forall y : w + x > y + z and (forall z : x > y + z)) imp w > y 
 * nfv   4   4                 4   4   4   4                 4   4   4       4   4  
 * depth 0   0                 1   1   1   1                 2   2   2       0   0
 * m[]  -1  -2             1  -3  -2   1  -4             2  -2   1   2      -3  -1
 * b     3   2                 2   3   0   1                 4   1   0       1   3
 *
 * free variable implicit bindings: forall y : forall x : forall w : forall z : ...
 * nfv = number of free variables = 4
 */
static int find_alpha_equiv(Form *f, Form *g, struct HashTable *fm, struct HashTable *gm,
    int depth, int nfv) {
  // check for same structure
  if (f->tag != g->tag) return -1;
  if (!f->left != !g->left) return -1;
  if (!f->mid != !g->mid) return -1;
  if (!f->right != !g->right) return -1;
  if (!f->data != !g->data) return -1;

  if (f->tag == F_TERM_QVAR) {
    assert(f->data && g->data);
    int m_f = (int)hash_findItem(fm, f->data);
    int m_g = (int)hash_findItem(gm, g->data);
    if (m_f != m_g)
      return -1;
    // both are new, or both are old and equal
    if (!m_f) { // two new free vars
      nfv++;
      hash_insert(fm, f->data, (void *)-nfv);
      hash_insert(gm, g->data, (void *)-nfv);
    }
    return 0;
  }
  if (f->tag == F_STMT_FORALL || f->tag  == F_STMT_EXISTS) {
    Form *f_qvar = f->left;
    Form *g_qvar = g->left;
    assert(f_qvar && g_qvar && f_qvar->data && g_qvar->data);
    assert(f_qvar->tag == F_TERM_QVAR && g_qvar->tag == F_TERM_QVAR);
    hash_insert(fm, f_qvar->data, (void *)(depth+1)); // takes advantage of lifo hashtable dups
    hash_insert(gm, g_qvar->data, (void *)(depth+1)); // takes advantage of lifo hashtable dups
    if (find_alpha_equiv(f->right, g->right, fm, gm, depth+1, nfv))
      return -1;
    hash_delete(fm, f_qvar->data); // restores previous value, if any
    hash_delete(gm, g_qvar->data); // restores previous value, if any
    return 0;
  } else {
    switch (f->tag & F_ARITY_MASK) {
      case F_IS_TERNARY:
	if (f->mid && find_alpha_equiv(f->mid, g->mid, fm, gm, depth, nfv)) return -1;
	// fall through
      case F_IS_BINARY:
	if (f->right && find_alpha_equiv(f->right, g->right, fm, gm, depth, nfv)) return -1;
	// fall through
      case F_IS_UNARY:
	if (f->left && find_alpha_equiv(f->left, g->left, fm, gm, depth, nfv)) return -1;
	// fall through
      case F_IS_EMPTY:
	return 0;
      default:
	return (form_cmp(f, g) ? -1 : 0);
    }
  }
}


/*
static void replace_qvars_from_map(void *entry, void *arg) {
  char *qvar_oldname = hash_entryToKey(entry);
  char *qvar_newname = hash_entryToItem(entry);
  Form *f = arg;

  char *s = form_to_pretty(paramval, 80);
  // printf("replacing %s\n"
	  // "     with %s\n", paramname, s); 
  free(s);
  int used = form_rename_qvar(f, qvar_oldname, qvar_newname);
  if (used < 0) {
    printf("ack! problem replacing parameter...\n");
    // todo: break out and return error
  }
}
*/

static int do_rename(struct eval *eval, Form *h) { 
  h = form_dup(h);
  Judge *f = eval_pop(eval);

  struct HashTable *fm = hash_new_vlen(16, hash_strlen);
  struct HashTable *gm = hash_new_vlen(16, hash_strlen);
  // note: the proposed form (h) must go first in this expression.
  int err = find_alpha_equiv(h, f->concl, fm, gm, 0, 0);
  hash_destroy(fm);
  hash_destroy(gm);
  if (err) {
      char *s = form_to_pretty(f->concl, 80);
      char *s2 = form_to_pretty(h, 80);
      printf("suggested renaming is not alpha-equivalent\n");
      printf("  original: %s\n", s);
      printf("  renaming: %s\n", s2);
      nxcompat_free(s);
      nxcompat_free(s2);
      form_free(h);
      kill(eval);
      return -1;
  }

  push(eval, judge_new(eval, h));
  return 0;
}

int find_qvar_subst(Form *f, Form *g, char *qname, Form **repl, HashTable **replfv) {
  // check for replacement
  if (f->tag == F_TERM_QVAR && !strcmp(f->data, qname)) {
    if (!*repl) {
      *repl = g;
      *replfv = form_free_qvars(g);
    }
    else if (form_cmp(g, *repl))
	printf("no such substitution\n");
    return 0;
  }
  // check for same structure
  if (f->tag != g->tag) printf("tag mismatch\n");
  if (!f->left != !g->left) printf("bad structure\n");
  if (!f->mid != !g->mid) printf("bad structure\n");
  if (!f->right != !g->right) printf("bad structure\n");
  if (!f->data != !g->data) printf("bad structure\n");

  // two special cases:
  // f == (forall $x : S) -- normal case, but then check $x not in fv of repl
  // f == (forall $q : S) -- do direct comparison, b/c $q is shadowed

  if (f->tag == F_STMT_FORALL || f->tag  == F_STMT_EXISTS) {
    Form *f_qvar = f->left;
    assert(f_qvar && f_qvar->data && f_qvar->tag == F_TERM_QVAR);
    if (!strcmp(f_qvar->data, qname)) {
      if (form_cmp(f, g)) printf("different structure\n");
      else return 0;
    }
  }

  switch (f->tag & F_ARITY_MASK) {
    case F_IS_TERNARY:
      if (f->mid && find_qvar_subst(f->mid, g->mid, qname, repl, replfv)) printf("mismatch\n");
      // fall through
    case F_IS_BINARY:
      if (f->right && find_qvar_subst(f->right, g->right, qname, repl, replfv)) printf("mismatch\n");
      // fall through
    case F_IS_UNARY:
      if (f->left && find_qvar_subst(f->left, g->left, qname, repl, replfv)) printf("mismatch\n");
      // fall through
    case F_IS_EMPTY:
      break;
    default:
      if (form_cmp(f, g)) printf("mismatch\n");
      else return 0;
  }

  if (*repl && (f->tag == F_STMT_FORALL || f->tag  == F_STMT_EXISTS)) {
    Form *f_qvar = f->left;
    if (strcmp(f_qvar->data, qname)) {
      if (hash_findItem(*replfv, f_qvar->data)) printf("capture error\n");
    }
  }

  return 0;
}


// check if there is a term t such that f[qname/t] = g
int check_legal_existsi(char *qname, Form *f, Form *g) {
  // traverse f and g
  // figure out replacement t
  // ensure same structure other than replacing qname in f with t
  // ensure free vars in t don't get captured in g

  HashTable *replfv = NULL;
  Form *repl = NULL;
  int err = find_qvar_subst(f, g, qname, &repl, &replfv);

  if (replfv) hash_destroy(replfv);

  return err;
}

Form *const_term_eval(Form *f);
int const_eval_children(Form *f, Form **lhs, Form **rhs) {
  *lhs = *rhs = NULL;
  if (f->tag == F_TERM_TLIST || f->tag == F_TERM_TSET)
    return 0; // these are evaluted specially in const_term_eval
  if (F_ISBINARY(f->tag) || F_ISUNARY(f->tag)) {
    *lhs = const_term_eval(f->left);
    if (!*lhs) return -1;
  }
  if (F_ISBINARY(f->tag)) {
    *rhs = const_term_eval(f->right);
    if (!*rhs) {
      form_free(*lhs);
      return -1;
    }
  }
  return 0;
}

int list_contains(Form *e, Form *list) {
  if (list->tag != F_LIST_CONS) return 0;
  if (!form_cmp(e, list->left)) return 1;
  return list_contains(e, list->right);
}

int list_len(Form *list) {
  if (list->tag != F_LIST_CONS) return 0;
  return 1 + list_len(list->right);
}

Form *list_eval(Form *f, Form *head, Form *tail, int asSet) {
  if (f->tag == F_LIST_NONE) return head;
  Form *e = const_term_eval(f->left);
  if (!e) return NULL;
  if (!head) {
    // first element of entire list
    head = tail = form_new(F_LIST_CONS, e, 0, form_new(F_LIST_NONE, 0, 0, 0));
    if (!list_eval(f->right, head, tail, asSet)) {
      form_free(head);
      return NULL;
    }
    return head;
  } else {
    // middle element of entire list
    if (asSet && list_contains(e, head)) { // discard this new element
      form_free(e);
    } else { // splice in this new element
      e = form_new(F_LIST_CONS, e, 0, tail->right);
      tail->right = e;
      tail = e;
    }
    if (!list_eval(f->right, head, tail, asSet))
      return NULL; // top of recursion will free head
    return head;
  }
}

Form *const_list_eval(Form *f, int asSet) {
  int vartype = (asSet ? F_TERM_TSET : F_TERM_TLIST);
  if (f->tag != vartype) return NULL;
  if (f->left->tag == F_LIST_NONE) return form_dup(f);
  Form *body = list_eval(f->left, NULL, NULL, asSet);
  if (!body) return NULL;
  return form_new(vartype, body, 0, 0);
}

Form *list_merge(Form *f, Form *head, Form **tail, int asSet) {
  if (f->tag == F_LIST_NONE) return head;
  Form *e = const_term_eval(f->left);
  if (!e) return NULL;
  if (!head) {
    // first element of entire list
    head = *tail = form_new(F_LIST_CONS, e, 0, form_new(F_LIST_NONE, 0, 0, 0));
    if (!list_merge(f->right, head, tail, asSet)) {
      form_free(head);
      return NULL;
    }
    return head;
  } else {
    // middle element of entire list
    if (asSet && list_contains(e, head)) { // discard this new element
      form_free(e);
    } else { // splice in this new element
      e = form_new(F_LIST_CONS, e, 0, (*tail)->right);
      (*tail)->right = e;
      *tail = e;
    }
    if (!list_merge(f->right, head, tail, asSet))
      return NULL; // top of recursion will free head
    return head;
  }
}

Form *const_list_merge(Form *f, Form *g, int asSet) { // f and g already evaluated (uniquified, reduced, etc.)
  int vartype = (asSet ? F_TERM_TSET : F_TERM_TLIST);
  if (f->tag != vartype || g->tag != vartype) return NULL;
  if (f->left->tag == F_LIST_NONE) return form_dup(g);
  if (g->left->tag == F_LIST_NONE) return form_dup(f);
  Form *tail1 = NULL;
  Form *body1 = list_merge(f->left, NULL, &tail1, 0);
  if (!body1) return NULL;
  Form *body2 = list_merge(g->left, body1, &tail1, asSet);
  if (!body2) {
    form_free(body1);
    return NULL;
  }
  return form_new(vartype, body2, 0, 0);
}

Form *const_term_eval(Form *f) {
  Form *lhs = NULL, *rhs = NULL, *ret = NULL;
  if (const_eval_children(f, &lhs, &rhs))
    return NULL;
  switch(f->tag) {
    case F_TERM_INT:
    case F_TERM_STR:
    case F_TERM_BYTES:
      ret = form_dup(f);
      break;
    case F_TERM_TLIST:
      ret = const_list_eval(f, 0);
      break;
    case F_TERM_TSET:
      ret = const_list_eval(f, 1);
      break;
    case F_TERM_SIZE:
      if (lhs->tag == F_TERM_BYTES)
	ret = form_newval(F_TERM_INT, lhs->len);
      else if (lhs->tag == F_TERM_STR)
	ret = form_newval(F_TERM_INT, strlen(lhs->data));
      else if (lhs->tag == F_TERM_TLIST)
	ret = form_newval(F_TERM_INT, list_len(lhs->left));
      else if (lhs->tag == F_TERM_TSET)
	ret = form_newval(F_TERM_INT, list_len(lhs->left));
    case F_TERM_PLUS:
      if (lhs->tag == F_TERM_INT && rhs->tag == F_TERM_INT)
	ret = form_newval(F_TERM_INT, lhs->value + rhs->value);
      break;
    case F_TERM_MINUS:
      if (lhs->tag == F_TERM_INT && rhs->tag == F_TERM_INT)
	ret = form_newval(F_TERM_INT, lhs->value - rhs->value);
      break;
    case F_TERM_JOIN:
      ret = const_list_merge(lhs, rhs, 0);
      break;
    case F_TERM_UNION:
      ret = const_list_merge(lhs, rhs, 1);
      break;
    default:
      break;
  }
  if (rhs) form_free(rhs);
  if (lhs) form_free(lhs);
  return ret;
}

int const_cmp(Form *f, Form *g) {
  if (f->tag == F_TERM_STR && g->tag == F_TERM_STR)
    return strcmp(f->data, g->data);
  if (f->tag == F_TERM_INT && g->tag == F_TERM_INT) {
    if (f->value < g->value) return -1;
    else if (f->value == g->value) return 0;
    else return +1;
  } else if (!form_cmp(f, g))
    return 0; // for equality checking
  else
    return 1;
  // note: gt, lt, ge, le are undefined for most types, so returning 1 is fine
}

Form *const_eval(Form *f) {
  Form *lhs = NULL, *rhs = NULL;
  if (F_ISTERM(f->tag)) {
    lhs = const_term_eval(f);
    if (!lhs) return NULL;
    return form_new(F_PRED_EQ, form_dup(f), 0, lhs);
  }
  if (const_eval_children(f, &lhs, &rhs))
    return NULL;
  int ok = 0;
  switch(f->tag) {
    case F_PRED_EQ: ok = (const_cmp(lhs, rhs) == 0); break;
    case F_PRED_NE: ok = (const_cmp(lhs, rhs) != 0); break;
    case F_PRED_LT: ok = (const_cmp(lhs, rhs) < 0); break;
    case F_PRED_GT: ok = (const_cmp(lhs, rhs) > 0); break;
    case F_PRED_LE: ok = (const_cmp(lhs, rhs) <= 0); break;
    case F_PRED_GE: ok = (const_cmp(lhs, rhs) >= 0); break;
    case F_PRED_ISSTR: ok = (lhs->tag == F_TERM_STR); break;
    case F_PRED_ISINT: ok = (lhs->tag == F_TERM_INT); break;
    case F_PRED_ISBYTES: ok = (lhs->tag == F_TERM_BYTES); break;
    case F_PRED_ISTSET: ok = (lhs->tag == F_TERM_TSET); break;
    case F_PRED_ISTLIST: ok = (lhs->tag == F_TERM_TLIST); break;
    case F_PRED_IN: ok = ((rhs->tag == F_TERM_TSET || rhs->tag == F_TERM_TLIST) && list_contains(lhs, rhs->left)); break;
    default: break;
  }
  if (lhs) form_free(lhs);
  if (rhs) form_free(rhs);
  return (ok ? form_dup(f) : NULL);
}

Form *extern_eval(const char *cmd, int cmdlen, Form *f) {
  // ideally, this would invoke various external provers. For now we will make do with
  // this one very weak stub prover.
  int n = strlen("extern");
  if (cmdlen < n) return NULL;
  cmdlen -= n;
  cmd += n;
  while (cmdlen > 0 && __isspace(*cmd)) { cmdlen--; cmd++; }
  n = strlen("set-theory");
  if (cmdlen >= n && !strncmp(cmd, "set-theory", n) && __isspace(cmd[n])) {
    printf("invoking set-theory prover\n");
    form_printf("parameter: %s\n", form_s(f));
    Form *x, *set, *disj;
    if (!form_scan(f, "%{term} in %{term} iff %{Stmt}", &x, &set, &disj)) {
      // make sure lhs is what we expect
      if (x->tag != F_TERM_SVAR && x->tag != F_TERM_QVAR && x->tag != F_TERM_PREF)
	return NULL;
      if (set->tag != F_TERM_TSET && set->tag != F_TERM_TLIST)
	return NULL;
      // make sure rhs is the expansion of lhs
      // (x1 or (x2 or (x3 or ...)))
      // it would be better to have in the other direction, but oh well
      if (set->left->tag == F_LIST_NONE) {
	if (disj->tag != F_STMT_FALSE) return NULL;
	return form_dup(f);
      }
      Form *e = set->left;
      Form *d = disj;
      while (e->tag != F_LIST_NONE) {
	Form *d0;
	if (e->right->tag != F_LIST_NONE) {
	  // not last element
	  d0 = d->left;
	  d = d->right;
	} else {
	  d0 = d;
	}
	if (d0->tag != F_PRED_EQ || form_cmp(d0->left, x) || form_cmp(d0->right, e->left))
	  return NULL;
	e = e->right;
      }
      return form_dup(f);
    }
    return NULL;
  }
  else return NULL;
}

#define EVAL_FAIL(msg...) do { printf(msg); kill(eval); return -1*__LINE__; } while (0);

/** Evaluate a single line */
int 
eval_run1(struct eval *eval, const char *code, int codelen, PointerVector *args) 
{
	Judge *f, *g;
	Form *h;
	struct hc hc;
	int rc;

	eval->code = code;
	if ((rc = hc_match(code, codelen, &hc, args, eval->rules))) {
		printf("invalid hintcode (%dB): %.*s\n", codelen, codelen, code);
		switch (rc) {
		  case -1: EVAL_FAIL("  (hint not recognized)\n");
		  case -2: EVAL_FAIL("  (missing required space)\n");
		  case -3: EVAL_FAIL("  (missing argument)\n");
		  case -4: EVAL_FAIL("  (garbage at end / extra arguments)\n");
		  case -5: EVAL_FAIL("  (malformed / illegal argument)\n");
		  default: return -101;
		}
	}

	if (hc.nstackargs > PointerVector_len(&eval->stack))
		EVAL_FAIL("too few stack operands for hintcode: %.*s\n", codelen, code);

	switch (hc.tag) {
		case HC_RULE: // stack , a1->p1 , ... , aN->pN :: stack , a1U...UaN->c
			if (apply_rule(eval, hc.rule, hc.argf)) return -102;
			break;
		case HC_PUSHDOWN: // stack , stack(n), a->F :: stack , a->F , stack(n)
			if (hc.argi <= 0)
			  EVAL_FAIL("pushdown <n> expects at n > 0\n");
			if (hc.argi >= PointerVector_len(&eval->stack))
			  EVAL_FAIL("pushdown <n> expects at least n+1 elements on the stack\n");
			f = eval_pop(eval);
			PointerVector_truncate(&eval->recentstack);
			slipin(eval, f, hc.argi);
			break;
		case HC_PULLUP: // stack , a->F, stack(n) :: stack , stack(n), a->F
			if (hc.argi <= 0)
			  EVAL_FAIL("pushdown <n> expects at n > 0\n");
			if (hc.argi >= PointerVector_len(&eval->stack))
			  EVAL_FAIL("pullup <n> expects at least n+1 elements on the stack\n");
			f = slipout(eval, hc.argi);
			PointerVector_truncate(&eval->recentstack);
			push(eval, f);
			break;
		case HC_EFE: // arg=P says f(F); stack , a->P says F=G , b->P says f(G) :: stack , aUb->P says f(F)
		/* alt  */   // arg=f(F); stack , a->F=G , b->f(G) :: stack , aUb->f(F)
		/* alt2 */   // stack , a->P says F=G , b->P says H :: stack , aUb->P says H[F/G]
		/* alt3 */   // stack , a->F=G , b->H :: stack , aUb->H[F/G]
			h = hc.argf; // special case: may be null
			g = eval_pop(eval);
			f = eval_pop(eval);
			if (f->concl->tag == F_STMT_SAYS) {
			  if (g->concl->tag != F_STMT_SAYS || (h && h->tag != F_STMT_SAYS)
			      || form_cmp(f->concl->left, g->concl->left)
			      || (h && form_cmp(f->concl->left, h->left))
			      || f->concl->right->tag != F_PRED_EQ)
			    EVAL_FAIL("efe (for principals) expects two elements on stack, of form \"P says t2=t1\" and \"P says F(t1)\"\n"
				"and optionally an argument of form \"P says F(t2)\"\n");
			  if (!hc.argf)
			    h = form_new(F_STMT_SAYS, form_dup(f->concl->left), 0,
				form_repl(g->concl->right, f->concl->right->right, f->concl->right->left));
			  if (form_cmp_replace(g->concl->right, h->right,
				f->concl->right->right, f->concl->right->left)) {
			    form_free(h);
			    EVAL_FAIL("not a valid equals-for-equals result\n");
			  }
			} else {
			  if (f->concl->tag != F_PRED_EQ)
			    EVAL_FAIL("efe (for statements) expects two elements on stack, of form \"t2=t1\" and \"F(t1)\"\n"
				"and optionally an argument of form \"F(t2)\"\n");
			  if (!hc.argf)
			    h = form_repl(g->concl, g->concl->right, g->concl->left);
			  if (form_cmp_replace(g->concl, h,
				f->concl->right, f->concl->left)) {
			    form_free(h);
			    EVAL_FAIL("not a valid equals-for-equals result\n");
			  }
			}
			push(eval, judge_new(eval, h));
			break;
		case HC_IMPI: // arg=G; stack ,  [a,G]->F :: stack , a->G imp F
			h = hc.argf;
			f = eval_pop(eval);
			g = judge_new(eval, form_new(F_STMT_IMP, h, 0, f->concl));
			judge_del(g, h);
			push(eval, g);
			break;
		case HC_DUP: // stack ,  a->F :: stack , a->F , a->F
			f = eval_peek(eval);
			g = judge_dup(f);
			push(eval, g);
			break;
		case HC_POP: // stack ,  a->F :: stack 
			f = eval_pop(eval);
			judge_free(f);
			PointerVector_truncate(&eval->recentstack);
			done(eval, 0);
			break;
		case HC_RENAME: // arg=G; stack , a->F :: stack , a->G (where F =a G)
			if (do_rename(eval, hc.argf)) return -103;
			break;
		case HC_CONST: // arg=G; stack :: stack , []->G=c (where eval(G)=c)
			h = const_eval(hc.argf);
			if (!h)
			  EVAL_FAIL("could not evaluate to a constant\n");
			f = judge_new(eval, h);
			push(eval, f);
			break;
		case HC_EXTERN: // arg=G; stack :: stack , []->F (where external proof checker returns F on input G)
			h = extern_eval(code, codelen, hc.argf);
			if (!h)
			  EVAL_FAIL("could not evaluate external proof\n");
			f = judge_new(eval, h);
			push(eval, f);
			break;
		case HC_FORALLI: // arg=v; stack , a->F :: stack , a->forall v : F
			h = hc.argf;
			if (h->tag != F_TERM_QVAR)
			  EVAL_FAIL("foralli requires a quantified var\n");
			f = eval_pop(eval);
			g = judge_new(eval, form_new(F_STMT_FORALL, h, 0, f->concl));
			push(eval, g);
			break;
		case HC_FORALLE: // arg=t; stack , a->forall $v : F :: stack , a->F[$v/t]
			/* todo: forbid if F has params except when t is dummy $v */
			if (!F_ISTERM(hc.argf->tag))
			  EVAL_FAIL("foralle requires a term\n");
			f = eval_pop(eval);
			h = f->concl;
			if (h->tag != F_STMT_FORALL)
			  EVAL_FAIL("foralle expects one element on stack, of form \"forall $v : F\"\n");
			assert(h->left && h->left->tag == F_TERM_QVAR);
			h = form_dup(h->right);
			if (form_replace_qvar(h, f->concl->left->data, hc.argf) < 0)
			  EVAL_FAIL("replacement capture error\n");
			g = judge_new(eval, h);
			push(eval, g);
			break;
		case HC_SAYSFORALL: // stack , a->P says forall $v : F , closed(P) :: stack , a->forall $v : P says F
			g = eval_pop(eval);
			f = eval_pop(eval);
			if (g->concl->tag != F_PRED_CLOSED || // closed(P)
			    f->concl->tag != F_STMT_SAYS || //  P' says ...
			    form_cmp(f->concl->left, g->concl->left) || // P = P'
			    f->concl->right->tag != F_STMT_FORALL || // says forall ...
			    f->concl->right->left->tag != F_TERM_QVAR) // forall $v : ...
			  EVAL_FAIL("saysforall expects two elements on stack, of form \"closed(P)\" and \"P says forall $v : F\"\n");
			// check for variable capture: P must not have $v free
			if (appears_free_in(f->concl->right->left, g->concl->left))
			  EVAL_FAIL("variable capture error\n");
			f = judge_new(eval, form_dup(f->concl));
			h = f->concl;
			f->concl = h->right;
			h->right = f->concl->right;
			f->concl->right = h;
			push(eval, f);
			break;
		case HC_FORALLSAYS: // stack , a->forall $v : P says F , closed(P) :: stack , a->P says forall $v : F
			g = eval_pop(eval);
			f = eval_pop(eval);
			if (g->concl->tag != F_PRED_CLOSED || // closed(P)
			    f->concl->tag != F_STMT_FORALL || //  forall ...
			    f->concl->left->tag != F_TERM_QVAR || // forall $v : ...
			    f->concl->right->tag != F_STMT_SAYS || //  forall $v : P' says ...
			    form_cmp(f->concl->right->left, g->concl->left)) // P = P'
			  EVAL_FAIL("saysforall expects two elements on stack, of form \"closed(P)\" and \"P says forall $v : F\"\n");
			// check for variable capture: P must not have $v free
			if (appears_free_in(f->concl->left, g->concl->left))
			  EVAL_FAIL("variable capture error\n");
			f = judge_new(eval, form_dup(f->concl));
			h = f->concl;
			f->concl = h->right;
			h->right = f->concl->right;
			f->concl->right = h;
			push(eval, f);
			break;
		case HC_EXISTSI: // arg=exists $v : F; stack , a->F[$v/t] :: stack , a->exists $v : F
			h = hc.argf;
			if (h->tag != F_STMT_EXISTS)
			  EVAL_FAIL("existsi requires a statement, of form \"exists $v : F\"\n");
			f = eval_pop(eval);
			if (check_legal_existsi(h->left->data, h->right, f->concl))
			  EVAL_FAIL("illegal existential abstraction\n");
			g = judge_new(eval, h);
			push(eval, g);
			break;
		case HC_GROUPI: // arg=[[ $v : G ]]; stack , a->P says F , b->G[$v/P] :: stack , aUb->[[ $v : G ]] says F
				  // arg=[( $v : G )]; stack , a->P says F , b->G[$v/P] :: stack , aUb->[( $v : G )] says F
			if (hc.argf->tag != F_TERM_CIGRP && hc.argf->tag != F_TERM_DIGRP)
			  EVAL_FAIL("groupi requires a term, of form \"[[ $v : G ]]\" or \"[( $v : G )]\"\n");
			g = eval_pop(eval);
			f = eval_pop(eval);
			if (f->concl->tag != F_STMT_SAYS)
			  EVAL_FAIL("groupi requires two elements on stack, of form \"P says F\" and \"G[$v/P]\"\n");
			h = form_dup(hc.argf->right);
			if (form_replace_qvar(h, hc.argf->left->data, f->concl->left) < 0) {
			  form_free(h);
			  EVAL_FAIL("replacement capture error\n");
			}
			if (form_cmp(h, g->concl)) {
			  form_free(h);
			  EVAL_FAIL("groupi can't unify second premise\n");
			}
			form_free(h);
			f = judge_new(eval, form_dup(f->concl));
			form_free(f->concl->left);
			f->concl->left = form_dup(hc.argf);
			push(eval, f);
			break;
		case HC_ASSUME: // arg=G; stack :: stack , [G]->G
			// an assuption: add to the list of assumptions ('judgements')
			h = hc.argf;
			f = judge_new(eval, h);
			judge_add(f, h);
			push(eval, f);
			break;
		default:
			assert(0);
	}

	return 0;
}

int 
eval_run(struct eval *eval, const char *code, PointerVector *args) 
{
	uint64_t trun;
	unsigned long ktotal, kused;
	const char *nextcode, *origcode;
	int len, err, lines;

	if (!code) {
		nxcompat_fprintf(stderr, "cannot evaluate empty proof\n");
		return -1;
	}

	len = strlen(code);
	if (!len || len > PROOF_RULELENGTH) {
		nxcompat_fprintf(stderr, "proof length out of bounds\n");
		return -1;
	}

	lines = 0;
	origcode = code;
	nextcode = skipws(code);
//	trun = rdtsc64();
	while (nextcode && *nextcode && nextcode - origcode < len) {
		eval->code = code = nextcode;

		// search for next statement
		while (*nextcode) {
		  nextcode += strcspn(nextcode, ";\"");
		  // does not handle escapes inside strings
		  if (*nextcode == '\"') {
		    nextcode += 2 + strcspn(nextcode + 1,  "\"");
		  } else break;
		}
		assert(nextcode - code != 0);

		// skip comments
		if (code[0] == '#') {
		  nextcode = code + strcspn(code, ";\n");
		  printf("%.*s\n", nextcode - code, code);
		  nextcode = skipws(nextcode+1);
		  continue;
		}

		// evaluate line
		err = eval_run1(eval, code, (nextcode-code), args);
		if (err) {
			eval->errors++;
			return err;
		}
		nextcode = skipws(nextcode+1);
		lines++;
	}
//	trun = rdtsc64() - trun;

	return 0;
}

void dump_eval_stack(struct eval *eval) 
{
	Judge *f;
	char *s;
	int i, n;
	
	n = PointerVector_len(&eval->stack);
	printf("  stack: (%d formulas)\n", n);
	for (i = 0; i < n; i++) {
		f = PointerVector_nth(&eval->stack, i);
		assert(f && f->concl);
		s = form_to_pretty(f->concl, 0);
		printf("   %3d: [%d] -> %s\n", i, PointerVector_len(&f->hyp), s);
		nxcompat_free(s);
	}
}

