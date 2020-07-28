
#ifdef __NEXUSKERNEL__
#define print_please printk_current
#else
#define print_please printf
#endif

#define dbgprintf(...) 						\
	do { 							\
		if (g->flags & GUARD_DEBUG_POLICY) 		\
			print_please("guard: " __VA_ARGS__); 	\
	} while (0)

#define PRETTY(f, cols) form_to_pretty(form_repl_all(f, g->param_vals, g->param_names), cols)

#ifdef __NEXUSKERNEL__
#define FILE void
#define stdout NULL
#define fopen(filename, mode) NULL
#define fclose(file) do { } while (0)
#define fprintf(file, args...) printk(args)
#endif

Judge *judge_new(struct eval *eval, Form *concl);
void judge_add(Judge *f, Form *h);
void judge_del(Judge *f, Form *h);
Judge *judge_dup(Judge *g);
void judge_free(Judge *f);

void judge_print(FILE *out, Judge *f, char *fmt, char *name, PointerVector *replnames, PointerVector *replvals);

static void eval_init(struct eval *eval);
int eval_run(struct eval *eval, char *code, PointerVector *args);
void eval_clear(struct eval *eval);
void eval_dump(struct eval *eval);
void eval_destroy(struct eval *eval);
static void eval_rule_introduce(struct eval *eval, struct _Lemma *rule);

void guard_add_std_rules(struct guard *g);

Guard *guard_create(void) {
	Guard *g = nxcompat_alloc(sizeof(struct guard));
	guard_init(g);
	return g;
}

void guard_init(Guard *g) {
	memset(g, 0, sizeof(struct guard));
	PointerVector_init(&g->facts, 1, POINTERVECTOR_ORDER_PRESERVING);
	PointerVector_init(&g->vars, 1, POINTERVECTOR_ORDER_PRESERVING);
	g->params = hash_new_vlen(4, hash_strlen);
	g->param_names = nxcompat_alloc(sizeof(PointerVector));
	g->param_vals = nxcompat_alloc(sizeof(PointerVector));
	PointerVector_init(g->param_names, 1, POINTERVECTOR_ORDER_PRESERVING);
	PointerVector_init(g->param_vals, 1, POINTERVECTOR_ORDER_PRESERVING);
	eval_init(&g->eval);
	g->eval.params = g->params;
	g->eval.param_names = g->param_names;
	g->eval.param_vals = g->param_vals;
	g->pfout = stdout;
	guard_add_std_rules(g);
}

void guard_destroy(Guard *g) {
	if (g->gf) nxcompat_free(g->gf);
	if (g->gfx) form_free(g->gfx);
	memset(g, 0, sizeof(struct guard));
}

void guard_free(Guard *g) {
	guard_destroy(g);
	nxcompat_free(g);
}

void guard_setdebug(Guard *g, int flags) {
	g->eval.flags = g->flags = flags;
}

void guard_setdebugpfout(Guard *g, FILE *out) {
	g->pfout = out;
}

void guard_dump(Guard *g) {
	eval_dump(&g->eval);
}

int guard_setgoal(Guard *g, Formula *gf) {
	Form *gfx;

	if (!gf)
		return -1;

	gfx = form_from_der(gf);
	if (!gfx) 
		return -1;

	if (g->gf) 
		nxcompat_free(g->gf);
	if (g->gfx) 
		form_free(g->gfx);

	g->gf = nxcompat_alloc(der_msglen(gf->body));
	memcpy(g->gf, gf, der_msglen(gf->body));
	g->gfx = gfx;
	return 0;
}

Formula *guard_getgoal(Guard *g) {
	return g->gf;
}

int guard_addpolicy(Guard *g, Formula *fact) {
	Form *f;

	if (!fact)
		return -1;

	f = form_from_der(fact);
	if (!f) 
		return -1;
	PointerVector_append(&g->facts, f);
	return 0;
}

struct gvar {
	char *key;
	Form *val;
};

void guard_set_param(Guard *g, char *paramname, Form *val) {
  Form *old = hash_delete(g->params, paramname);
  if (old) {
    int i, n = PointerVector_len(g->param_names);
    for (i = 0; i < n; i++) {
      Form *s = PointerVector_nth(g->param_names, i);
      if (!strcmp(s->data, paramname)) {
	PointerVector_deleteAt(g->param_names, i);
	PointerVector_deleteAt(g->param_vals, i);
	form_free(s);
	break;
      }
    }
    form_free(old);
  }
  if (val) {
    hash_insert(g->params, paramname, val);
    int is_stmt = F_ISSTMT(val->tag);
    Form *s = form_newdata(is_stmt ? F_STMT_PREF : F_TERM_PREF, strdup(paramname), -1);
    PointerVector_append(g->param_names, s);
    PointerVector_append(g->param_vals, val);
  }
}

int guard_setvar(Guard *g, char *var, Form *val) {
	char *key = strdup(var);
	int i, n = PointerVector_len(&g->vars);
	struct gvar *v = NULL;
	for (i = 0; i < n; i++) {
		v = PointerVector_nth(&g->vars, i);
		if (!strcmp(v->key, key))
			break;
		v = NULL;
	}
	if (!v) {
		v = nxcompat_alloc(sizeof(struct gvar));
		v->key = key;
		PointerVector_append(&g->vars, v);
	} else {
		nxcompat_free(key);
		form_free(v->val);
	}
	v->val = form_dup(val);
	return 0;
}

Form *check_subst_var(Form *f, struct gvar *v) {
    if (!f) return NULL;
    if (!v) return NULL;
    if (!f->data) return NULL;
    if (!v->key) return NULL;
    if (!v->val) return NULL;
    if (strcmp(f->data, v->key))
      return f;
    form_free(f);
    return form_dup(v->val);
}


// todo: use form_set_param() instead
Form *replace_var(Guard *g, Form *f) {
	if (!f) return NULL;

	switch(f->tag & F_ARITY_MASK) {
	  case F_IS_DATA:
	    if (f->tag == F_TERM_PREF) {
		    int i, n = PointerVector_len(&g->vars);
		    struct gvar *v = NULL;
		    for (i = 0; i < n; i++) {
			    v = PointerVector_nth(&g->vars, i);
			    f = check_subst_var(f, v);
			    if (!f) return NULL;
		    }
	    }
	    break;
	  case F_IS_TERNARY: f->mid = replace_var(g, f->mid);
	    // fall through
	  case F_IS_BINARY: f->right = replace_var(g, f->right);
	    // fall through
	  case F_IS_UNARY: f->left = replace_var(g, f->left);
	    break;
	  default:
	    break;
	}
	return f;
}

void formula_print_recurse(Form *f) {
  print_please("formula at 0x%p\n", f);
  if (!f) return;
  print_please("  tag = 0x%x ", f->tag);
  print_please("  left  = 0x%p ", f->left);
  print_please("  right = 0x%p\n", f->right);
  if ((f->tag & F_ARITY_MASK) == F_IS_BINARY) {
    if (f->left) formula_print_recurse(f->left);
    if (f->right) formula_print_recurse(f->right);
  }
  print_please(" => ");
  char *s = form_to_pretty(f, 0);
  print_please("  %s\n", s);
  nxcompat_free(s);
}

int unify_result(char *msg, int res, Form *f, Form *g, struct HashTable *map) {
  if (!res) return 0;
  print_please("%s failed tags (ret = %d): %08x %08x:\n", msg, res, f->tag, g->tag);
  char *s = form_to_pretty(f, -80);
  print_please("f = %s\n", s);
  nxcompat_free(s);
  s = form_to_pretty(g, -80);
  print_please("g = %s\n", s);
  nxcompat_free(s);
  return res;
}


int unify(Form *f, Form  *g, struct HashTable *map) {
  if (g->tag == F_TERM_QVAR) {
    assert(g->len == -1);
    assert(strlen(g->data) < 50);
    print_please("checking for %s\n", g->data);
    Form *r = (Form *)hash_findItem(map, g->data); // xxx: this line is hanging
    print_please("got for %s replacement %p\n", g->data, r);
    if (r) {
      // policy metavar already unified
      return unify_result("unify", form_cmp(f, r), f, r, map);
    } else {
      // check level, set replacement
      /* if ((f->tag & (g->tag & F_TYPE_MASK)) != (g->tag & F_TYPE_MASK))
	return unify_result("unify", 1, f, g, map); */
      hash_insert(map, g->data, f);
      return unify_result("unify", 0, f, g, map);
    }
  }
  // policy goal is not a metavar
  if (f->tag != g->tag)
    return unify_result("unify", 1, f, g, map);
  switch (f->tag & F_ARITY_MASK) {
    case F_IS_TERNARY:
      if (!f->mid != !g->mid) return unify_result("unify", 1, f, g, map);
      if (f->mid && unify(f->mid, g->mid, map)) return 1;
      // fall through
    case F_IS_BINARY:
      if (!f->right != !g->right) return unify_result("unify", 1, f, g, map);
      if (f->right && unify(f->right, g->right, map)) return 1;
      // fall through
    case F_IS_UNARY:
      if (!f->left != !g->left) return unify_result("unify", 1, f, g, map);
      if (f->left && unify(f->left, g->left, map)) return 1;
      return unify_result("unify", 0, f, g, map);
    case F_IS_EMPTY:
      return unify_result("unify", 0, f, g, map);
    case F_IS_VALUE:
      return unify_result("unify", f->value != g->value, f, g, map);
    case F_IS_DATA:
      if (f->len != g->len) return unify_result("unify", 1, f, g, map);
      if (f->len == 0)
	return unify_result("unify", 0, f, g, map);
      else if (f->len < 0)
	return unify_result("unify", strcmp(f->data, g->data), f, g, map);
      else
	return unify_result("unify", memcmp(f->data, g->data, f->len), f, g, map);
    default:
      return unify_result("unify", 1, f, g, map); 
  }
}

int unify_shown_to_policy(Form *shown, Form *gfx) {
  struct HashTable *map = hash_new_vlen(16, hash_strlen);
  int ret = unify(shown, gfx, map);
  hash_destroy(map);
  return ret;
}

static void proof_print(Judge *shown, Guard *g)
{
	FILE *pfout = g->pfout;

	// only write if guard is in debug mode
	if (!(g->flags & GUARD_DEBUG_PROOFS))
		return;       
	
	// use stdout if no output file is set
	if (!pfout)
	    pfout = stdout;

	// print
	judge_print(pfout, shown, "html", "last checked", 
		    g->param_names, g->param_vals);
}

/** See if the fact proves any of the hypotheses.
    If so, remove the hypothesis from the set. 
 
    @return 1 if it matches or 0 otherwise */
static int formula_match(Form *fact, PointerVector *hypotheses)
{
	Form *hypo;
	int i, len;

	if (!fact)
		return 0;

	len = PointerVector_len(hypotheses);
	for (i = 0; i < len; i++) {
		hypo = PointerVector_nth(hypotheses, i);
		if (!form_cmp(fact, hypo)) {
			PointerVector_deleteAt(hypotheses, i);
			return 1;
		}
	}

	return 0;
}


/** Very basic built-in theorem prover
 
    @returns 1 if formula is true. 0 if false or unknown */
static int formula_prove(Form *f)
{
	// try "P says valid-predicate"
	if (f->tag == F_STMT_SAYS) {
	  Form *pred = f->right;
	  if (pred->tag == F_PRED_EQ) {
	    if (!form_cmp(f->left, f->right)) { // p = p
	      printf("discharged because p=p is a valid predicate, for any p\n");
	      return 1;
	    }
	  }
#if 0 // uses long deprecated F_INT_CONST
	  else if (pred->tag == F_PRED_LE && pred->left->tag == F_INT_CONST && pred->right->tag == F_INT_CONST) { // i <= j
	    int i = pred->left->value;
	    int j = pred->right->value;
	    if (i <= j) {
	      printf("discharged because %d<=%d is a valid predicate\n", i, j);
	      match = 1;
	    }
	  }
	  else if (pred->tag == F_PRED_GE && pred->left->tag == F_INT_CONST && pred->right->tag == F_INT_CONST) { // i <= j
	    int i = pred->left->value;
	    int j = pred->right->value;
	    if (i >= j) {
	      printf("discharged because %d>=%d is a valid predicate\n", i, j);
	      match = 1;
	    }
	  }
#endif
	  // todo: other valid predicates
	}
	else if (f->tag == F_STMT_TRUE) {
	  printf("discharged \'true\'\n");
	  return 1;
	}

	return 0;
}

// DEBUG XXX remove
#ifndef __NEXUSKERNEL__
#define printk_current printf
#endif

#ifdef DO_NOTDONE
int guard_check_new(Form *goal, const char *proof)
{
	return 0;
}
#endif

/** Verify whether a guard's goal is satisfied by the given grounds. 

    @param pg is a set of grounds: 
    	   facts ("credentials"), rules ("hintcode") and authorities
	   that attest to runtime properties.

    @param req is another ground. It is not included in grounds, because
           many requests need one unique ground. Adding/removing to pg
	   is unnecessary overhead.

 XXX the following code leaks like a drunk after a kegger.
 XXX grounds checking is complicated, which makes it hard to prove 
     sufficiency and necessity
 */
int guard_check(Guard *g, Form *req, _Grounds *pg)
{
	PointerVector args, ocs, *leaves;
	Form *gfx;
        struct opencred *oc;
	char *code, *s;
	int ret, i, j, npremises, nocs, nfacts, ncred, match;

	// check input sanity
	if (!pg || !g->gf || !g->gfx) {
		printk_current("[guard] Deny. Missing goal or grounds\n");
		return -1;
	}

	// setup state
	eval_clear(&g->eval);
	gfx = replace_var(g, form_dup(g->gfx));
	PointerVector_init(&args, 16, POINTERVECTOR_ORDER_PRESERVING);
	ncred = (pg ? pg->numleaves : 0);

	// XXX when are inline arguments used? 
	for (i = 0; i < pg->argc; i++) {
	  Form *f = form_from_der(pg->args[i]);
	  if (!f) {
	    printk_current("[guard] Deny. Argument %d is invalid\n", i);
	    return -1;
	  }
	  PointerVector_append(&args, f);
	}

	// find a proof
	if (pg->hints)
		code = pg->hints;
	else if (g->proof)
		code = g->proof;
	else {
		printk_current("[guard] Deny. No proof to evaluate\n");
		return -1;
	}

	// check proof
	if ((ret = eval_run(&g->eval, code, &args)) < 0) {
		printk_current("[guard] Deny. proof is not well formed\n");
		PointerVector_dealloc(&args);
		return ret;
	}
	PointerVector_dealloc(&args);

	// single proven statement?
	if (PointerVector_len(&g->eval.stack) != 1) {
	  printk_current("[guard] Deny. no single proven statement\n");
	  return -1;
	}

	Judge *shown = PointerVector_deleteAt(&g->eval.stack, 0);

	// verify that proof matches goal
	if (unify_shown_to_policy(shown->concl, gfx)) {
	  printk_current("[guard] Deny. proof does not match goal\n");

#ifndef NDEBUG
	  char *f1 = PRETTY(gfx, 80);
	  printk_current("  goal:   %s\n", f1);
	  nxcompat_free(f1);

	  f1 = PRETTY(shown->concl, 80);
	  printk_current("  proven: %s\n", f1);
	  nxcompat_free(f1);
#endif

	  judge_free(shown);
	  return -1;
	}

	// at this point, conclusion follows from hypotheses.
	// what is left is to show that all premises ('leaves') are true.

	leaves = &shown->hyp;
	npremises = PointerVector_len(leaves);
	printk_current("%d premises to verify\n", npremises);

	if (!npremises) {
	  judge_free(shown);
	  printk_current("[guard] Allow. No premises\n");
	  return 0;
	}

	// first, check if the 'req' formula matches a leave
	npremises -= formula_match(req, leaves);

	if (!npremises) {
	  judge_free(shown);
	  printk_current("[guard] Allow. Single premise\n");
	  return 0;
	}

	// next, check if any facts (installed via addpolicy) match any leaves
	nfacts = PointerVector_len(&g->facts);
	for (i = 0; i < nfacts && npremises > 0; i++)
	  npremises -= formula_match(PointerVector_nth(&g->facts, i), leaves);

	if (!npremises) {
	  judge_free(shown);
	  printk_current("[guard] Allow. Facts prove all premises\n");
	  return 0;
	}

	// open all given credentials
#ifdef DO_OPENCRED
	PointerVector_init(&ocs, ncred + 1, POINTERVECTOR_ORDER_PRESERVING);
	for (j = 0; j < ncred; j++) {
		oc = cred_open(pg->leaves[j]);
		if (oc)
			PointerVector_append(&ocs, oc);
		else
			printk_current("ERROR in cred_open for %d\n", j);
	}
	nocs = PointerVector_len(&ocs);
#endif

	// next, try the credentials (labels, authorities, signed statements)
	// for each remaining premise ...
	match = 1;
	for (i = 0; i < npremises && match; i++) {
		Form *f = PointerVector_nth(leaves, i);
		match = 0;

#ifdef DO_THEOREMPROVER
		// ... try to prove if it's a tautology
		// XXX can compound statements exist in leaves? I don't think so: DROP
		if (formula_prove(f))
			continue;
#endif

		// ... try each credential
#ifdef DO_OPENCRED
		for (j = 0; j < nocs; j++) {
			oc = PointerVector_nth(&ocs, j);
			if (!form_cmp(f, oc->f)) {
				match = oc->needed = 1;
				break;
			}
		}
#else
		for (j = 0; j < ncred; j++) {
			oc = cred_open(pg->leaves[j]);
			if (oc) {
				match = 1;
				gfree(oc);
				break;
			}
		}
#endif
		if (match)
			continue;

/// XXX replace with new notion of authorities
#if 0
		// ... try each known credential generator, aka "authority"
		auth = nxguard_authorities;
		for (; auth->name && !match; auth++) {
			Cred *cred;
		       
printk_current("NXDEBUG trying authority %s for formula %s\n", auth->name, form_to_pretty(f, 0));
			cred = auth->query(f);
			if (!cred) 
				continue;
#ifdef DO_OPENCRED
			oc = cred_open(cred);
			if (!oc) 
				continue;
			oc->needed = 1;
			PointerVector_append(&ocs, oc);
			nocs++;
#endif
			match = 1;
		}
		if (match)
			continue;
#endif

		// ... give up
		if (g->flags & GUARD_DEBUG_POLICY) {
			s = PRETTY(f, 0);
			dbgprintf("error: unproven hypothesis %s\n", s);
			nxcompat_free(s);
			break;
		}
	}

#ifdef DO_OPENCRED
#ifndef NDEBUG
	if (!match && nocs > 0 && (g->flags & GUARD_DEBUG_POLICY)) {
		dbgprintf("matched credentials were:\n");
		for (j = 0; j < nocs; j++) {
			oc = PointerVector_nth(&ocs, j);
			s = PRETTY(oc->f, 0);
			dbgprintf(" %3d: %s\n", j, s);
			nxcompat_free(s);
		}
	}
#endif
#endif

#ifdef DO_OPENCRED
        // acquire credentials from the runtime system: call the authorities
	// calls are coordinated through a start() - stop() mechanism
	//
	// XXX this is not used anywhere. why is it needed?
        if (match) {
		// start
                for (j = 0; j < nocs; j++) {
			oc = PointerVector_nth(&ocs, j);
                        if (oc->needed && oc->start && oc->start(oc)) {
                                dbgprintf("credential %d failed at start\n", j);
				match = 0;
				break;
                        }
                }
		// stop
                for (j = 0; j < nocs; j++) {
                        oc = PointerVector_nth(&ocs, j);
			if (oc->needed && oc->stop && oc->stop(oc)) {
                                dbgprintf("credential %d failed at stop\n", j);
				match = 0;
				break;
			}
                }
        }

	// todo: free authority creds, lots other cleanup
	for (j = nocs - 1; j >= 0; j--) {
		oc = PointerVector_deleteAt(&ocs, j);
		cred_close(oc);
	}
	PointerVector_dealloc(&ocs);
#endif

	judge_free(shown);

	// XXX deallocate
	//       - generated creds and opencreds
	//       - ...?

	printk_current("[guard] %s all grounds\n", 
			match ? "Allow. Matched" : "Deny. Failed to match");
	return match ? 0 : -1;
}

void guard_lemma_print(struct _Lemma *lemma) {
  if (!strcmp(lemma->name, "goal"))
    print_please("goal statement:\n");
  else
    print_please("%s %s:\n", (lemma->pf ? "lemma" : "rule"), lemma->name);
  int i;
  for (i = 0; i < lemma->numprems; i++) {
    char *s = form_to_pretty(lemma->prems[i], 0);
    print_please(" %3d: %s\n", i, s);
    nxcompat_free(s);
  }
  char *s = form_to_pretty(lemma->concl, 0);
  print_please("   /  %s\n", s);
  nxcompat_free(s);
  if (lemma->pf)
    print_please("  proof: %s\n", lemma->pf);
}

int guard_check_lemma(Guard *g, struct _Lemma *lemma)
{
	eval_clear(&g->eval);

	char *code;
	if (lemma->pf) {
	  code = lemma->pf;
	  dbgprintf("hintcode (%d bytes)\n", strlen(code));
	} else {
	  code = "true;"; // try to devine an evaluation tree
	}

	int ret;
	if ((ret = eval_run(&g->eval, code, NULL /* args are inline */)) < 0) {
	      dbgprintf("failed (err = %d): lemma proof is not well formed\n", ret);
	      return ret;
	}

	if (PointerVector_len(&g->eval.stack) != 1) {
	  dbgprintf("failed: lemma proof did not terminate properly\n");
	  return -1;
	}

	Judge *shown = PointerVector_deleteAt(&g->eval.stack, 0);

	// make sure conclusion matches
	if (form_cmp(shown->concl, lemma->concl)) {
	  dbgprintf("failed: lemma is has wrong conclusion\n");
	  judge_free(shown);
	  return -1;
	}

	// make sure premises match
	int j, i, n = PointerVector_len(&shown->hyp);
	for (i = 0; i < n; i++) {
	  Form *f = PointerVector_nth(&shown->hyp, i);
	  for (j = 0; j < lemma->numprems; j++) {
	    if (!form_cmp(f, lemma->prems[j]))
	      break;
	  }
	  if (j == lemma->numprems) {
	    dbgprintf("failed: lemma is missing required premise\n");
	    judge_free(shown);
	    return -1;
	  }
	}

	char *fmt = "html"; 
	if (g->flags & GUARD_DEBUG_PROOFS) {
	  char *name = nxcompat_alloc(strlen(lemma->name) + 10);
	  if (!strcmp(lemma->name, "goal"))
	    sprintf(name, "goal");
	  else
	    sprintf(name, "%s %s", (lemma->pf ? "lemma" : "rule"), lemma->name);
	  char *filename = NULL;
	  FILE *pfout = g->pfout;
	  if (!pfout) {
	    // set output filename based on rule name
	    filename = nxcompat_alloc(strlen(lemma->name) + strlen(fmt) + 3);
	    sprintf(filename, "%s.%s", lemma->name, fmt);
	    pfout = fopen(filename, "w");
	  }
	  if (!pfout) {
	    pfout = stdout;
	    if (filename) nxcompat_free(filename);
	    filename = NULL;
	  }
	  judge_print(pfout, shown, fmt, name, g->param_names, g->param_vals);
	  if (filename) nxcompat_free(filename);
	  if (!g->pfout && pfout != stdout) fclose(pfout);
	  nxcompat_free(name);
	}

	judge_free(shown);
	return 0;
}

#ifndef nop__NEXUSKERNEL__
static int parse_lemma_a(Guard *g, struct _Lemma *lemma, char *name, char *conclstr, char **premises) {

  Form *concl = form_from_pretty(conclstr);
  if (!concl) {
    dbgprintf("guard: conclusion is malformed:\n  %s\n", conclstr);
    return -1;
  }
  form_replace_all(concl, g->params);

  char *c = strchr(name, ' ');
  if (c) {
    lemma->arg = form_or_term_from_pretty(c+1);
    if (!lemma->arg) {
      dbgprintf("guard: argument is malformed:\n  %s\n", c+1);
      return -1;
    }
  } else {
    lemma->arg = NULL;
  }

  int nprems = 0;
  char **p = premises;
  while (*(p++)) nprems++;

  Form **prems = nxcompat_alloc((nprems ? nprems : 1) * sizeof(Form *));
  int i;
  for (i = 0; i < nprems; i++) {
    char *fstr = premises[i];
    prems[i] = form_from_pretty(fstr);
    if (!prems[i]) {
      dbgprintf("guard: premise %d is malformed:\n  %s\n", i, fstr);
      form_free(concl);
      while (i > 0) form_free(prems[--i]);
      nxcompat_free(prems);
      return -1;
    }
    form_replace_all(prems[i], g->params);
  }

  lemma->name = strdup(name);
  if (lemma->arg) strchr(lemma->name, ' ')[0] = '\0';
  lemma->concl = concl;
  lemma->numprems = nprems;
  lemma->prems = prems;
  lemma->pf = NULL;
  return 0;
}
#endif

#ifndef nop__NEXUSKERNEL__
static int parse_lemma(Guard *g, struct _Lemma *lemma, char *name, char *conclstr, va_list args) {

  Form *concl = form_from_pretty(conclstr);
  if (!concl) {
    dbgprintf("guard: conclusion is malformed:\n  %s\n", conclstr);
    return -1;
  }
  form_replace_all(concl, g->params);

  char *c = strchr(name, ' ');
  if (c) {
    lemma->arg = form_or_term_from_pretty(c+1);
    if (!lemma->arg) {
      dbgprintf("guard: argument is malformed:\n  %s\n", c+1);
      return -1;
    }
  } else {
    lemma->arg = NULL;
  }

  va_list args2;
  va_copy(args2, args);

  int nprems = 0;
  while (va_arg(args, char *)) nprems++;

  Form **prems = nxcompat_alloc((nprems ? nprems : 1) * sizeof(Form *));
  int i;
  for (i = 0; i < nprems; i++) {
    char *fstr = va_arg(args2, char *);
    prems[i] = form_from_pretty(fstr);
    if (!prems[i]) {
      dbgprintf("guard: premise %d is malformed:\n  %s\n", i, fstr);
      form_free(concl);
      while (i > 0) form_free(prems[--i]);
      nxcompat_free(prems);
      va_end(args2);
      return -1;
    }
    form_replace_all(prems[i], g->params);
  }
  va_end(args2);

  lemma->name = strdup(name);
  if (lemma->arg) strchr(lemma->name, ' ')[0] = '\0';
  lemma->concl = concl;
  lemma->numprems = nprems;
  lemma->prems = prems;
  lemma->pf = NULL;

  return 0;
}
#endif

#ifndef nop__NEXUSKERNEL__
struct _Lemma *guard_rule_introduce_a(Guard *g, char *name, char *conclstr, char **premises) {
  struct _Lemma *rule = nxcompat_alloc(sizeof(struct _Lemma));

  int err = parse_lemma_a(g, rule, name, conclstr, premises);
  if (err) {
    nxcompat_free(rule);
    return NULL;
  }

  eval_rule_introduce(&g->eval, rule);

  if (g->flags & GUARD_DEBUG_POLICY) 
    guard_lemma_print(rule);

  return rule;
}
#endif

#ifndef nop__NEXUSKERNEL__
struct _Lemma *guard_rule_introduce(Guard *g, char *name, char *conclstr, ...) {
  va_list args;
  struct _Lemma *rule = nxcompat_alloc(sizeof(struct _Lemma));

  va_start(args, conclstr);
  int err = parse_lemma(g, rule, name, conclstr, args);
  va_end(args);
  if (err) {
    nxcompat_free(rule);
    return NULL;
  }

  eval_rule_introduce(&g->eval, rule);

  if (g->flags & GUARD_DEBUG_POLICY) 
    guard_lemma_print(rule);

  return rule;
}
#endif

void guard_lemma_free(struct _Lemma *lemma) {
  int i;
  for (i = 0; i < lemma->numprems; i++)
    form_free(lemma->prems[i]);
  nxcompat_free(lemma->prems);
  if (lemma->pf)
    nxcompat_free(lemma->pf);
  nxcompat_free(lemma);
}

#ifndef nop__NEXUSKERNEL__
struct _Lemma *guard_lemma_introduce_a(Guard *g, char *name, char *conclstr, char *pf, char **premises) {
  struct _Lemma *lemma = nxcompat_alloc(sizeof(struct _Lemma));

  int err = parse_lemma_a(g, lemma, name, conclstr, premises);
  if (err) {
    nxcompat_free(lemma);
    return NULL;
  }
  lemma->pf = strdup(pf);

  if (guard_check_lemma(g, lemma)) {
    guard_lemma_free(lemma);
    return NULL;
  }

  eval_rule_introduce(&g->eval, lemma);

  if (g->flags & GUARD_DEBUG_POLICY) 
    guard_lemma_print(lemma);

  return lemma;
}
#endif

#ifndef nop__NEXUSKERNEL__
struct _Lemma *guard_lemma_introduce(Guard *g, char *name, char *conclstr, char *pf, ...) {
  va_list args;
  struct _Lemma *lemma = nxcompat_alloc(sizeof(struct _Lemma));

  va_start(args, pf);
  int err = parse_lemma(g, lemma, name, conclstr, args);
  va_end(args);
  if (err) {
    nxcompat_free(lemma);
    return NULL;
  }
  lemma->pf = strdup(pf);

  if (guard_check_lemma(g, lemma)) {
    guard_lemma_free(lemma);
    return NULL;
  }

  eval_rule_introduce(&g->eval, lemma);

  if (g->flags & GUARD_DEBUG_POLICY) 
    guard_lemma_print(lemma);

  return lemma;
}
#endif

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
  "sfor %F", "(%a says %F) imp (%b says %F)", "%a speaksfor %b", 0,
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
  "eq_swap", "%x = %y",
      "given %y = %x; "
      "eqi %x; "
      "efe %x = %y; ",
      "%y = %x", 0,

  "not-not", "not not %S",
      "given %S; "
      "assume not %S; "
      "defe_not; " // %S imp false
      "impe; " // false
      "impi not %S; " // not %S imp false
      "defi_not; ", // not not %S
      "%S", 0,

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

  "ori_l %G", "%F or %G",
      "given %F; "
      "assume %F imp %G; "
      "impe; "
      "impi %F imp %G; "
      "defi_or; ", 
      "%F", 0,

  "ori_r %F", "%F or %G",
      "given %G; "
      "impi %F imp %G; "
      "defi_or; ",
      "%G", 0,

  "iffe_r", "%F",
      "given %G; "
      "given %F iff %G; "
      "defe_iff; "
      "ande_r; "
      "impe; ",
      "%G", "%F iff %G", 0,

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
      "impe; ",
      "(%x in %s1) or (%x in %s2)", 0,

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

  0
};


void guard_add_std_rules(struct guard *g) {
#ifdef nop__NEXUSKERNEL__
  return;
#else
  struct _Lemma *lemma, *rule;
  char **p;

  // XXX check this combination for/while loop. it seems unnecessarily complex
  for (p = nal_stdrules; *p != 0; p++) {
    rule = guard_rule_introduce_a(g, p[0], p[1], &p[2]);
    assert(rule);
    while (*p) p++;
  }

  for (p = nal_stdlemmas; *p != 0; p++) {
    lemma = guard_lemma_introduce_a(g, p[0], p[1], p[2], &p[3]);
    assert(lemma);
    while (*p) p++;
  }

#endif // nop__NEXUSKERNEL__
}

_Policy *policy_all(void) {
  char der[] = { 
      0x30,  15,
	0x13, 7, 'f', 'o', 'r', 'm', 'u', 'l', 'a',
	0x13, 4, 't', 'r', 'u', 'e' };
  _Policy *p = nxcompat_alloc(sizeof(der));
  memcpy(p, der, sizeof(der));
  return p;
}

_Policy *policy_none(void) {
  char der[] = {
      0x30,  16,
	0x13, 7, 'f', 'o', 'r', 'm', 'u', 'l', 'a',
	0x13, 5, 'f', 'a', 'l', 's', 'e' };
  _Policy *p = nxcompat_alloc(sizeof(der));
  memcpy(p, der, sizeof(der));
  return p;
}

#undef dbgprintf
#undef print_please
#undef PRETTY
