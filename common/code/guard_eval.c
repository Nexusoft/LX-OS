
// eval_run() takes the "hintcode" embeded in a Grounds, and rebuilds the
// evaluation tree from it, typechecking the tree as it goes (i.e. structural
// integrity).
//
// The result is zero or more elements left on the stack.
//
// It is up to the caller (e.g. guard.c) to check that the stack contains
// exactly one element, that this one element matches the policy goal formula,
// and that all of the assumptions of the final element are simultaneously true.


#define PRETTY(f, cols) form_to_pretty(form_repl_all(f, eval->param_vals, eval->param_names), cols)

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

#define dbgprintf(...) do { \
	if (eval->flags & GUARD_DEBUG_HINTCODE) printf("guard: eval: " __VA_ARGS__); } while (0)


static void eval_init(struct eval *eval) {
	memset(eval, 0, sizeof(struct eval));
	PointerVector_init(&eval->stack, 16, POINTERVECTOR_ORDER_PRESERVING);
	PointerVector_init(&eval->recentstack, 16, POINTERVECTOR_ORDER_PRESERVING);
	eval->rules = hash_new_vlen(16, hash_strlen);
	PointerVector_init(&eval->rules_sorted, 16, POINTERVECTOR_ORDER_PRESERVING);
}

static void eval_rule_introduce(struct eval *eval, struct _Lemma *rule) {
  hash_insert(eval->rules, rule->name, rule);
  PointerVector_append(&eval->rules_sorted, rule->name);
}

static char *skipws(char *s) { while (s && isspace(*s)) s++; return s; }
static char *rtrim(char *s) { while (s && isspace(*s)) s--; return s; }

#ifdef __NEXUSKERNEL__
// kwalsh: why the different names?
#define strtoul simple_strtoul
#endif

static int hc_match(char *s, int n, struct hc *hc, PointerVector *args, struct HashTable *rules) {
	int ac = -1, opsize = -1, fromargs = 0;

	memset(hc, 0, sizeof(struct hc));
	if (!s || !*s)
		return 0;

	n = (rtrim(s + n) - s);

#define HC_MATCH(op, str, k, ss) \
	if (n >= strlen(str) + 2*k && !strncmp(str, s, strlen(str))) { \
	      hc->tag = op; ac = k; hc->nstackargs = ss; opsize = strlen(str); \
	if (opsize > 1 && s[opsize] == '*') {				\
	  opsize++;							\
	  fromargs = 1;							\
	}								\
}

	HC_MATCH(HC_PUSHDOWN, "pushdown", 1, 2)
	else HC_MATCH(HC_PULLUP, "pullup", 1, 2)
	else HC_MATCH(HC_ASSUME, "assume", 1, 0)
	else HC_MATCH(HC_ASSUME, "given", 1, 0)
	else HC_MATCH(HC_EFE, "efe", 0 /*1 arg optional*/, 2)
	else HC_MATCH(HC_IMPI, "impi", 1, 1)
	else HC_MATCH(HC_DUP, "dup", 0, 1)
	else HC_MATCH(HC_POP, "pop", 0, 1)
	else HC_MATCH(HC_RENAME, "rename", 1, 1)
	else HC_MATCH(HC_CONST, "const", 1, 0)
	else HC_MATCH(HC_EXTERN, "extern set-theory", 1, 0)
	else HC_MATCH(HC_FORALLI, "foralli", 1, 1)
	else HC_MATCH(HC_FORALLE, "foralle", 1, 1)
	else HC_MATCH(HC_SAYSFORALL, "says-forall", 0, 1)
	else HC_MATCH(HC_FORALLSAYS, "forall-says", 0, 1)
	else HC_MATCH(HC_EXISTSI, "existsi", 1, 1)
	else HC_MATCH(HC_GROUPI, "groupi", 1, 2)
#undef HC_MATCH
	else {
	
	  // create private copy of hintcode statement	
	  char *op = nxcompat_alloc(n+1);
	  memcpy(op, s, n);
	  op[n] = '\0';

	  // look for optional argument beyond first token
	  char *p = op + 1;
	  while (*p && !isspace(*p))
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
	  nxcompat_free(op);
	  if (!rule) {
	    nxcompat_printf("[warning]: no rule [%s]\n", op);
	    return -1;
	  }

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

	char *p = s + opsize;
	char *end;

	// move to start of argument
	assert(ac == 1);
	if ((p == s + n) || !isspace(*p++)) 
		return -2;
	while (isspace(*p)) 
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
	    nxcompat_printf("arguments missing\n");
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
	  else
	    hc->argf = form_from_pretty(fstr);
	  nxcompat_free(fstr);
	  if (!hc->argf) return -5;
	}
	return 0;
}

static Judge *pop(struct eval *eval) {
	int n = PointerVector_len(&eval->stack);
	if (n <= 0) {
	  dbgprintf("error: pop from empty stack\n");
	  return NULL;
	}
	Judge *f = PointerVector_deleteAt(&eval->stack, n-1);
	PointerVector_append(&eval->recentstack, f);
	return f;
}

static Judge *peek(struct eval *eval) {
	int n = PointerVector_len(&eval->stack);
	if (n <= 0) {
	  dbgprintf("error: peek into empty stack\n");
	  return NULL;
	}
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

static void dump_eval_stack(struct eval *eval);

static void kill(struct eval *eval) {
  done(eval, 1);
  dump_eval_stack(eval);
  dbgprintf("(%d errors so far)\n", eval->errors + 1);
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

static void kill_map_entry(void *item, void *arg) {
  form_free((Form *)item);
}

static void print_map_entry(void *entry, void *arg) {
  /* char *paramname = hash_entryToKey(entry);
  Form *paramval = hash_entryToItem(entry);
  form_printf(" subst %s as %s\n", paramname, form_s(paramval)); */
}

static int apply_rule(struct eval  *eval, struct _Lemma *rule, Form *arg) {
  // match the first n stack args to n premises
  int i;
  struct HashTable *reps = hash_new_vlen(16, hash_strlen);
  if (rule->arg && form_unify_params(arg, rule->arg, reps)) {
    dbgprintf("can't unify argument\n");
      char *s;
      s = PRETTY(rule->arg, 0);
      dbgprintf(" argument is %s\n", s);
      nxcompat_free(s);
      s = PRETTY(arg, 0);
      dbgprintf(" passed value is %s\n", s);
      nxcompat_free(s);
      hash_iterate(reps, &kill_map_entry, NULL);
      hash_destroy(reps);
      kill(eval);
      return -1;
  }
  for (i = rule->numprems-1; i >= 0; i--) {
    Judge *g = pop(eval);
    if (form_unify_params(g->concl, rule->prems[i], reps)) {
      dbgprintf("can't unify premise %d\n", i);
      char *s;
      s = PRETTY(rule->prems[i], 0);
      dbgprintf(" premise is %s\n", s);
      nxcompat_free(s);
      s = PRETTY(g->concl, 0);
      dbgprintf(" target is %s\n", s);
      nxcompat_free(s);

      if (eval->flags & GUARD_DEBUG_HINTCODE) 
	hash_iterateEntries(reps, &print_map_entry, NULL);
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
    dbgprintf("can't substitute into rule conclusion\n");
    kill(eval);
    return -1;
  }

  push(eval, judge_new(eval, concl));
  return 0;
}

#define FAIL(ret) unify_result("alpha-equiv", __LINE__, f, g, NULL)

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
  if (f->tag != g->tag) return FAIL(-1);
  if (!f->left != !g->left) return FAIL(-1);
  if (!f->mid != !g->mid) return FAIL(-1);
  if (!f->right != !g->right) return FAIL(-1);
  if (!f->data != !g->data) return FAIL(-1);

  if (f->tag == F_TERM_QVAR) {
    assert(f->data && g->data);
    int m_f = (int)hash_findItem(fm, f->data);
    int m_g = (int)hash_findItem(gm, g->data);
    if (m_f != m_g)
      return FAIL(-1);
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
      return FAIL(-1);
    hash_delete(fm, f_qvar->data); // restores previous value, if any
    hash_delete(gm, g_qvar->data); // restores previous value, if any
    return 0;
  } else {
    switch (f->tag & F_ARITY_MASK) {
      case F_IS_TERNARY:
	if (f->mid && find_alpha_equiv(f->mid, g->mid, fm, gm, depth, nfv)) return FAIL(-1);
	// fall through
      case F_IS_BINARY:
	if (f->right && find_alpha_equiv(f->right, g->right, fm, gm, depth, nfv)) return FAIL(-1);
	// fall through
      case F_IS_UNARY:
	if (f->left && find_alpha_equiv(f->left, g->left, fm, gm, depth, nfv)) return FAIL(-1);
	// fall through
      case F_IS_EMPTY:
	return 0;
      default:
	return (form_cmp(f, g) ? FAIL(-1) : 0);
    }
  }
}

#undef FAIL

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
  Judge *f = pop(eval);

  struct HashTable *fm = hash_new_vlen(16, hash_strlen);
  struct HashTable *gm = hash_new_vlen(16, hash_strlen);
  // note: the proposed form (h) must go first in this expression.
  int err = find_alpha_equiv(h, f->concl, fm, gm, 0, 0);
  hash_destroy(fm);
  hash_destroy(gm);
  if (err) {
      char *s = PRETTY(f->concl, 80);
      char *s2 = PRETTY(h, 80);
      dbgprintf("suggested renaming is not alpha-equivalent\n");
      dbgprintf("  original: %s\n", s);
      dbgprintf("  renaming: %s\n", s2);
      nxcompat_free(s);
      nxcompat_free(s2);
      form_free(h);
      kill(eval);
      return -1;
  }

  push(eval, judge_new(eval, h));
  return 0;
}

#define FAIL(msg...) do { printf(msg); \
  char *s = form_to_pretty(f, 80); printf(" f = %s\n", s); \
  char *m = form_to_pretty(g, 80); printf(" g = %s\n", m); \
  nxcompat_free(s); nxcompat_free(m); return -1; } while (0)

int find_qvar_subst(Form *f, Form *g, char *qname, Form **repl, HashTable **replfv) {
  // check for replacement
  if (f->tag == F_TERM_QVAR && !strcmp(f->data, qname)) {
    if (!*repl) {
      *repl = g;
      *replfv = form_free_qvars(g);
    }
    else if (form_cmp(g, *repl))
	FAIL("no such substitution\n");
    return 0;
  }
  // check for same structure
  if (f->tag != g->tag) FAIL("tag mismatch\n");
  if (!f->left != !g->left) FAIL("bad structure\n");
  if (!f->mid != !g->mid) FAIL("bad structure\n");
  if (!f->right != !g->right) FAIL("bad structure\n");
  if (!f->data != !g->data) FAIL("bad structure\n");

  // two special cases:
  // f == (forall $x : S) -- normal case, but then check $x not in fv of repl
  // f == (forall $q : S) -- do direct comparison, b/c $q is shadowed

  if (f->tag == F_STMT_FORALL || f->tag  == F_STMT_EXISTS) {
    Form *f_qvar = f->left;
    assert(f_qvar && f_qvar->data && f_qvar->tag == F_TERM_QVAR);
    if (!strcmp(f_qvar->data, qname)) {
      if (form_cmp(f, g)) FAIL("different structure\n");
      else return 0;
    }
  }

  switch (f->tag & F_ARITY_MASK) {
    case F_IS_TERNARY:
      if (f->mid && find_qvar_subst(f->mid, g->mid, qname, repl, replfv)) FAIL("mismatch\n");
      // fall through
    case F_IS_BINARY:
      if (f->right && find_qvar_subst(f->right, g->right, qname, repl, replfv)) FAIL("mismatch\n");
      // fall through
    case F_IS_UNARY:
      if (f->left && find_qvar_subst(f->left, g->left, qname, repl, replfv)) FAIL("mismatch\n");
      // fall through
    case F_IS_EMPTY:
      break;
    default:
      if (form_cmp(f, g)) FAIL("mismatch\n");
      else return 0;
  }

  if (*repl && (f->tag == F_STMT_FORALL || f->tag  == F_STMT_EXISTS)) {
    Form *f_qvar = f->left;
    if (strcmp(f_qvar->data, qname)) {
      if (hash_findItem(*replfv, f_qvar->data)) FAIL("capture error\n");
    }
  }

  return 0;
}

#undef FAIL

// check if there is a term t such that f[qname/t] = g
int check_legal_existsi(char *qname, Form *f, Form *g) {
  // traverse f and g
  // figure out replacement t
  // ensure same structure other than replacing qname in f with t
  // ensure free vars in t don't get captured in g

  HashTable *replfv = NULL;
  Form *repl = NULL;
  int err = find_qvar_subst(f, g, qname, &repl, &replfv);

  if (repl) {
    //char *s = form_to_pretty(repl, 80);
    // printf("replacement was %s\n", s);
    //nxcompat_free(s);
  } else {
    //printf("replacement was any\n");
  }

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

Form *extern_eval(char *cmd, int cmdlen, Form *f) {
  // ideally, this would invoke various external provers. For now we will make do with
  // this one very weak stub prover.
  int n = strlen("extern");
  if (cmdlen < n) return NULL;
  cmdlen -= n;
  cmd += n;
  while (cmdlen > 0 && isspace(*cmd)) { cmdlen--; cmd++; }
  n = strlen("set-theory");
  if (cmdlen >= n && !strncmp(cmd, "set-theory", n) && isspace(cmd[n])) {
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

#define FAIL(msg...) do { printf(msg); kill(eval); return -1*__LINE__; } while (0);

int eval_run1(struct eval *eval, char *code, int codelen, PointerVector *args) {
	Judge *f, *g;
	Form *h;
	struct hc hc;
	int rc;

	eval->code = code;
	if ((rc = hc_match(code, codelen, &hc, args, eval->rules))) {
		dbgprintf("invalid hintcode: %.*s\n", codelen, code);
		switch (rc) {
		  case -1: FAIL("  (hint not recognized)\n");
		  case -2: FAIL("  (missing required space)\n");
		  case -3: FAIL("  (missing argument)\n");
		  case -4: FAIL("  (garbage at end / extra arguments)\n");
		  case -5: FAIL("  (malformed / illegal argument)\n");
		  default: return -101;
		}
	}
	if (hc.argf)
	  form_replace_all(hc.argf, eval->params);

	if (hc.nstackargs > PointerVector_len(&eval->stack))
		FAIL("too few stack operands for hintcode: %.*s\n", codelen, code);
	switch (hc.tag) {
		case HC_RULE: // stack , a1->p1 , ... , aN->pN :: stack , a1U...UaN->c
			if (apply_rule(eval, hc.rule, hc.argf)) return -102;
			break;
		case HC_PUSHDOWN: // stack , stack(n), a->F :: stack , a->F , stack(n)
			if (hc.argi <= 0)
			  FAIL("pushdown <n> expects at n > 0\n");
			if (hc.argi >= PointerVector_len(&eval->stack))
			  FAIL("pushdown <n> expects at least n+1 elements on the stack\n");
			f = pop(eval);
			PointerVector_truncate(&eval->recentstack);
			slipin(eval, f, hc.argi);
			break;
		case HC_PULLUP: // stack , a->F, stack(n) :: stack , stack(n), a->F
			if (hc.argi <= 0)
			  FAIL("pushdown <n> expects at n > 0\n");
			if (hc.argi >= PointerVector_len(&eval->stack))
			  FAIL("pullup <n> expects at least n+1 elements on the stack\n");
			f = slipout(eval, hc.argi);
			PointerVector_truncate(&eval->recentstack);
			push(eval, f);
			break;
		case HC_EFE: // arg=P says f(F); stack , a->P says F=G , b->P says f(G) :: stack , aUb->P says f(F)
		/* alt  */   // arg=f(F); stack , a->F=G , b->f(G) :: stack , aUb->f(F)
		/* alt2 */   // stack , a->P says F=G , b->P says H :: stack , aUb->P says H[F/G]
		/* alt3 */   // stack , a->F=G , b->H :: stack , aUb->H[F/G]
			h = hc.argf; // special case: may be null
			g = pop(eval);
			f = pop(eval);
			if (f->concl->tag == F_STMT_SAYS) {
			  if (g->concl->tag != F_STMT_SAYS || (h && h->tag != F_STMT_SAYS)
			      || form_cmp(f->concl->left, g->concl->left)
			      || (h && form_cmp(f->concl->left, h->left))
			      || f->concl->right->tag != F_PRED_EQ)
			    FAIL("efe (for principals) expects two elements on stack, of form \"P says t2=t1\" and \"P says F(t1)\"\n"
				"and optionally an argument of form \"P says F(t2)\"\n");
			  if (!hc.argf)
			    h = form_new(F_STMT_SAYS, form_dup(f->concl->left), 0,
				form_repl(g->concl->right, f->concl->right->right, f->concl->right->left));
			  if (form_cmp_replace(g->concl->right, h->right,
				f->concl->right->right, f->concl->right->left)) {
			    form_free(h);
			    FAIL("not a valid equals-for-equals result\n");
			  }
			} else {
			  if (f->concl->tag != F_PRED_EQ)
			    FAIL("efe (for statements) expects two elements on stack, of form \"t2=t1\" and \"F(t1)\"\n"
				"and optionally an argument of form \"F(t2)\"\n");
			  if (!hc.argf)
			    h = form_repl(g->concl, f->concl->right, f->concl->left);
			  if (form_cmp_replace(g->concl, h,
				f->concl->right, f->concl->left)) {
			    form_free(h);
			    FAIL("not a valid equals-for-equals result\n");
			  }
			}
			push(eval, judge_new(eval, h));
			break;
		case HC_IMPI: // arg=G; stack ,  [a,G]->F :: stack , a->G imp F
			h = hc.argf;
			f = pop(eval);
			g = judge_new(eval, form_new(F_STMT_IMP, h, 0, f->concl));
			judge_del(g, h);
			push(eval, g);
			break;
		case HC_DUP: // stack ,  a->F :: stack , a->F , a->F
			f = peek(eval);
			g = judge_dup(f);
			push(eval, g);
			break;
		case HC_POP: // stack ,  a->F :: stack 
			f = pop(eval);
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
			  FAIL("could not evaluate to a constant\n");
			f = judge_new(eval, h);
			push(eval, f);
			break;
		case HC_EXTERN: // arg=G; stack :: stack , []->F (where external proof checker returns F on input G)
			h = extern_eval(code, codelen, hc.argf);
			if (!h)
			  FAIL("could not evaluate external proof\n");
			f = judge_new(eval, h);
			push(eval, f);
			break;
		case HC_FORALLI: // arg=v; stack , a->F :: stack , a->forall v : F
			h = hc.argf;
			if (h->tag != F_TERM_QVAR)
			  FAIL("foralli requires a quantified var\n");
			f = pop(eval);
			g = judge_new(eval, form_new(F_STMT_FORALL, h, 0, f->concl));
			push(eval, g);
			break;
		case HC_FORALLE: // arg=t; stack , a->forall $v : F :: stack , a->F[$v/t]
			/* todo: forbid if F has params except when t is dummy $v */
			if (!F_ISTERM(hc.argf->tag))
			  FAIL("foralle requires a term\n");
			f = pop(eval);
			h = f->concl;
			if (h->tag != F_STMT_FORALL)
			  FAIL("foralle expects one element on stack, of form \"forall $v : F\"\n");
			assert(h->left && h->left->tag == F_TERM_QVAR);
			h = form_dup(h->right);
			if (form_replace_qvar(h, f->concl->left->data, hc.argf) < 0)
			  FAIL("replacement capture error\n");
			g = judge_new(eval, h);
			push(eval, g);
			break;
		case HC_SAYSFORALL: // stack , a->P says forall $v : F , closed(P) :: stack , a->forall $v : P says F
			g = pop(eval);
			f = pop(eval);
			if (g->concl->tag != F_PRED_CLOSED || // closed(P)
			    f->concl->tag != F_STMT_SAYS || //  P' says ...
			    form_cmp(f->concl->left, g->concl->left) || // P = P'
			    f->concl->right->tag != F_STMT_FORALL || // says forall ...
			    f->concl->right->left->tag != F_TERM_QVAR) // forall $v : ...
			  FAIL("saysforall expects two elements on stack, of form \"closed(P)\" and \"P says forall $v : F\"\n");
			// check for variable capture: P must not have $v free
			if (appears_free_in(f->concl->right->left, g->concl->left))
			  FAIL("variable capture error\n");
			f = judge_new(eval, form_dup(f->concl));
			h = f->concl;
			f->concl = h->right;
			h->right = f->concl->right;
			f->concl->right = h;
			push(eval, f);
			break;
		case HC_FORALLSAYS: // stack , a->forall $v : P says F , closed(P) :: stack , a->P says forall $v : F
			g = pop(eval);
			f = pop(eval);
			if (g->concl->tag != F_PRED_CLOSED || // closed(P)
			    f->concl->tag != F_STMT_FORALL || //  forall ...
			    f->concl->left->tag != F_TERM_QVAR || // forall $v : ...
			    f->concl->right->tag != F_STMT_SAYS || //  forall $v : P' says ...
			    form_cmp(f->concl->right->left, g->concl->left)) // P = P'
			  FAIL("saysforall expects two elements on stack, of form \"closed(P)\" and \"P says forall $v : F\"\n");
			// check for variable capture: P must not have $v free
			if (appears_free_in(f->concl->left, g->concl->left))
			  FAIL("variable capture error\n");
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
			  FAIL("existsi requires a statement, of form \"exists $v : F\"\n");
			f = pop(eval);
			if (check_legal_existsi(h->left->data, h->right, f->concl))
			  FAIL("illegal existential abstraction\n");
			g = judge_new(eval, h);
			push(eval, g);
			break;
		case HC_GROUPI: // arg=[[ $v : G ]]; stack , a->P says F , b->G[$v/P] :: stack , aUb->[[ $v : G ]] says F
				  // arg=[( $v : G )]; stack , a->P says F , b->G[$v/P] :: stack , aUb->[( $v : G )] says F
			if (hc.argf->tag != F_TERM_CIGRP && hc.argf->tag != F_TERM_DIGRP)
			  FAIL("groupi requires a term, of form \"[[ $v : G ]]\" or \"[( $v : G )]\"\n");
			g = pop(eval);
			f = pop(eval);
			if (f->concl->tag != F_STMT_SAYS)
			  FAIL("groupi requires two elements on stack, of form \"P says F\" and \"G[$v/P]\"\n");
			h = form_dup(hc.argf->right);
			if (form_replace_qvar(h, hc.argf->left->data, f->concl->left) < 0) {
			  form_free(h);
			  FAIL("replacement capture error\n");
			}
			if (form_cmp(h, g->concl)) {
			  form_free(h);
			  FAIL("groupi can't unify second premise\n");
			}
			form_free(h);
			f = judge_new(eval, form_dup(f->concl));
			form_free(f->concl->left);
			f->concl->left = form_dup(hc.argf);
			push(eval, f);
			break;
		case HC_ASSUME: // arg=G; stack :: stack , [G]->G
			h = hc.argf;
			f = judge_new(eval, h);
			judge_add(f, h);
			push(eval, f);
			break;
		default:
			assert(0);
	}

	if (eval->flags & GUARD_DEBUG_HINTCODE) {
	  if (PointerVector_len(&eval->stack) > 0) {
	    f = peek(eval);
	    char *s = PRETTY(f->concl, 80);
	    printf("[%d] -> %s\n", PointerVector_len(&f->hyp), s);
	    nxcompat_free(s);
	  } else {
	    printf("(empty stack)\n");
	  }
	}

	return 0;
}
#undef FAIL

int eval_run(struct eval *eval, char *code, PointerVector *args) {
	int err;

	eval_clear(eval);

	if (!code) {
		nxcompat_fprintf(stderr, "cannot evaluate empty proof\n");
		return -1;
	}

	char *nextcode = skipws(code);
	while (nextcode && *nextcode) {
		eval->code = code = nextcode;
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
			nxcompat_printf("NXDEBUG: evaluation failed\n");
			eval->errors++;
			return err;
		}

		nextcode = skipws(nextcode+1);
	}
	return 0;
}

static void dump_eval_stack(struct eval *eval) {
	int i, n = PointerVector_len(&eval->stack);
	printf("  stack: (%d formulas)\n", n);
	//for (i = n-1; i >= 0; i--)
	for (i = 0; i < n; i++) {
		Judge *f = PointerVector_nth(&eval->stack, i);
		assert(f && f->concl);
		char *s = PRETTY(f->concl, 0);
		printf("   %3d: [%d] -> %s\n", i, PointerVector_len(&f->hyp), s);
		nxcompat_free(s);
	}
}

void eval_dump(struct eval *eval) {
	printf("guard evaluator state:\n");
	dump_eval_stack(eval);
	printf("  code: %s\n", eval->code);
	printf("  errors: %d so far\n", eval->errors);
}

void eval_clear(struct eval *eval) {
	while (PointerVector_len(&eval->stack)) {
	    judge_free(pop(eval));
	}
	eval->code = NULL;
}

void eval_destroy(struct eval *eval) {
	eval_clear(eval);
	PointerVector_dealloc(&eval->stack);
	memset(eval, 0, sizeof(eval));
	// todo: free rules
	hash_destroy(eval->rules);
}

#undef dbgprintf
#undef PRETTY
