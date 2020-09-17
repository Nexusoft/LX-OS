/** NexusOS: proof ('judgement') handling */

/** Find a hypothesis.
    @return its index or -1 if not found */
static int 
judge_find(Judge *f, Form *h)
{
  int i, n;
  
  n= PointerVector_len(&f->hyp);
  for (i = 0; i < n; i++) {
    Form *h2 = PointerVector_nth(&f->hyp, i);
    if (!form_cmp(h, h2))
      return i;
  }

  return -1;
}

/** Add a hypothesis (duplicates are detected) */
void judge_add(Judge *f, Form *h) {
  Form *h2;

  if (judge_find(f, h) >= 0)
	  return;

  h2 = form_dup(h);
  if (!h2)
	return;
  PointerVector_append(&f->hyp, h2);
}

/** Remove a hypothesis */
void 
judge_del(Judge *f, Form *h) 
{
  Form *h2;
  int i;

  i = judge_find(f, h);
  if (i >= 0) {
    h2 = PointerVector_nth(&f->hyp, i);
    PointerVector_deleteAt(&f->hyp, i);
    form_free(h2);
  }
}

/** Free a judge and all its structures */
void 
judge_free(Judge *f) 
{
  int i, n;
 
  // free hypotheses
  n = PointerVector_len(&f->hyp);
  for (; n; n--)
    form_free(PointerVector_deleteAt(&f->hyp, n - 1));
  assert(PointerVector_len(&f->hyp) == 0);
  PointerVector_dealloc(&f->hyp);

  // free antecedents
  for (i = 0; i < f->arity; i++) {
    if (!--f->ant[i]->refcnt)
    	judge_free(f->ant[i]);
  }

  if (f->concl)
    form_free(f->concl);
  if (f->rule)
    nxcompat_free(f->rule);
  nxcompat_free(f);
}

/** Create a new proof structure */
Judge *
judge_new(struct eval *eval, Form *concl) 
{
  int i, j, n, m, size;
  Judge *f;

  n = PointerVector_len(&eval->recentstack);
  size = sizeof(Judge) + (n * sizeof(void *));

  f = nxcompat_calloc(1, size);
  f->concl = concl;
  f->arity = n;
  f->rule = strdup(eval->code);

  // link to deduction rule antecedents
  PointerVector_init(&f->hyp, 2, 0);
  for (i = 0; i < n; i++) {

    // link to antecedent
    Judge *g = PointerVector_nth(&eval->recentstack, i);
    f->ant[i] = g;
    g->refcnt++;
    
    // copy all hypotheses of antecedent to hypothesis list of conclusion
    m = PointerVector_len(&g->hyp);
    for (j = 0; j < m; j++) {
      Form *h; 
      
      h = PointerVector_nth(&g->hyp, j);
      assert(h);
      judge_add(f, /* form_dup(h) */ h);
    }
  }
  PointerVector_truncate(&eval->recentstack);

  return f;
}

Judge *judge_dup(Judge *g) {
  int i, n = g->arity;
  int size = sizeof(Judge) + n * sizeof(Judge *);
  Judge *f = nxcompat_calloc(1, size);
  f->concl = form_dup(g->concl);
  PointerVector_init(&f->hyp, 2, 0);
  f->arity = n;
  f->rule = strdup(g->rule);

  // dup antecedents from g
  for (i = 0; i < n; i++) {
    f->ant[i] = judge_dup(g->ant[i]);
  }
  // dup hypotheses from g
  int j, m = PointerVector_len(&g->hyp);
  for (j = 0; j < m; j++) {
    Form *h = PointerVector_nth(&g->hyp, j);
    PointerVector_append(&f->hyp, form_dup(h));
  }
  return f;
}

// compare only conclusions & hypotheses, ignore differences in derivation
int judge_cmp(Judge *f, Judge *g) {
  int i, j, n = PointerVector_len(&f->hyp);
  if (n != PointerVector_len(&g->hyp)) return -1;
  if (form_cmp(f->concl, g->concl)) return -1;
  for (i = 0; i < n; i++) {
    Form *h = PointerVector_nth(&f->hyp, i);
    for (j = 0; j < n; j++) {
      Form *h2 = PointerVector_nth(&g->hyp, j);
      if (!form_cmp(h, h2)) break;
    }
    if (j == n) return -1;
  }
  return 0;
}

////////  pretty print proofs  ////////

int judge_print_graphviz0(FILE *out, Judge *f, int *num_nodes, 
			  PointerVector *givens, 
			  PointerVector *assumptions, 
			  PointerVector *conclusions) 
{

  if (conclusions) {
    int i, n = PointerVector_len(conclusions);
    for (i = 0; i < n; i++) {
      Judge *g = PointerVector_nth(conclusions, i);
      if (!judge_cmp(f, g)) {
	// were duplicates
	return i+1;
      }
    }
    PointerVector_append(conclusions, f);
  }

  int node_id = ++(*num_nodes);

  char *rule = strdup(f->rule);
  char *e = rule;
  while (*e && !isspace(*e) && *e != ';') e++;
  *e = '\0';
  char *s = form_to_pretty(f->concl, -80); // abbreviation for now
  int len = form_qstr_escape(NULL, 0, s, -1) + 1;
  char *text = nxcompat_alloc(len);
  form_qstr_escape(text, len, s, -1);
  fprintf(out, "\tj%d [label=\"%s\\l\" shape=rect];\n", node_id, text);
  if (!strcmp(rule, "impi")) {
    assert(f->concl->tag == F_STMT_IMP);
    int k = PointerVector_len(assumptions);
    PointerVector_append(assumptions, f->concl->left);
    fprintf(out, "\tr%d [label=\"impi A%d\" style=filled];\n", node_id, k);
  } else if (!strcmp(rule, "assume")) {
    int j, k = PointerVector_len(assumptions);
    for (j = 0; j < k; j++) {
      Form *h = PointerVector_nth(assumptions, j);
      if (!form_cmp(h, f->concl))
	break;
    }
    if (j >= k) 
      fprintf(out, "\tr%d [label=\"assumption A?\" style=filled];\n", node_id);
    else 
      fprintf(out, "\tr%d [label=\"assumption A%d\" style=filled];\n", node_id, j);
  } else if (!strcmp(rule, "given")) {
    int j, k = PointerVector_len(givens);
    for (j = 0; j < k; j++) {
      Form *h = PointerVector_nth(givens, j);
      if (!form_cmp(h, f->concl))
	break;
    }
    if (j == k)
      PointerVector_append(givens, f->concl);
    fprintf(out, "\tr%d [label=\"given G%d\" style=filled shape=octagon];\n", node_id, j);
  } else {
    fprintf(out, "\tr%d [label=\"%s\"];\n", node_id, rule);
  }
  //fprintf(out, "\tr%d -> j%d [arrowhead=none weight=10]\n", node_id, node_id);
  fprintf(out, "\tj%d -> r%d [arrowtail=none weight=10]\n", node_id, node_id);
  nxcompat_free(rule);
  nxcompat_free(s);
  nxcompat_free(text);

  int i, n = f->arity;
  for (i = 0; i < n; i++) {
    int child_id = judge_print_graphviz0(out, f->ant[i], num_nodes, givens, assumptions, conclusions);
    //fprintf(out, "\tj%d -> r%d;\n", child_id, node_id);
    fprintf(out, "\tr%d -> j%d;\n", node_id, child_id);
  }

  return node_id;
}

//#define DOT_ELIMINATE_DUPS

void judge_print_graphviz(FILE *out, Judge *f, char *name) {
  PointerVector givens, assumptions;
  PointerVector_init(&givens, 16, POINTERVECTOR_ORDER_PRESERVING);
  PointerVector_init(&assumptions, 16, POINTERVECTOR_ORDER_PRESERVING);
#ifdef DOT_ELIMINATE_DUPS
  PointerVector concls;
  PointerVector_init(&concls, 16, POINTERVECTOR_ORDER_PRESERVING);
  PointerVector *conclusions = &concls;
#else
  PointerVector *conclusions = NULL;
#endif
  fprintf(out, "digraph \"%s\" {\n"
      "\tlabel=\"%s\";\n"
      "\tlabelloc=t;\n"
      "\tnodesep=0.15;\n"
      "\tminlen=0.2;\n"
      "\tranksep=0.2;\n"
      "\tnode [shape=oval];\n"
      "\tedge [arrowhead=none arrowtail=vee];\n",
      name, name);
  int num_nodes = 0;
  judge_print_graphviz0(out, f, &num_nodes, &givens, &assumptions, conclusions);
  fprintf(out, "}\n");
  PointerVector_dealloc(&givens);
  PointerVector_dealloc(&assumptions);
#ifdef DOT_ELIMINATE_DUPS
  PointerVector_dealloc(&concls);
#endif
}

#define DEST (buf+written), (len <= written ? 0 : len - written)

int form_escape_html(char *buf, int len, char *str)
{
  int written = 0;
  for (; *str; str++) {
    if (*str <= 0x1f || *str == 0x7f || *str & 0x80) {
      if (*str == '\n') written += snprintf(DEST, "<br>" "\n");
      else if (*str == '\t') written += snprintf(DEST, "&nbsp;&nbsp;&nbsp;&nbsp;");
      else if (*str == '\r') written += snprintf(DEST, "\\r");
      else if (*str == '\b') written += snprintf(DEST, "\\b");
      else if (*str == '\f') written += snprintf(DEST, "\\f");
      else written += snprintf(DEST, "\\%03o", (int)*str & 0xff);
    }
    else if (*str == '\"') written += snprintf(DEST, "\\\"");
    else if (*str == '\\') written += snprintf(DEST, "\\\\");
    else if (*str == '<') written += snprintf(DEST, "&lt;");
    else if (*str == '>') written += snprintf(DEST, "&gt;");
    else written += snprintf(DEST, "%c", *str);
  }
  return written;
}

int judge_uses_val(Judge *f, Form *name, Form *val) {
  Form *g = form_repl(f->concl, val, name);
  if (form_cmp(g, f->concl)) {
    //form_printf("%d: uses %s\n", __LINE__, form_s(name));
    form_free(g);
    return 1;
  }
  g = form_repl(f->concl, name, val);
  if (form_cmp(g, f->concl)) {
    form_free(g);
    //form_printf("%d: uses %s\n", __LINE__, form_s(name));
    return 1;
  }
  int i, n = f->arity;
  for (i = 0; i < n; i++) {
    if (judge_uses_val(f->ant[i], name, val)) {
      //form_printf("%d: uses %s\n", __LINE__, form_s(name));
      return 1;
    }
  }
  return 0;
}

int judge_print_dhtml0(FILE *out, Judge *f, int *num_nodes, 
		       PointerVector *givens, 
		       PointerVector *assumptions, 
		       PointerVector *replnames, 
		       PointerVector *replvals) 
{
  int node_id = ++(*num_nodes);

  char *rule = strdup(f->rule);
  char *e = rule;
  while (*e && !isspace(*e) && *e != ';') e++;
  *e = '\0';
  Form *g = form_repl_all(f->concl, replvals, replnames);
  char *s = form_to_pretty(g, 180); // no abbreviation for now
  int len = form_escape_html(NULL, 0, s) + 1;
  char *text = nxcompat_alloc(len);
  form_escape_html(text, len, s);
  fprintf(out, "<li>");
  if (!strcmp(rule, "impi")) {
    assert(f->concl->tag == F_STMT_IMP);
    int k = PointerVector_len(assumptions);
    PointerVector_append(assumptions, f->concl->left);
    fprintf(out, "<span>implication introduction (on assumption A%d)</span>", k);
  } else if (!strcmp(rule, "assume")) {
    int j, k = PointerVector_len(assumptions);
    for (j = 0; j < k; j++) {
      Form *h = PointerVector_nth(assumptions, j);
      if (!form_cmp(h, f->concl))
	break;
    }
    if (j >= k) fprintf(out, "<span>assumption A?</span>");
    else fprintf(out, "<span>assumption A%d</span>", j);
  } else if (!strcmp(rule, "given")) {
    int j, k = PointerVector_len(givens);
    for (j = 0; j < k; j++) {
      Form *h = PointerVector_nth(givens, j);
      if (!form_cmp(h, f->concl))
	break;
    }
    if (j == k)
      PointerVector_append(givens, f->concl);
    fprintf(out, "<span>given G%d</span>", j);
  } else {
    fprintf(out, "<span>%s</span>", rule);
  }
  nxcompat_free(rule);
  nxcompat_free(s);

  fprintf(out, "%s\n", text);
  nxcompat_free(text);

  int i, n = f->arity;
  if (n > 0) {
    fprintf(out, "<ul>\n");
    for (i = 0; i < n; i++) {
      judge_print_dhtml0(out, f->ant[i], num_nodes, givens, assumptions, replnames, replvals);
    }
    fprintf(out, "</ul>\n");
  }
  fprintf(out, "</li>\n");

  return node_id;
}

void judge_print_dhtml(FILE *out, Judge *f, char *name, 
		       PointerVector *replnames, PointerVector *replvals) 
{
  PointerVector givens, assumptions;
  PointerVector_init(&givens, 16, POINTERVECTOR_ORDER_PRESERVING);
  PointerVector_init(&assumptions, 16, POINTERVECTOR_ORDER_PRESERVING);
  
  fprintf(out, "<html><head><title>%s</title></head>\n"
    "<script language=\"JavaScript\" src=\"mktree.js\"></script>\n"
    "<link rel=\"stylesheet\" href=\"mktree.css\">\n"
    "<body>\n", name);
  int i, n = PointerVector_len(replnames);
  if (n > 0) {
    fprintf(out, "<h2>variables:</h2>\n<ul>\n");
    for (i = 0; i < n; i++) {
      Form *name = PointerVector_nth(replnames, i);
      Form *val = PointerVector_nth(replvals, i);
      if (!judge_uses_val(f, name, val))
	continue;
      char *ns = form_to_pretty(name, 180);
      char *vs = form_to_pretty(val, 180);
      int nlen = form_escape_html(NULL, 0, ns) + 1;
      int vlen = form_escape_html(NULL, 0, vs) + 1;
      char *ntext = nxcompat_alloc(nlen);
      char *vtext = nxcompat_alloc(vlen);
      form_escape_html(ntext, nlen, ns);
      form_escape_html(vtext, vlen, vs);
      fprintf(out, " <li>%s = %s</li>\n", ntext, vtext);
      nxcompat_free(ns); nxcompat_free(vs); nxcompat_free(ntext); nxcompat_free(vtext);
    }
    fprintf(out, "</ul>\n");
  }

  fprintf(out, "<h2>%s proof:</h2>\n"
    "<A href=\"#\" onClick=\"expandTree('%s'); return false;\">Expand All</A>&nbsp;&nbsp;&nbsp;\n"
    "<A href=\"#\" onClick=\"collapseTree('%s'); return false;\">Collapse All</A>&nbsp;&nbsp;&nbsp;\n"
    "<ul class=\"mktree\" id=\"%s\">\n", name, name, name, name);
  int num_nodes = 0;
  judge_print_dhtml0(out, f, &num_nodes, &givens, &assumptions, replnames, replvals);
  fprintf(out, "</body></html>\n");
  PointerVector_dealloc(&givens);
  PointerVector_dealloc(&assumptions);
}

/* this output is comaptible with the `dot` graph viewer from graphviz */
void judge_print(FILE *out, Judge *f, char *fmt, char *name, 
		 PointerVector *replnames, PointerVector *replvals) 
{
 if (!strcmp(fmt, "dot")) {
    /* this output is comaptible with the `dot` graph viewer from graphviz */
    judge_print_graphviz(out, f, name);
  } else if (!strcmp(fmt, "html")) {
    /* this output is pure html, but needs the (modified) mktree.js, mktree.css, etc. scripts */
    judge_print_dhtml(out, f, name, replnames, replvals);
  }
}

