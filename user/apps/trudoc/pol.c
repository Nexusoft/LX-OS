#include "aas_eval.h"

// principal: generic
static Form *self(void) { return make_name("pol"); }


void extract_quotes(struct xn *xn, PointerVector *v) {
  for (; xn; xn = xn->sib) {
    if (!xn || !xn->tag) continue;
    if (!strcmp(xn->tag, "BlockQuote")) {
      PointerVector_append(v, xn);
    }
    extract_quotes(xn->son, v);
  }
}

#define FAIL(s) do { printf("error: "); printf(s); printf("\n"); return -1; } while (0)
int pol_advise(char *xml, PointerVector *ev, struct hints *hints) {
  struct xn *xn = docbook_parse(xml);
  if (!xn) FAIL("can't parse docbook");

  Form *sd = form_new(F_STMT_SAYS, self(), NULL,
      form_new(F_STMT_SFOR, self(), NULL, make_sub(self(), "e")));
  Form *qd = form_new(F_STMT_SAYS, self(), NULL,
      form_new(F_STMT_SFOR, make_name("qc"), NULL, make_sub(self(), "e")));
  // decide what policy applies
  // for now: all quotes must match
 
  PointerVector v; 
  PointerVector_init(&v, 5, POINTERVECTOR_AUTO_ZERO | POINTERVECTOR_ORDER_PRESERVING);
  extract_quotes(xn, &v);
  int i, n = PointerVector_len(&v);
  printf("Found %d quotes in document\n", n);
  if (n == 0) {
    Form *f = form_new(F_STMT_SAYS, self(), NULL,
      form_new(F_PRED_APPLY, form_newdata(F_FUNC_USERVAR, strdup("DocbookOkay"), -1), NULL,
	form_new(F_LIST_CONS,
	  form_newdata(F_STR_CONST, strdup(xml), -1), NULL,
	    form_new(F_LIST_NONE, NULL, NULL, NULL))));
    PointerVector_append(ev, f);
    PointerVector_append(ev, sd);
    return 0;
  }

  char *str = xn_tostring((struct xn *)PointerVector_nth(&v, n-1), 1);
  Form *g = 
	form_new(F_PRED_APPLY, form_newdata(F_FUNC_USERVAR, strdup("ValidQuote"), -1), NULL,
	  form_new(F_LIST_CONS,
	    form_newdata(F_STR_CONST, str, -1), NULL,
	      form_new(F_LIST_NONE, NULL, NULL, NULL)));
  for (i = n-2; i >= 0; i--) {
    str = xn_tostring((struct xn *)PointerVector_nth(&v, i), 1);
    g = form_new(F_PRED_AND,
      form_new(F_PRED_APPLY, form_newdata(F_FUNC_USERVAR, strdup("ValidQuote"), -1), NULL,
	    form_new(F_LIST_CONS,
	      form_newdata(F_STR_CONST, str, -1), NULL,
		form_new(F_LIST_NONE, NULL, NULL, NULL))), NULL, g);
  }
  Form *f = form_new(F_STMT_SAYS, self(), NULL,
    form_new(F_PRED_IMP, g, NULL,
      form_new(F_PRED_APPLY, form_newdata(F_FUNC_USERVAR, strdup("DocbookOkay"), -1), NULL,
	form_new(F_LIST_CONS,
	  form_newdata(F_STR_CONST, strdup(xml), -1), NULL,
	    form_new(F_LIST_NONE, NULL, NULL, NULL)))));
  PointerVector_append(ev, f);
  PointerVector_append(ev, sd);
  PointerVector_append(ev, qd);
  for (i = 0; i < n; i++) {
    str = xn_tostring((struct xn *)PointerVector_nth(&v, i), 1);
    if (qc_advise(str, ev, hints))
      return -1;
  }
  return 0;
}
#undef FAIL
