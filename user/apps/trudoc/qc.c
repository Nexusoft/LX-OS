#include "aas_eval.h"

// principal: generic
static Form *self(void) { return make_name("qc"); }

#define FAIL(s...) do { printf("error: "); printf(s); printf("\n"); return 0; } while (0)
int validQuote(struct xn *xq, struct xn *xs) {
  // pull out attribution data (first node or two)
  struct xn *xtag = NULL, *xatt = NULL;
  if (xq && xq->son && xq->son->tag && !strcmp(xq->son->tag, "Attribution")) {
    xtag = xq->son;
    xq->son = xtag->sib;
    xtag->sib = NULL;
  }
  if (xq && xq->son && xq->son->tag && !strcmp(xq->son->tag, "Comment")) {
    xatt = xq->son;
    xq->son = xatt->sib;
    xatt->sib = NULL;
  }

  struct xn *xa;

  if (!xatt)
    FAIL("quote has no attestation data"); // don't bother without it
  if (xtag) {
    if (!xtag->son  || xtag->son->sib || xtag->son->tag)
      FAIL("attribution line missing");
    char *auth = strdup(xtag->son->arg);
    char *date = strchr(auth, ',');
    if (date) {
      *date = '\0';
      date++;
      while (*date == ' ') date++;
    }
    // make sure it matches attestation
    for (xa = xatt->son; xa; xa = xa->sib) {
      if (!strcmp(xa->tag, "para") && xa->son && !xa->son->son
	  && !xa->son->sib && !xa->son->tag && !strncmp(xa->son->arg, " author=", strlen(" author=")))
	xa = xa->son;
	break;
    }
    if (!xa)
      FAIL("attestation data missing author info");
    char *p = strrchr(xa->arg, '/');
    if (!p || strcmp(p+1, auth))
      FAIL("inconsistent attribution: %s versus %s\n", auth, xa->arg);

    if (date) {
      for (xa = xatt->son; xa; xa = xa->sib) {
	if (!strcmp(xa->tag, "para") && xa->son && !xa->son->son
	    && !xa->son->sib && !xa->son->tag && !strncmp(xa->son->arg, " published at=", strlen(" published at=")))
	  xa = xa->son;
	  break;
      }
      if (!xa)
	FAIL("attestation data missing needed date info");
      p = strchr(xa->arg, '=');
      if (!p || strcmp(p+1, date))
	FAIL("inconsistent attribution date: %s versus %s\n", date, xa->arg);
    }
  }

  // now check if source matches attribution
  if (!xs || !xs->son || !xs->son->tag || strcmp(xs->son->tag, "ArticleInfo"))
    FAIL("source document missing ArticleInfo");
  xa = xs->son;
  if (!xa->son || !xa->son->tag || strcmp(xa->son->tag, "Digest") || !xa->son->son || xa->son->son->tag)
    FAIL("source document missing digest in ArticleInfo");
  char *digest = xa->son->son->arg;

  for (xa = xatt->son; xa; xa = xa->sib) {
    if (!strcmp(xa->tag, "para") && xa->son && !xa->son->son
	&& !xa->son->sib && !xa->son->tag && !strncmp(xa->son->arg, " hash=", strlen(" hash=")))
      xa = xa->son;
      break;
  }
  if (!xa)
    FAIL("attestation data missing digest");
  char *hash = strchr(xa->arg, '=');
  if (!hash)
    FAIL("bad attestation data digest");
  hash = hash+1;
  if (strcmp(hash, digest))
    FAIL("digest mismatch");

  // todo: check if other attestation data matches source articleinfo (date,
  // author, etc.)

  int offset = xn_match(xq, xs);
  return (offset >= 0);
}
#undef FAIL

#define FAIL(s) do { printf("error: "); printf(s); printf("\n"); return -1; } while (0)
int qc_advise(char *q, PointerVector *ev, struct hints *hints) {
  printf("qc_advise: %s\n", q);
  struct xn *xq = xn_parse(q);
  if (!xq || !xq->tag || strcmp(xq->tag, "BlockQuote"))
    FAIL("bad quote xml");
  // strategy 1: go through hints, which are docbook files in a PointerVector, and
  // find evidence we need to evaluate ValidQuote(q)
  PointerVector *srcs = &hints->docbook_docs;
  int i, n = PointerVector_len(srcs);
  for (i = 0; i < n; i++) {
    char *src = PointerVector_nth(srcs, i);
    printf("source? %s\n", src);
    struct xn *xs = docbook_parse(src);
    if (!xs) continue;
    if (validQuote(xq, xs)) {
      xn_free(xq);
      xn_free(xs);
      // need: qc says ValidQuote(q)
      // give: qc says contains(D, q) imp ValidQuote(q)
      // and contains(D, q)
      Form *f = form_new(F_STMT_SAYS, self(), NULL, 
	  form_new(F_PRED_IMP, 
	    form_new(F_PRED_APPLY, form_newdata(F_FUNC_USERVAR, strdup("ContainsQuote"), -1), NULL,
	      form_new(F_LIST_CONS,
		form_newdata(F_STR_CONST, src, -1), NULL,
		form_new(F_LIST_CONS,
		  form_newdata(F_STR_CONST, strdup(q), -1), NULL,
		    form_new(F_LIST_NONE, NULL, NULL, NULL)))), NULL,
	    form_new(F_PRED_APPLY, form_newdata(F_FUNC_USERVAR, strdup("ValidQuote"), -1), NULL,
	      form_new(F_LIST_CONS,
		form_newdata(F_STR_CONST, strdup(q), -1), NULL,
		  form_new(F_LIST_NONE, NULL, NULL, NULL)))));
      PointerVector_append(ev, f);
      Form *g = form_new(F_STMT_SAYS, self(), NULL, 
	  form_new(F_PRED_APPLY, form_newdata(F_FUNC_USERVAR, strdup("ContainsQuote"), -1), NULL,
	    form_new(F_LIST_CONS,
	      form_newdata(F_STR_CONST, src, -1), NULL,
	      form_new(F_LIST_CONS,
		form_newdata(F_STR_CONST, strdup(q), -1), NULL,
		  form_new(F_LIST_NONE, NULL, NULL, NULL)))));
      PointerVector_append(ev, f);
      return 0;
    }
    xn_free(xs);
  }
  xn_free(xq);
  FAIL("no source for quote");
}

#undef FAIL

