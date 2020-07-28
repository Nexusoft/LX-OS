
#include "aas_eval.h"

// example: "all quotes are attested and verbatim"

// principal: generic
static Form *self(void) { return make_name("generic"); }

#define FAIL(s) do { printf("error: "); printf(s); printf("\n"); return NULL; } while (0)
char *odf_to_docbook(char *zip, int zlen) {
    if (pzipcheck(zip, zlen)) FAIL("zip is bad"); // sanity check
    struct doc *doc = docsigs_parse_pzip(zip, zlen);
    if (!doc) FAIL("can't parse ODF");
    if (docsigs_verify_all(doc)) FAIL("bad sigs on ODF");
    char *docbook = pxslt("<odf2docbook>", doc->content_xml);
    if (!docbook) FAIL("can't convert to docbook");
    if (doc->nsigs > 0) {
      struct xn *xn = docbook_parse(docbook);
      struct docsig *sig;
      int i = doc->nsigs;
      if (!xn || !xn->tag || strcmp(xn->tag, "article"))
	FAIL("can't parse docbook");
      char buf[1000];
      struct xn *xa = xn_parse("<ArticleInfo><Digest/>1234</ArticleInfo>");
      char *digest = xa->son->son->arg = malloc(41);
      for (i = 0; i < 20; i++)
	sprintf(digest+(2*i), "%02x", doc->content_digest[i] & 0xff);
      struct xn **xx = &xa->son->sib;
      printf("adding %d signatures\n", doc->nsigs);
      for (sig = doc->sigs; sig; sig = sig->next) {
	sig = doc->sigs;
	// E=kwalsh@cs.cornell.edu,CN=Kevin Walsh,OU=Computer Science,O=Cornell,L=Ithaca,ST=New York,C=US
	sprintf(buf, "<Author>");
	char *p = sig->issuername;
	while (p && *p) {
	  char *m = strchr(p, '=');
	  if (!m) break;
	  char *e = strchr(m, ',');
	  if (!e) e = p + strlen(p);
	  sprintf(buf+strlen(buf), "<%.*s>%.*s</%.*s>", m-p, p, e-(m+1), m+1, m-p, p);
	  p = e;
	}
	sprintf(buf+strlen(buf), "</Author>");

	*xx = xn_parse(buf);
	xx = &(*xx)->sib;
      }

    } else {
      printf("no signatures to add\n");
    }
    docsigs_free(doc);
    return docbook;
}
#undef FAIL

#define FAIL(s) do { printf("error: "); printf(s); printf("\n"); return -1; } while (0)
int aas_generic_advise(char *zip, int zlen, PointerVector *ev, struct hints *hints)
{
  // extract document
  // todo: delegate to zip, xstl, and signature checker instead
  char *docbook = odf_to_docbook(zip, zlen);
  if (!docbook) FAIL("can't convert to docbook");
  Form *f = form_new(F_STMT_SAYS, self(), NULL,
    form_new(F_PRED_IMP, 
      form_new(F_PRED_APPLY, form_newdata(F_FUNC_USERVAR, strdup("DocbookOkay"), -1), NULL,
	form_new(F_LIST_CONS,
	  form_newdata(F_STR_CONST, docbook, -1), NULL,
	    form_new(F_LIST_NONE, NULL, NULL, NULL))), NULL,
      form_new(F_PRED_APPLY, form_newdata(F_FUNC_USERVAR, strdup("GenericOkay"), -1), NULL,
	form_new(F_LIST_CONS,
	  form_newdata(F_BYTES_CONST, mem_dup(zip, zlen), zlen), NULL,
	    form_new(F_LIST_NONE, NULL, NULL, NULL)))));
  Form *f2 = form_new(F_STMT_SAYS, self(), NULL,
      form_new(F_STMT_SFOR, self(), NULL, make_sub(self(), "compliance")));
  Form *f3 = form_new(F_STMT_SAYS, self(), NULL,
      form_new(F_STMT_SFOR, make_sub(make_name("pol"), "e"), NULL, make_sub(self(), "compliance")));

  int naux = PointerVector_len(&hints->odf_docs);
  PointerVector_init(&hints->docbook_docs, naux,  POINTERVECTOR_AUTO_ZERO | POINTERVECTOR_ORDER_PRESERVING);
  PointerVector_init(&hints->odf2docbook_certs, naux,  POINTERVECTOR_AUTO_ZERO | POINTERVECTOR_ORDER_PRESERVING);

  int i;
  for (i = 0; i < naux; i++) {
    struct aux *aux = PointerVector_nth(&hints->odf_docs, i);
    char *docbook = odf_to_docbook(aux->data, aux->len);
    if (!docbook) {
      printf("warning: hint %d is unusable\n", i+1);
      continue;
    }
    PointerVector_append(&hints->docbook_docs, docbook);
    PointerVector_append(&hints->odf2docbook_certs,
      form_new(F_STMT_SAYS, self(), NULL,
	form_new(F_PRED_EQ, 
	  form_new(F_STR_APPLY, form_newdata(F_FUNC_USERVAR, strdup("Odf2Docbook"), -1), NULL,
	    form_new(F_LIST_CONS,
	      form_newdata(F_BYTES_CONST, aux->data, aux->len), NULL,
		form_new(F_LIST_NONE, NULL, NULL, NULL))), NULL,
	  form_newdata(F_STR_CONST, docbook, -1))));
  }

  PointerVector_append(ev, f2);
  PointerVector_append(ev, f);
  PointerVector_append(ev, f3);
  return pol_advise(docbook, ev, hints);
}
#undef FAIL

int aas_generic_eval(char *doc, int doclen, char **aux, int *auxlen, int naux)
{
  // "generic.compliance says generic_okay(doc)";
  Form *target =
    form_new(F_STMT_SAYS, make_sub(self(), "compliance"), NULL,
      form_new(F_PRED_APPLY, form_newdata(F_FUNC_USERVAR, strdup("GenericOkay"), -1), NULL,
	form_new(F_LIST_CONS,
	  form_newdata(F_BYTES_CONST, mem_dup(doc, doclen), doclen), NULL,
	    form_new(F_LIST_NONE, NULL, NULL, NULL))));

  char *s = form_to_pretty(target, -80);
  printf("target formula:\n%s\n\n", s);
  free(s);

  struct hints *hints = malloc(sizeof(struct hints));
  memset(hints, 0, sizeof(struct hints));
  PointerVector_init(&hints->odf_docs, naux,  POINTERVECTOR_AUTO_ZERO | POINTERVECTOR_ORDER_PRESERVING);

  int i;
  for (i = 0; i < naux; i++) {
    struct aux *x = malloc(sizeof(struct aux));
    x->data = aux[i];
    x->len = auxlen[i];
    PointerVector_append(&hints->odf_docs, x);
  }

  PointerVector ev;
  PointerVector_init(&ev, 20,  POINTERVECTOR_AUTO_ZERO | POINTERVECTOR_ORDER_PRESERVING);

  if (aas_generic_advise(doc, doclen, &ev, hints)) {
    printf("giving up\n");
    return -1;
  } else {
    printf("satisfied\n");
    return 0;
  }
}

