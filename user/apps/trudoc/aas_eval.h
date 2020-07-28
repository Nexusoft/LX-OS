#ifndef AAS_EVAL_H
#define AAS_EVAL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nexus/formula.h>
#include <nexus/vector.h>

#include "prin.h"
#include "pzip.h"
#include "pxslt.h"
#include "odf_sign.h"

struct aux {
  char *data;
  int len;
};

struct hints {
  PointerVector /* of pzip */ odf_docs;
  PointerVector /* of xml */ docbook_docs;
  PointerVector /* of Form */ odf2docbook_certs;
};

void aas_init(void);
int aas_generic_eval(char *doc, int doclen, char **aux, int *auxlen, int naux);

int aas_generic_advise(char *doc, int doclen, PointerVector *ev, struct hints *hints);
int pol_advise(char *docbook, PointerVector *ev, struct hints *hints);
int qc_advise(char *q, PointerVector *ev, struct hints *hints);

#endif // AAS_EVAL_H
