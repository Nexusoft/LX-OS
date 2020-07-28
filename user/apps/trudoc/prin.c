#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nexus/formula.h>

#include "prin.h"

Form *make_sub(Form *parent, char *name) {
  return form_new(F_PRIN_SUB, parent, NULL, 
      form_newdata(F_NAME_CONST, strdup(name), -1));
}

Form *make_name(char *name) {
  return make_sub(form_newdata(F_PRIN_KEY, mem_dup(aas_key, aas_key_len), aas_key_len), name);
}

char *mem_dup(char *buf, int len) {
  char *data = malloc(len);
  memcpy(data, buf, len);
  return data;
}
