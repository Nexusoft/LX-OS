#include <stdio.h>
#include <nexus/formula.h>
#include <nexus/util.h>

// form-parse is a dumping ground for testing Form * parsing code

int main(int argc, char **argv) {
  int label_len;
  if(argc < 2) {
    printf("Usage: form-print <label>\n");
    exit(-1);
  }
  char *fname = argv[1];
  SignedFormula *label_buf = (SignedFormula *) read_file(fname, &label_len);
  if(label_buf == NULL) {
    printf("Could not read label!\n");
    exit(-1);
  }
  printf("%s\n", form_to_pretty(form_from_der(signedform_get_formula(label_buf)), 1000));
  return 0;
}
