#ifndef _GENERIC_MAPPING_H_
#define _GENERIC_MAPPING_H_

struct  Mapping {
  int in_num;
  int out_num;
};

struct Mapping interposition_table[5] = {
  { 0, Interposition_Passthrough },
  { 1, Interposition_Modify },
  { 2, Interposition_Replace },
  { 3, Interposition_Drop },
  { -1, -1 },
};
struct Mapping replacement_table[5] = {
  { 0, Replacement_Identity },
#if 0
  { 1, Replacement_Constant },
  { 2, Replacement_Add },
  { 3, Replacement_Multiply },
#else
  { 1, Replacement_Add },
  { 2, Replacement_Multiply },
#endif
  { -1, -1 },
};

static int Mapping_find(struct Mapping *table, int v) {
  int i;
  for(i=0; table[i].in_num != -1; i++) {
    if(table[i].in_num == v) {
      return table[i].out_num;
    }
  }
  return -1;
}

#endif // _GENERIC_MAPPING_H_
