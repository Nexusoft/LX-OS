#ifndef _KEYBOARDRM_H_
#define _KEYBOARDRM_H_

#include <nexus/stringbuffer.h>
#include <nexus/sema.h>
#include <nexus/formula.h>
#include <nexus/LabelStore.interface.h>

extern Sema call_table_mutex;
extern struct HashTable *call_table; // EventID => CallInfo (copy)
extern StringBuffer *all_input;
extern Sema all_input_mutex;
extern FSID store;
extern SignedFormula *hashcred;
extern FSID hashcred_id;
extern char *target_name;

#endif // _KEYBOARDRM_H_
