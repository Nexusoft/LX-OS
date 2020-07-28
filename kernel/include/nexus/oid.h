#ifndef _OID_H_
#define _OID_H_

#define OID_NONE (0)

struct OID_Table;

OID_Table *OIDTable_new(void);

OID OID_assign(OID_Table *table, void *obj); // returns OID
OID OID_ipd_assign(OID_Table *table, int id, void *obj); // returns OID in IPD range
void OID_unassign(OID_Table *table, OID oid);
void *OID_find(OID_Table *table, OID oid);

#endif // _OID_H_

