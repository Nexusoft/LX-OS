#ifndef _SWITCH_NQ_HH_
#define _SWITCH_NQ_HH_

#include <nq/tuple.hh>
#include <nq/site.hh>

extern NQ_Principal *switch_owner;
void switch_nq_init(short server_port_num, NQ_Host home, NQ_Principal *principal = NULL);
bool trust_all(NQ_Tuple tid, KnownClass *obj_class);
bool trust_attrval_all(NQ_Attribute_Name *name, NQ_Tuple tid, NQ_Principal *principal);
extern ExtRef<T_Site> g_site_ref;

#endif // _SWITCH_NQ_HH_
