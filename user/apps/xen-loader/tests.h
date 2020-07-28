#ifndef _TESTS_H_
#define _TESTS_H_

extern maddr_t pgtable_l1;
extern maddr_t pgtable_l2;

void test_seg_regs(void);
void dump_seg_regs(void);
void dump_checkvals(void);
void run_pdir_map_tests(void);
int sanity_check_m2p_consistency(void);

void p2m_mapping_dump(void);
int sanity_check_pdir(machfn_t pdir_mfn);

void pdir_dump(void);
void l1tab_dump(void * l1tab, int isVirt);
void l2tab_dump(void * l2tab, int isVirt);

void mapdump(vaddr_t start, vaddr_t end);

struct HypercallState;
void record_hypercall(struct HypercallState *);
void dump_hypercall_record(void);

#endif // _TESTS_H_
