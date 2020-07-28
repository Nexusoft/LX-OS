#ifndef __IDTGDT_H__
#define __IDTGDT_H__

extern int nexus_sse_enabled;

void init_gdt(void);
void switch_to_final_gdt(void);
void init_idt(void);
int init_sse(void);

void write_ldt(unsigned int base_address, int num_entries);

void print_gdt(void);
void print_idt(void);
void print_tss(void);

void put_idt(unsigned int idtoffset, unsigned int idtLo, unsigned int idtHi);
void put_gdt(unsigned int gdtoffset, unsigned int gdtLo, unsigned int gdtHi);
void write_tr(unsigned int selector);

void set_idt(unsigned int idtoffset, unsigned int type, unsigned int dpl, void *handler);

void set_fast_trap(int vector, __u16 cs, unsigned long eip);

#endif
