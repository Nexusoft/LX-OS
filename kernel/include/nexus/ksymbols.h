#ifndef __NEXUS_KSYMBOLS_H__
#define __NEXUS_KSYMBOLS_H__

struct KSymbol {
	void *addr;
	char *name;
	char type;
} __attribute__((packed));

struct SymTable {
	int count;
	KSymbol syms[0];
};

SymTable *symtable_parse(char *filename, char *text, int textsize); /* parses output of 'nm' */
SymTable *symtable_find(const char *name);
void symtable_sort(SymTable *table); // sort the table

// initialize the table
void ksym_init(void);

// (quickly) pretty print symbol info containing a virtual address
void ksym_print_by_addr(void *addr);
void symtable_print_by_addr(SymTable *table, void *addr);

void ksym_log_by_addr(void *addr);
void symtable_log_by_addr(SymTable *table, void *addr);

// (quickly) find symbol containing a virtual address
KSymbol *ksym_find_by_addr(void *addr);
KSymbol *symtable_find_by_addr(SymTable *table, void *addr);

// (slowly) find symbol by name and type (can be 0 for "any type")
KSymbol *ksym_find_by_name(char *name, char type);
KSymbol *symtable_find_by_name(SymTable *table, char *name, char type);

// get the whole symbol table
KSymbol *ksym_table(int *count);

// Accessors for non-kernel symbol tables. Used for userspace stack trace
SymTable *symtable_find(const char *name);
SymTable *symtable_addNewFromFile(const char *name);

#endif
