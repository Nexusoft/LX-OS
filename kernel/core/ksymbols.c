#include <stdarg.h>
#include <nexus/defs.h>
#include <nexus/ksymbols.h>
#include <nexus/initrd.h>
#include <nexus/util.h>

#include <nexus/hashtable.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/tftp.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>
#include <linux/ctype.h>

static SymTable *kernel_table;

Sema symtable_lock = SEMA_MUTEX_INIT;
struct HashTable *symtable_map; // asciiz => SymTable *

SymTable *symtable_find(const char *name) {
	return (SymTable *)hash_findItem(symtable_map, name);
}

static SymTable *symtable_addNew(const char *name, char *data, int size) {
	// printk_red("adding new symbol table for '%s'", name);
	assert(hash_findItem(symtable_map, name) == NULL);
	char *c, *end = data + size;
	int n = 0;
	for (c = data; c <= end; c++) if (*c == '\n') n++;

	printkx(PK_SHELL, PK_DEBUG, "Loading %d symbols... ", n);
	SymTable *rtable = galloc(sizeof(SymTable) + n*sizeof(KSymbol));
	rtable->count = 0;

	while (data < end) {
		char *line = data;
		while (*data != '\n') data++;
		*data = '\0';
		int len = data - line;
		data++;
		if(len > 0 && !(isalnum(data[0]))) {
			// printk_red("Skipping %s\n", data);
			continue;
		}
		if (len > 8 && !strncmp(line, "00000000", 8) && line[8] != ' ') {
			// ignore high 32 bits if 64 bit addresses
			line += 8;
			len -= 8;
		}
		if ((len < 8+1+1+1+1) || (line[8] != ' ') || (line[10] != ' ')) {
		  printk_red("Bad System.map, line %d: %s, %d %d %d\n", rtable->count+1, line,
			     (len < 8+1+1+1+1), (line[8] != ' '), (line[10] != ' '));
			break;
		}
		rtable->syms[rtable->count].addr = (void *)hexatoi(line);
		rtable->syms[rtable->count].name = &line[11];
		rtable->syms[rtable->count].type = line[9];
		rtable->count++;
	}  
	hash_insert(symtable_map, name, rtable);
	return rtable;
}

SymTable *symtable_addNewFromFile(const char *name) {
	char *data;
	int size;
	
	data = fetch_file((char *) name, &size);
	if (!data)
		return NULL;

	return symtable_addNew(name, data, size);
}

const char *ksym_name = "System.map";

void ksym_init(void) {
	symtable_map = hash_new_vlen(16, hash_strlen);

	struct InitRD_File *te = initrd_find((char *)ksym_name);
	if (!te || !te->len) {
		printk_red("System.map not in initrd: no kernel symbols available\n");
		return;
	}
	char *data = te->data;
	char *end = te->data + te->len - 1;
	*end = '\n'; // just to be safe
	kernel_table = symtable_addNew(ksym_name, data, end - data);
}

#define SYMTABLE_PRINTER(NAME, PFUNC)					\
  void symtable_##NAME##_by_addr(SymTable *table, void *a) {		\
    if (!table || !table->count) {					\
      PFUNC("  [<0x%08lx>] ", (long)a);					\
      return;								\
    }									\
    KSymbol *s = symtable_find_by_addr(table, a);			\
    if (!s)								\
      PFUNC("  [<0x%p>] ???\n", a);					\
    else								\
      PFUNC("  [<0x%p>] %c %8u+%s\n", a, s->type, a - s->addr, s->name); \
  }

SYMTABLE_PRINTER(print, printk_current)
SYMTABLE_PRINTER(log, nexuslog)

void ksym_print_by_addr(void *a /* virtual address */) {
	symtable_print_by_addr(kernel_table, a);
}

void ksym_log_by_addr(void *a /* virtual address */) {
	symtable_log_by_addr(kernel_table, a);
}

KSymbol *symtable_find_by_addr(SymTable *table, void *a) {
	if (!table || !table->count)
		return NULL;
	if (a < table->syms[0].addr || a > table->syms[table->count-1].addr) {
		printk_red("%p not in [%p, %p]\n", a, table->syms[0].addr,
			   a > table->syms[table->count-1].addr);
		return NULL;
	}
	int k = 0, e = table->count;
	while (k < e-1) {
		// invariant: addr[k] <= a < addr[e]
		int m = k + (e-k)/2;
		if (a < table->syms[m].addr) e = m;
		else k = m;
	}
	return &table->syms[k];
}

KSymbol *ksym_find_by_addr(void *a) {
	return symtable_find_by_addr(kernel_table, a);
}

KSymbol *symtable_find_by_name(SymTable *table, char *name, char type) {
	if (!table) return NULL;
	int i;
	for (i = 0; i < table->count; i++) {
		if (type && (type != table->syms[i].type)) continue;
		if (strcmp(name, table->syms[i].name)) continue;
		return &table->syms[i];
	}
	return NULL;
}

KSymbol *ksym_find_by_name(char *name, char type) {
	return symtable_find_by_name(kernel_table, name, type);
}

KSymbol *ksym_table(int *count) {
	if(!kernel_table) {
	  *count = 0;
	  return NULL;
	} else {
	  *count = kernel_table->count;
	  return kernel_table->syms;
	}
}
