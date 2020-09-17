/** NexusOS: Symbol table support (debugging)
 
    Parse symbol tables generated with 
    
    	nm <non-stripped binary> | grep -v <non-standard lines> | sort */

#include <stdarg.h>
#include <nexus/defs.h>
#include <nexus/ksymbols.h>
#include <nexus/initrd.h>
#include <nexus/util.h>

#include <nexus/hashtable.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>

#include <linux/ctype.h>
#include <asm/hw_irq.h>		// for _stext

#if NXCONFIG_DEBUG_TRACE

struct KSymbol {
	void *addr;
	char *name;
	char type;
} __attribute__((packed));

struct SymTable {
	int count;
	KSymbol syms[0];
};

static SymTable *kernel_table;
static struct HashTable *symtable_map; // filename => symbol table


////////  support: symbol table parsing  ////////

static SymTable *
symtable_find(const char *name) 
{
	return (SymTable *) hash_findItem(symtable_map, name);
}

/** Parse a symbol table and add it to the lookup table by name */
static SymTable *
symtable_addNew(const char *name, char *data, int size) 
{
	struct SymTable *entry;
	char *c, *end = data + size - 1;
	int n = 0;

	// return existing entry (if any)
	entry = hash_findItem(symtable_map, name);
	if (entry)
		return entry;

	// calculate entries in the table
	for (c = data; c <= end; c++) {
		if (*c == '\n') 
			n++;
	}

	entry = galloc(sizeof(SymTable) + n * sizeof(KSymbol));
	entry->count = 0;

	while (data <= end) {
		// find line extents
		char *line = data;
		while (*data != '\n') {
			assert(data != end + 1);
			data++;
		}
		*data = '\0';

		int len = data - line;
		data++;

		// ?? combining statement about two consecutive lines ??
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
		  printk_red("Bad System.map, line %d: %s, %d %d %d\n", entry->count+1, line,
			     (len < 8+1+1+1+1), (line[8] != ' '), (line[10] != ' '));
			break;
		}

		// add line
		entry->syms[entry->count].addr = (void *)hexatoi(line);
		entry->syms[entry->count].name = &line[11];
		entry->syms[entry->count].type = line[9];
		entry->count++;
	} 

	hash_insert(symtable_map, name, entry);
	printkx(PK_SHELL, PK_DEBUG, "[debug] %s: %d symbols\n", name, n);
	return entry;
}

/** Parse a symbol table file and make it accessible using symtable_find */
static SymTable *
symtable_addNewFromFile(const char *name) 
{
	struct InitRD_File *te;
	int size;
	
	te = initrd_find(name);
	if (!te || !te->len)
		return NULL;

	te->data[te->len - 1] = '\n';
	return symtable_addNew(name, te->data, te->len);
}

static KSymbol *
symtable_find_by_addr(SymTable *table, void *a) 
{
	if (!table || !table->count)
		return NULL;
	if (a < table->syms[0].addr || a > table->syms[table->count-1].addr) {
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

static void
symtable_print_by_addr(SymTable *table, void *a)
{
	KSymbol *s;

	s = symtable_find_by_addr(table, a);
	if (s)
		printk_red("[0x%p] %c %s\n", a, s->type, s->name);
	else
		printk_red("[0x%p]\n", a);
	
}

static void
__dump_stack(BasicThread *thread, SymTable *table, unsigned long ebp)
{
  unsigned long data[2];
  int i;

  // walk stack
  for (i = 0; i < 16 && ebp; i++) {
    copy_from_generic(thread->ipd->map, data, (void *) ebp, sizeof(data));
    symtable_print_by_addr(table, (void *) data[1]);
    ebp = data[0];
  }

  printk_red("\n");
}


////////  trace: print a kernelstack trace  ////////

/** Initialize the symbol table lookup structure and insert the kernel table */
void 
ksym_init(void) 
{
  symtable_map = hash_new_vlen(16, hash_strlen);

  kernel_table = symtable_addNewFromFile("System.map");
  if (kernel_table)
  	printk("[debug] kernel symbols loaded\n");
}

static void
__dump_kernel_stack(BasicThread *thread)
{
  unsigned long ebp;

  printk_red("[trace] %d.%d.kernel (%s)\n", 
	      thread->ipd->id, thread->id, thread->ipd->name);

  // get stack pointer
  if (thread == curt)
  	asm("movl %%ebp, %0" : "=g" (ebp));
  else
  	ebp = thread_getKTS(thread)->ebp;
  
  __dump_stack(thread, kernel_table, ebp);
}

/** dump the current (kernel) thread */
static void 
dump_kernel_stack(void)
{
	__dump_kernel_stack(curt);
}


////////  trace: print a userstack trace  ////////

void 
dump_regs_is(InterruptState *is) 
{
  printk_red("eax=0x%x ebx=0x%x ", is->eax, is->ebx);
  printk_red("ecx=0x%x edx=0x%x\n", is->ecx, is->edx);
  printk_red("esi=0x%x edi=0x%x ", is->esi, is->edi);
  printk_red("ebp=0x%x esp=0x%x\n", is->ebp, is->esp);
  printk_red("ds=0x%x es=0x%x ss=0x%x fs=0x%x gs=0x%x eflags=0x%x\n", 
	     is->ds, is->es, is->ss, is->fs, is->gs, is->eflags);
  printk_red("cs=%x sp=0x%x pc=0x%x errorcode=0x%x entry_vector=%d\n", 
	     is->cs, is->esp, is->eip, is->errorcode, is->entry_vector);
}

/** lookup symbol table file <filepath>.<suffix> */
static SymTable *
dumpstack_findsymbols(const char *filepath, const char *suffix)
{
  SymTable *table;
  char fname[512];

  if (strlen(filepath) + strlen(suffix) + 1 > 512) {
	printk_red("[elf] path out of bounds\n");
	return NULL;
  }

  strcpy(fname, filepath);
  strcat(fname, suffix);
  return symtable_addNewFromFile(fname);
}

/** Dump a process stack while resolving names using a symbol table */
void
dump_user_stack(BasicThread *thread, unsigned int ebp)
{
  SymTable *table;
  unsigned long curr_ebp, data[2];
  int i;

  printk_red("[trace] %d.%d.user (%s)\n", 
	     thread->ipd->id, thread->id, thread->ipd->name);
  
  // looking symbol file in initrd
  table = dumpstack_findsymbols(thread->ipd->name, ".map");
  if (!table) {
	  table = dumpstack_findsymbols(thread->ipd->name, ".debug.map");
	  if (!table) {
    		  printk_red("no symbols\n");
		  return;
	  } 
  }
 
  __dump_stack(thread, table, ebp);
}

/** Dump the current stack, whether user or kernel */
void
dump_stack_current(InterruptState *is)
{
  // in user thread?
  if (is && curt->type == USERTHREAD && !curt->syscall_is)
	  dump_user_stack(curt, is->ebp);
  else
	  dump_kernel_stack();
}

#else /* NXCONFIG_DEBUG_TRACE */

void ksym_init(void)
{
}

void
dump_user_stack(BasicThread *thread, unsigned int ebp)
{
}

void 
dump_stack_current(InterruptState *is)
{
}

void 
dump_regs_is(InterruptState *is) 
{
}

#endif /* NXCONFIG_DEBUG_TRACE */

