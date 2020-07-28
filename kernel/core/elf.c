/** NexusOS: ELF binary functions */

#include <nexus/defs.h>
#include <nexus/mem.h>
#include <nexus/mem-private.h>
#include <nexus/synch-inline.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>
#include <nexus/ipd.h>
#include <nexus/elf.h>
#include <nexus/tftp.h>
#include <nexus/syscall-private.h>

typedef unsigned char u8int;
typedef unsigned short u16int;
typedef unsigned int u32int;
typedef unsigned long u64int;
typedef unsigned char uchar;

typedef struct ElfObj ElfObj;
struct ElfObj {
  unsigned char	magic[4];
  unsigned char	class;			/* ELF32 or ELF64? */
  unsigned char	data;			/* data format */
  unsigned char	elfver;
  unsigned char	abi;
  unsigned char	abiver;
  unsigned char	pad[7];
  unsigned short	type;			/* File type */
  unsigned short	mach;			/* Machine architechture */
  unsigned int	version;		/* ELF version */
  unsigned long	entry;			/* Entry point */
  unsigned long	segdaddr;		/* Segment header disk address */
  unsigned long	secdaddr;		/* Section header disk address */
  unsigned int	flags;			/* Architechture-specific */
  unsigned short	elfsize;		/* ELF header size */
  unsigned short	segentsize;		/* Size of segment header */
  unsigned short	nseg;			/* Number of segment header entries */
  unsigned short	secentsize;		/* Size of section header */
  unsigned short	nsec;			/* Number of section header entries */
  unsigned short	secstridx;		/* Section name strings section */
};

typedef struct ElfSeg ElfSeg;
struct ElfSeg {
  unsigned int	type;
  unsigned int	flags;
  unsigned long	daddr;			/* Disk address */
  unsigned long	vaddr;			/* Virtual address */
  unsigned long	paddr;			/* Physical address (not used) */
  unsigned long	dlength;		/* Size on disk */
  unsigned long	vlength;		/* Size in core */
  unsigned long	align;			/* Alignment on disk and in core */
};

typedef struct ElfSec ElfSec;
struct ElfSec {
  char		*name;
  u32int	type;		/* Section type */
  u64int	flags;
  u64int	vaddr;		/* Address in core */
  u64int	daddr;		/* Disk address */
  u64int	size;		/* Size in bytes */
  u32int	link;
  u32int	info;
  u64int	align;		/* Alignment in bytes */
  u64int	entsize;	/* Size of each entry in section */
};

typedef unsigned int Elf32_Addr;
typedef unsigned short Elf32_Half;
typedef unsigned int Elf32_Off;
typedef int Elf32_Sword;
typedef int Elf32_Word;
typedef struct Elf32_Ehdr Elf32_Ehdr;

#define EI_MAG0    0
#define EI_MAG1    1
#define EI_MAG2    2
#define EI_MAG3    3
#define EI_CLASS   4
#define EI_DATA    5
#define EI_VERSION 6
#define EI_PAD     7
#define EI_NIDENT  16


#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define ELFCLASS32 1

#define IS_ELF(ehdr)    ((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
                         (ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
                         (ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
                         (ehdr).e_ident[EI_MAG3] == ELFMAG3)


/* Legal values for p_flags (segment flags).  */

#define PF_X            (1 << 0)        /* Segment is executable */
#define PF_W            (1 << 1)        /* Segment is writable */
#define PF_R            (1 << 2)        /* Segment is readable */
#define PF_MASKOS       0x0ff00000      /* OS-specific */
#define PF_MASKPROC     0xf0000000      /* Processor-specific */

#define PT_NULL             0
#define PT_LOAD             1
#define PT_DYNAMIC          2
#define PT_INTERP           3
#define PT_NOTE             4
#define PT_SHLIB            5
#define PT_PHDR             6
#define PT_TLS	7
#define PT_LOPROC  0x70000000
#define PT_HIPROC  0x7fffffff

/* Section Types */
#define SHT_NULL     0
#define SHT_PROGBITS 1
#define SHT_SYMTAB   2
#define SHT_STRTAB   3
#define SHT_RELA     4
#define SHT_HASH     5
#define SHT_DYNAMIC  6
#define SHT_NOTE     7
#define SHT_NOBITS   8
#define SHT_REL      9
#define SHT_SHLIB    10
#define SHT_DYNSYM   11
#define SHT_LOPROC    0x70000000
#define SHT_HIPROC    0x7fffffff
#define SHT_LOUSER    0x80000000
#define SHT_HIUSER    0xffffffff

/* Special Section Indexes */
#define SHN_UNDEF       0
#define SHN_LORESERVE 0xff00
#define SHN_LOPROC    0xff00
#define SHN_HIPROC    0xff1f
#define SHN_ABS       0xfff1
#define SHN_COMMON    0xfff2
#define SHN_HIRESERVE 0xffff

/* Legal values for sh_flags (section flags).  */

#define SHF_WRITE            (1 << 0)   /* Writable */
#define SHF_ALLOC            (1 << 1)   /* Occupies memory during execution */
#define SHF_EXECINSTR        (1 << 2)   /* Executable */
#define SHF_MERGE            (1 << 4)   /* Might be merged */
#define SHF_STRINGS          (1 << 5)   /* Contains nul-terminated strings */
#define SHF_INFO_LINK        (1 << 6)   /* `sh_info' contains SHT index */
#define SHF_LINK_ORDER       (1 << 7)   /* Preserve order after combining */
#define SHF_OS_NONCONFORMING (1 << 8)   /* Non-standard OS specific handling
                                           required */
#define SHF_GROUP            (1 << 9)   /* Section is member of a group.  */
#define SHF_TLS              (1 << 10)  /* Section hold thread-local data.  */
#define SHF_MASKOS           0x0ff00000 /* OS-specific.  */
#define SHF_MASKPROC         0xf0000000 /* Processor-specific */
#define SHF_ORDERED          (1 << 30)  /* Special ordering requirement
                                           (Solaris).  */
#define SHF_EXCLUDE          (1 << 31)  /* Section is excluded unless
                                           referenced or allocated (Solaris).*/


struct Elf32_Ehdr {
  unsigned  char e_ident[EI_NIDENT];
  Elf32_Half    e_type;
  Elf32_Half    e_machine;
  Elf32_Word    e_version;
  Elf32_Addr    e_entry;
  Elf32_Off     e_phoff;
  Elf32_Off     e_shoff;
  Elf32_Word    e_flags;
  Elf32_Half    e_ehsize;
  Elf32_Half    e_phentsize;
  Elf32_Half    e_phnum;
  Elf32_Half    e_shentsize;
  Elf32_Half    e_shnum;
  Elf32_Half    e_shstrndx;
};


typedef struct Elf32_Phdr Elf32_Phdr;
struct Elf32_Phdr{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

typedef struct Elf32_Shdr Elf32_Shdr;
struct Elf32_Shdr{
  Elf32_Word sh_name;
  Elf32_Word sh_type;
  Elf32_Word sh_flags;
  Elf32_Addr sh_addr;
  Elf32_Off  sh_offset;
  Elf32_Word sh_size;
  Elf32_Word sh_link;
  Elf32_Word sh_info;
  Elf32_Word sh_addralign;
  Elf32_Word sh_entsize;
};


/*
 * return -1 if not an acceptable ELF file
 */
static int elfehdrok(Elf32_Ehdr *ehdr){

  if(IS_ELF(*ehdr) == 0){
    printk("not an elf object file\n");
    return -1;
  }
  if(ehdr->e_ident[EI_CLASS] != ELFCLASS32){
    printk("unknown or unsupported class\n");// '%s'",elfname(elfclasstab, ehdr->e_ident[EI_CLASS]));
    return -1;
  }
  return 0;
}

static
ElfObj *elfreadobj(unsigned char *fd, int len){
  ElfObj *e;
  Elf32_Ehdr *h;

  h = (Elf32_Ehdr*) fd;
  
  if((unsigned char *)h + sizeof(Elf32_Ehdr) > fd + len){
    printk("ELF read extended past end of file\n");
    return NULL;
  }

  if (elfehdrok(h) < 0)
    return NULL;
  e = galloc(sizeof(ElfObj));
  memcpy((uchar*)e->magic, (uchar*)h, 4);
  e->class = h->e_ident[EI_CLASS];
  e->data = h->e_ident[EI_DATA];
  e->elfver = h->e_ident[EI_VERSION];
  //e->abi = h->e_ident[EI_OSABI];
  //e->abiver = h->e_ident[EI_ABIVERSION];
  e->mach = h->e_machine;
  e->type = h->e_type;
  e->version = h->e_version;
  e->elfsize = h->e_ehsize;
  e->flags = h->e_flags;
  e->entry = h->e_entry;
  e->segentsize = h->e_phentsize;
  e->secentsize = h->e_shentsize;
  e->segdaddr = h->e_phoff;
  e->secdaddr = h->e_shoff;
  e->nseg = h->e_phnum;
  e->nsec = h->e_shnum;
  e->secstridx = h->e_shstrndx;

  return e;
}


static
ElfSeg *elfreadseg(char *fd, ElfObj *e, int n, int len)
{
	char *off;

	ElfSeg *s;
	Elf32_Phdr *p;

	if(n >= e->nseg){
	  printk("botch: request for Phdr %d of %d\n", n, e->nseg);
	  nexuspanic();
	}
	off = fd + e->segdaddr + n*e->segentsize;
	
	if(off + sizeof(Elf32_Phdr) > fd + len){
	  printk("ELF read extended past end of file\n");
	  return NULL;
	}

	p = (Elf32_Phdr*)off;
	s = galloc(sizeof(ElfSeg));
	s->type = p->p_type;
	s->flags = p->p_flags;
	s->daddr = p->p_offset;
	s->vaddr = p->p_vaddr;
	s->paddr = p->p_paddr;
	s->dlength = p->p_filesz;
	s->vlength = p->p_memsz;
	s->align = p->p_align;

	return s;
}

static
ElfSec *elfreadsec(char *fd, ElfObj *e, ElfSec *s, int n)
{
	char *off;
	ElfSec *ns;
	Elf32_Shdr *h;

	if(n >= e->nsec){
	  printk("botch: request for Shdr %d of %d", n, e->nsec);
	  nexuspanic();
	}

	// NXDEBUG HACK HACK HACK: this is a heuristic indicating a dirty file
	// that will confuse the parser
	if (!e->secdaddr || e->secdaddr > (1 << 24) || n > 100)
	  return NULL;

	off = fd + e->secdaddr + n*e->secentsize;
	h = (Elf32_Shdr*)off;
	ns = gcalloc(1, sizeof(ElfSec));
	assert(ns);

	if(s != NULL) {
	  assert(s->type == SHT_STRTAB);
	  ns->name = (char *)(fd + s->daddr + h->sh_name);
	}

	ns->type = h->sh_type;
	ns->flags = h->sh_flags;
	ns->vaddr = h->sh_addr;
	ns->daddr = h->sh_offset;
	ns->size = h->sh_size;
	ns->link = h->sh_link;
	ns->info = h->sh_info;
	ns->align = h->sh_addralign;
	ns->entsize = h->sh_entsize;
	return ns;
}

static u32 page_roundup(u32 addr) {
  return (addr + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;
}

static unsigned int stack_push(Map *uspace, char *data, int len, unsigned int *sp) {
  *sp -= len;
  poke_user(uspace, *sp, data, len);
  return *sp;
}

static unsigned int stack_push_string(Map *uspace, char *str, unsigned
				      int *sp) {
  char zero[1024];
  memset(zero, 0, sizeof(zero));
  /* align the stack */
  *sp = stack_push(uspace, zero, 1024 - ((strlen(str) + 1) % 1024), sp);
  return stack_push(uspace, str, strlen(str) + 1, sp);
}

static unsigned int stack_push_u32(Map *uspace, unsigned int data, unsigned int *sp) {
  return stack_push(uspace, (char*)&data, sizeof(data), sp);
}

unsigned int map_push_main_args(Map *uspace, unsigned int sp, int argc, char **argv) {
  // check the arguments for sanity

  unsigned int *push_argv = galloc((argc+1) * sizeof(unsigned int));
  push_argv[argc] = 0;
  int i;
  for (i = argc - 1; i >= 0; i--) {
    push_argv[i] = stack_push_string(uspace, argv[i], &sp);
  }

  unsigned int argv_ptr = stack_push(uspace, (char *)push_argv, (argc+1) * sizeof(unsigned int), &sp);
  assert(argv_ptr > 0);
  gfree(push_argv);
      
  stack_push_u32(uspace, argv_ptr, &sp);
  stack_push_u32(uspace, argc, &sp);
  sp -= 4; // return address
  return sp;
}

int dbg_sections = 0;
static inline void SET_READONLY(Map *uspace, 
				unsigned int rostart, unsigned int rolength){
  /* round up the start and down the length */
  if(rostart == 0)
    return;
  unsigned int rostartup = rostart + (rostart % PAGESIZE);
  unsigned int roenddown = rostart + rolength - ((rostart + rolength) % PAGESIZE);

  if(dbg_sections)printk_red("rounded 0x%x to 0x%x and 0x%x to 0x%x\n", 
			     rostart, rostartup, rostart + rolength, roenddown);


  if(rostartup != roenddown){
    if(dbg_sections)printk_red("setting read-only 0x%x -> 0x%x\n", 
			       rostartup, roenddown);
    Map_setProt(uspace, rostartup, roenddown - rostartup, PROT_READ);
    if(dbg_sections)printk_red("done\n");
  }
}
	    
UThread *elf_loadthread(char *file, Map* uspace, IPD *ipd, int len, int argc, char **argv) {
  unsigned char *toload=NULL;
  unsigned int entrypt;
  int offset, hdroff, tablesize;
  int i;
  u32 length, vaddr, vaddr2;

  ElfObj *e;
  ElfSeg *seg;
  ElfSec *section, *sstrtab;
  KShMem *user_kshmem = NULL;
  int output_kshmem = 0;

  if ((e = elfreadobj(file, len)) == NULL){
    printk("ELF file cannot be loaded\n");
    return NULL;
  }

  hdroff = e->segdaddr;
  entrypt = e->entry;

  tablesize = e->segentsize * e->nseg;

  // Allocate a page, shared by all threads, for CPU-specific kernel state.
  // The page is read/writable by app and kernel 
  {
    void *real_addr = (void *)
      map_page(uspace, ipd,
	       1, 1, 1,  // 1 page, writable, user-accessible
	       0, 0, // normal cache handling
	       KSHMEM_VADDR, 1);
    if(real_addr != (void *)KSHMEM_VADDR) {
      printk("Could not map kshmem\n");
      return NULL;
    }
    output_kshmem = 1;
    user_kshmem = (struct KShMem *) KSHMEM_VADDR;
    if(setup_syscall_stub(uspace) != 0) {
      printk_red("Could not copy in syscall stubs! (this error path leaks memory\n");
      return NULL;
    }
  }
  //map in a readonly page that has nexustime on it
  { 
    void *real_addr = (void *)
      remap_kernel_page_readonly(uspace, 1, NEXUSTIME_KVADDR, NEXUSTIME_VADDR);
    if(real_addr != (void *)NEXUSTIME_VADDR) {
      printk("Could not map nexustime\n");
      return NULL;
    }
  }

#if 0
  /* find symbols */
  int isec;
  for(isec=0; isec<e->nsec && !ipd->symtab; isec++){
    section = elfreadsec(file, e, NULL, isec);
    if (section->type == SHT_SYMTAB) {
      int i, n = section->size / sizeof(Elf32_Sym) - 1;
      if (n <= 0) {
	printk("Found symtab: empty\n");
      } else {
	printk("Found symtab: Loading %d symbols...\n", n);
	sstrtab = elfreadsec(file, e, NULL, section->link);
	SymTable *rtable = galloc(sizeof(SymTable) + (n+2)*sizeof(KSymbol));
	rtable->count = 1; // leave slot at start, filled in below
	Elf32_Sym *sym = (Elf32_Sym *)(file + section->daddr);
	int a_start = sym[1].st_value;
	int a_end = a_start;
	for (i = 1; i <= n; i++) {
	  if (ELF32_ST_TYPE(sym[i].st_info) != STT_FUNC) continue;
	  int a = sym[i].st_value;
	  if (a < a_start) a_start = a;
	  if (a > a_end) a_end = a;
	  rtable->syms[rtable->count].addr = (void *)a;
	  rtable->syms[rtable->count].name = (char *)(file + sstrtab->daddr + sym[i].st_name);
	  rtable->syms[rtable->count].type = ' ';
	  rtable->count++;
	}
	rtable->syms[0].addr = (void *)a_start;
	rtable->syms[0].name = "<start>";
	rtable->syms[0].type = ' ';
	rtable->syms[rtable->count].addr = (void *)a_end;
	rtable->syms[rtable->count].name = "<end>";
	rtable->syms[rtable->count].type = ' ';
	rtable->count++;
	symtable_sort(rtable);
	ipd->symtab = rtable;
      }
      gfree(section);
    }
  }
#endif

  //Map_initializeSegmentHash(uspace);

  // make sure that ElfSeg matches KShSegment
  assert(sizeof(*seg) == sizeof(KShSegment));
  if(output_kshmem) {
    // write out number of segments
    int num_segments = e->nseg;
    assert(sizeof(user_kshmem->num_segments) == sizeof(num_segments));
    poke_user(uspace, (__u32) &user_kshmem->num_segments,
	      &num_segments, sizeof(num_segments));
  }

  for(i=0; i<e->nseg; ++i){
    seg = elfreadseg(file, e, i, len);
    if(seg == NULL)
      return NULL;
    if(output_kshmem) {
      if(i < min((int)KSHSEGMENT_MAX_NUM, (int)e->nseg)) {
	poke_user(uspace, (__u32) &user_kshmem->segments[i], 
		  seg, sizeof(*seg));
      }
    }

    if((seg->type == PT_LOAD) && (seg->vlength > 0)) {
      offset = seg->daddr;
      length = seg->vlength; //mem size (file size is s->dlength);
      vaddr = seg->vaddr;

      toload = file + offset;

      u32 vaddroff = vaddr % PAGESIZE;
      u32 vaddr_page = vaddr - vaddroff;
      //u32 map_page_len = (length+PAGESIZE-1)/PAGESIZE;
      u32 map_page_len = (vaddr + length - vaddr_page + PAGESIZE-1) / 
	PAGESIZE;
      int user = 1;

      vaddr2 = map_page(uspace, ipd,
			map_page_len, (((seg->flags & PF_W) != 0) ? 1 : 0), 
			user, 0, 0, vaddr_page, 1);
      unsigned int baddr = 0x804bd30;
      if(dbg_sections)
	printk_red("mapping (orig %p, %p) 0x%x to 0x%x (including 0x%x) and setting writable bit to %d\n", 
		   (void *) vaddr, (void *)(vaddr_page),
		   vaddr2, vaddr2 + map_page_len * PAGESIZE, baddr, (((seg->flags & PF_W) != 0) ? 1 : 0));

      if((char *)toload + seg->dlength > file + len){
	printk("ELF read extends past end of file\n");
	return NULL;
      }

      if(poke_user(uspace, vaddr, toload, seg->dlength) < 0) {
	printk("Error during poke_user\n");
      }

      /* Figure out the vaddr range that should be read only.  Sections
       * aren't aligned on page boundaries or anything, so some parts of
       * read only sections will end up being read/write. */
      if(e->secstridx != SHN_UNDEF){
	unsigned int rostart = vaddr;
	int rolength = vaddroff;
	if(dbg_sections)printk("looking through sections for readonly...");
	sstrtab = elfreadsec(file, e, NULL, e->secstridx);
	int isec;
	for(isec=0; isec<e->nsec; isec++){
	  section = elfreadsec(file, e, sstrtab, isec);
	  if(dbg_sections)printk("section %d: %s 0x%lx %ld 0x%lx\n", isec, 
				 section->name, 
				 section->vaddr, 
				 section->size,
				 section->flags);
	
	  /* section is in segment */
	  if((section->vaddr >= vaddr) && (section->vaddr < vaddr + length)){
	    if((section->flags & SHF_WRITE) == 0){
	      if(rostart ==0)
		rostart = section->vaddr;
	      rolength = (section->vaddr + section->size) - rostart;
	      if(dbg_sections)
		printk("rostart is now 0x%x rolength %d\n", rostart, rolength);
	    }else{
	      SET_READONLY(uspace, rostart, rolength);
	      rostart = 0;
	      rolength = 0;
	    }
	  }
	  gfree(section);
	}
	gfree(sstrtab);
      }
    }
    gfree(seg);
  }

  Map_wholeHash(uspace, file, len);

  gfree(e);

 unsigned int sp;
 {
   // Set up stack
  __u32 stack_page_size = USERSTACKSIZE_MAIN_DEFAULT/PAGESIZE;
  __u32 stack_base = USERSTACKSTART_MAIN_DEFAULT;
  int alloc_stack_pages = 1;
  unsigned int stackstart;

  // Scan for .stack section
  {
    sstrtab = elfreadsec(file, e, NULL, e->secstridx);
    for(i=0; i<e->nsec; i++){
      section = elfreadsec(file, e, sstrtab, i);
      if(section) {
        if(section->name && strcmp(section->name, ".stack") == 0) {
	  stack_page_size = page_roundup(section->size) / PAGESIZE;
	  stack_base = section->vaddr;
	  alloc_stack_pages = 0;
	  break;
        }
        gfree(section);
      }
      else {
        printk_red("[elf] dirty file [%s]. skipping\n", argv[0]);
        return NULL;
      }
    }
    gfree(sstrtab);
  }

  switch(ipd->type) {
  case NATIVE:
    printkx(PK_SHELL, PK_DEBUG, "elf_loadthread: Allocating stack %d segs\n", e->nseg);
    if(alloc_stack_pages) {
      stackstart = map_page(uspace, ipd,
			    stack_page_size,
			    1, 1, 0, 0, 
			    stack_base, 1);
      // zero done by map_page
      // zero_fill_pages(uspace, stackstart, USERSTACKSIZE/PAGESIZE);
    } else {
      stackstart = stack_base;
    }
    sp = stackstart + stack_page_size * PAGESIZE - 16;
    sp = map_push_main_args(uspace, sp, argc, argv);
    break;
  default:
    sp = 0;
    printk("parseelf: unknown ipd type\n");
    nexuspanic();
  }
 }

 return nexusuthread_create(uspace, entrypt, sp, ipd, NULL, NULL);
}

extern KVKey_nsk *default_nsk;

IPD *ipd_fromELF(const char *ipd_name, char *file, int size, int ac, char **av, 
		 int background, UThread **uthread_p) {
  IPD *ipd = ipd_new();
  ipd_setName(ipd, ipd_name);

  if (background)
    ipd->background = 1;

  ipd->map = Map_new();
  ipd->map->owner = ipd;

  if (default_nsk)
    ipd_set_nsk(ipd, default_nsk);

  UThread *ret = elf_loadthread(file, ipd->map, ipd, size, ac, av);
  if (uthread_p)
    *uthread_p = ret;

  return ipd;
}

UThread *
elf_load(const char *filepath, int background, int ac, char **av) {
	UThread *uthread = NULL;
	IPD *ipd;
	char *file;
	int size;
	
	file = fetch_file((char *) filepath, &size);
	if (!file) {
		printk("Cannot execute %s: no such file\n", filepath);
		return NULL;
	}

#if 0 // for debug. XXX reenable when done
#ifndef NDEBUG
	printkx(PK_SHELL, PK_INFO, "Loading map file\n");
	const char *map_suffix = ".map";
	char *fname = galloc(strlen(filename) + strlen(map_suffix) + 1);
	strcpy(fname, filename);
	strcat(fname, map_suffix);
	SymTable *table = symtable_find(fname);
	if (!table)
		table = symtable_addNewFromFile(fname);
	gfree(fname);
#endif
#endif

	ipd = ipd_fromELF(filepath, file, size, ac, av, background, &uthread);
	gfree(file);

	return uthread;
}

BasicThread *shell_wait_thread;

// start a not-yet-run thread A, wait for return value of not-yet-run thread B
static int start_thread_and_wait(UThread *toStart, UThread *toWait) {
	nexusthread_get((BasicThread *)toWait); // prevent reaping until we get the return value
	toWait->waitsema = sema_new(); // exit routines will V() this
	nexusthread_start((BasicThread *)toStart, 0);
	shell_wait_thread = (BasicThread *)toWait;
	P(toWait->waitsema);
	shell_wait_thread = NULL;
	int exitval = toWait->exit_status;
	gfree(toWait->waitsema);
	toWait->waitsema = NULL;
	nexusthread_put((BasicThread *)toWait); // release for reaping
	return exitval;
}

/** Execute a file and @return its process id. */
int elf_exec(const char *filepath, unsigned long flags, int ac, char **av)
{
	UThread *ut;

	ut = elf_load(filepath, flags & PROCESS_BG ? 1 : 0, ac, av);
	if (!ut) 
		return -1;

	if (flags & PROCESS_QUIET)
		ut->ipd->quiet = 1;

	if (flags & PROCESS_WAIT)
	  return start_thread_and_wait(ut, ut);
	
	nexusthread_start((BasicThread *)ut, 0);
	return ut->ipd->id;
}

