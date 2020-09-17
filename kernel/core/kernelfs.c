/** NexusOS: kernelfs exposes information to userspace, 
             similar to profcs on Unix systems. 
 
  	     The implementation is nothing more than a set of wrappers around
             mkdir, write, ... that are applied to an in-memory filesystem. */

#include <nexus/defs.h>
#include <nexus/mem.h>
#include <nexus/thread.h>
#include <nexus/ipd.h>
#include <nexus/fs.h>
#include <nexus/initrd.h>
#include <nexus/kernelfs.h>
#include <nexus/ipc_private.h>
#include <nexus/FS.kernel-interface.h>
#include <nexus/RamFS.kernel-interface.h>
#include <nexus/ProcFS.kernel-interface.h>

/** private variables set at initialization */
static FSID root, procfs, ports, bin, etc, dev;
extern struct HashTable *process_table;

/** Add an execute to /bin. 
    Used to populate from the initrd file.
    Duplicates memory use as initrd is not freed. XXX free initrd mem */
static void 
KernelFS_add_bin(const char *name, const char *data, int dlen)
{
  FSID file;

  if (!FSID_isDir(root))
	  return;

  file = nexusfs_mk_bin(bin, name, (char *) data, dlen);
  if (!FSID_isFile(file)) 
	  printkx(PK_KERNELFS, PK_INFO, "[ramfs] could not add %s\n", name);
}

/** Return the executable from /bin
    
    @param name is the name local to /bin
    @return is a region that the caller must free
  */
char * 
KernelFS_get_bin(const char *name, int *dlen)
{
  FSID file;
  char *buf;
  int size, ret;

  if (!FSID_isDir(root))
	  return NULL;

  // lookup inode
  file = nexusfs_lookup(bin, name);
  if (!FSID_isValid(file))
	  return NULL;

  // copy data
  size = FS_Size(file);
  buf = galloc(size);
  ret = FS_Read(file, 0, (struct VarLen) {.data = buf, .len = size}, size);
  if (ret != size) {
  	gfree(buf);
	printk("[fs] file read error\n");
	return NULL;
  }

  *dlen = size;
  return buf;
}

int KernelFS_add_initrd(void)
{
  struct InitRD_File *te;

  for (te = initrd_first(); te ; te = te->next) {
	  KernelFS_add_bin(te->name, te->data, te->len);
  	  printkx(PK_KERNELFS, PK_DEBUG, "[ramfs] added %s (%dB)\n", 
	  	  te->name, te->len);

  }
  return 0;
}

////////  process-specific procfs callbacks  ////////

/** return process data. data returned is page aligned (and thus max 4kB)
    @param is a virtual address in the process's address space
           note that as it is an int, it can only addres 31bits >0 */
static int
procfs_read_mem(struct dnode *dnode, char *buf, int off, int len)
{
	unsigned long vaddr, paddr, kvaddr, pgoff;
	IPD *ipd;

	// lookup process
	ipd = ipd_find((long) dnode->priv);
	if (!ipd)
		return -1;
	
	// validate input
	if (off < 0 || len < 0)
		return -1;

	// lookup page
	vaddr  = off & (PAGE_SIZE - 1);
	pgoff  = off - vaddr;
	paddr  = fast_virtToPhys(ipd->map, vaddr, 1, 0);
	if (!paddr)
		return -1;
	kvaddr = PHYS_TO_VIRT(paddr);

	printk("NXDEBUG readmem pid=%d vaddr=%lx paddr=%lx kvaddr=%lx\n",
			ipd->id, vaddr, paddr, kvaddr);
	
	// XXX DEBUG REMOVE
	return -1;

	len = min(len, (int) (PAGESIZE - pgoff));
	memcpy(buf, (void *) kvaddr + pgoff, len);
	return len;
}

/** procfs callback for dirs that correspond to process IDs 
    NOT multithread safe, because it returns a static node
    NOT safe wrt removal of IPDs
 */
static struct dnode * 
procfs_readdir_pid(struct dnode *dir, int n)
{
	static struct dnode child;
	IPD *ipd;
	int pid;

	pid = atoi(dir->name);
	ipd = ipd_find(pid);
	if (!ipd)
		return NULL;

	memset(&child, 0, sizeof(child));
	
	// iterate over nodes. 
	switch (n) {
		// name
		case 0:
			child.name = "name";
			child.priv = ipd->name;
			child.file.read = procfs_read_string;
		break;
		// sha1
		case 1:
			child.name = "sha1";
			child.priv = (void *) ipd->sha1;
			child.priv2= 20;
			child.file.read = procfs_read_bin;
		break;
		// mem
		case 2:
			child.name = "mem";
			child.priv = (void *) ipd->id;
			child.file.read = procfs_read_mem;
		break;
		// reference monitor port, if any
		case 3:
			child.name = "refmon";
			child.priv = (void *) ipd->refmon_port;
			child.file.read = procfs_read_int;
		break;
		// reference monitor decision cache, if any
		case 4:
			child.name = "rcache";
			child.priv = (void *) ipd->refmon_cache;
			child.priv2= ipd->refmon_cache_pglen << 12;
			child.file.read = procfs_read_bin;
		break;
		// NB: UPDATE end-of-list counter below when extending
		// error
		default: return NULL;
	};

	// only last one has no ->next to signal end of list
	if (n < 4)
		child.next = &child;

	return &child;
}

/** procfs callback for ipc ports
    @param dir->name is interpreted as a port number
    NOT multithread safe, because it returns a static node */
static struct dnode *
procfs_readdir_port(struct dnode *dir, int n)
{
	static struct dnode child;
	long portnum;
	IPC_Port *port;

	portnum = atoi(dir->name);
	port = IPCPort_find(portnum);
	if (!port)
		return NULL;

	switch (n) {
		case 0: child.name = "owner";
			child.file.read = procfs_read_int;
			
			if (port->kernel_call_handler)
				child.priv = (void *) 0;
			else
				child.priv = (void *) port->ipd->id;
		break;
		default: return NULL;
	}

	return &child;
}

/** Treat a hashtable key as a struct nxguard_object
    dnode->name will point to the tuple */
struct dnode *
procfs_readdir_hash_object(struct dnode *parent, int n)
{
	struct nxguard_object *obj;
	static char namebuf[64];
	struct dnode *dnode;

printk_red("readhash %d\n", n);
	dnode = procfs_readdir_hash_string(parent, n);
printk_red("readhash %d\n", n);
	if (dnode) {
		//obj = (void *) dnode->name;
		//assert(obj);
		//snprintf(namebuf, 63, "%llu.%llu", 
		//	 obj->upper, obj->lower);
		dnode->name = "hello";
	}
	return dnode;
}

/** Create the root of the kernel filesystem */
void
kernelfs_init(void) 
{
  FSID var, inode;
  struct dnode *sys, *guard, *cur;
  const char *file, *name;
  int size, i, nlen;

  // create the filesystem
  root = RamFS_new(KERNELFS_PORT);
  if (!FSID_isValid(root))
  	nexuspanic();
  
  // open a client connection to the FS
  if (nexusfs_mount(FSID_EMPTY, root))
  	nexuspanic();
  
  //// populate with initial standard directories
  
  // procfs
  procfs = 	nexusfs_mkdir(root, "proc");
  
  // dynamic (XXX structures should be locked during access)
  procfs_init(procfs);
  procfs_createdir_exdir(NULL, "pid", process_table, 
		         procfs_readdir_hash_int, procfs_readdir_pid);
  procfs_createdir_exdir(NULL, "port", porttable, 
		         procfs_readdir_hash_int, procfs_readdir_port);
  
  // procfs: system (hardware)
  sys = procfs_createdir(NULL, "sys");
  cur = procfs_createfile(sys, "meminfo", procfs_read_int, NULL);
  cur->priv = (void *) (((maxframenum + 1) << PAGE_SHIFT) >> 20);

  // procfs: os
  guard = procfs_createdir(NULL, "guard");
  cur = procfs_createfile(guard, "cache", procfs_read_bin, NULL);
  cur->priv = guard_cache;
  cur->priv2 = nxkguard_getsize();

  // XXX debug: crashes during readdir in readdir_hash_string:hash_findByIndex
  //procfs_createdir_exdir(guard, "port", guard_porttable, 
  //		         procfs_readdir_hash_object, NULL);
  
  // etc
  etc = nexusfs_mkdir(root, "etc");
  nexusfs_mk(etc, "passwd", "root::0:0:root:/:/bin/explorer.app\n");

  // dev
  dev = nexusfs_mkdir(root, "dev");
  assert(FSID_isDir(dev));
  
  // make a 1MB ramdisk /dev/ram0
  inode = nexusfs_mk(dev, "ram0", "");
  FS_Write(inode, 1 << 20, (struct VarLen) {.data = "t", .len = 1}, 1);	

  // other
  bin = nexusfs_mkdir(root, "bin");
  nexusfs_mkdir(root, "mnt");
  nexusfs_mkdir(root, "usr");
  var = nexusfs_mkdir(root, "var");
  nexusfs_mkdir(var, "auth");
  nexusfs_mkdir(var, "log");
  inode = nexusfs_mkdir(root, "tmp");

  // populate /bin with files in initrd
  KernelFS_add_initrd();

  printkx(PK_KERNELFS, PK_INFO, "[ramfs] up\n");
}

