/** NexusOS: kernelfs exposes information to userspace, 
             similar to profcs on Unix systems. 
 
  	     The implementation is nothing more than a set of wrappers around
             mkdir, write, ... that are applied to an in-memory filesystem. */

#include <nexus/defs.h>
#include <nexus/mem.h>
#include <nexus/thread.h>
#include <nexus/ipd.h>
#include <nexus/fs.h>
#include <nexus/tftp.h>
#include <nexus/kernelfs.h>
#include <nexus/ipc_private.h>
#include <nexus/FS.kernel-interface.h>
#include <nexus/RamFS.kernel-interface.h>

#include <libtcpa/tpm.h>

/** private variables set at initialization */
static FSID root, processes, ports, env, bin;

/** Create the root of the kernel filesystem */
void
kernelfs_init(void) 
{
  const char *file, *name;
  int size, i, nlen;

  // create the filesystem
  root = RamFS_new(KERNELFS_PORT);
  if (!FSID_isValid(root)) {
  	printkx(PK_KERNELFS, PK_WARN, "[kernelfs] could not start\n");
	return;
  }
  
  // open a client connection to the FS
  if (nexusfs_mount(FSID_EMPTY, root)) {
	  printkx(PK_KERNELFS, PK_WARN, "[kernelfs] failure at mount\n");
	  return;
  }
  
  // populate with initial standard directories
  processes = nexusfs_mkdir(root, "ipds");
  assert(FSID_isDir(processes));

  ports = nexusfs_mkdir(root, "ports");
  env = nexusfs_mkdir(root, "env");
  bin = nexusfs_mkdir(root, "bin");
  nexusfs_mkdir(root, "mnt");
  nexusfs_mk(env, "tcpa_version", "0.0.0.0");
  
  // populate with existing processes (using a callback function)
  void __kernelfs_init_ipd(void *item, void *unused) { 
	  KernelFS_addIPDNode((IPD *) item); 
  }
  ipd_iterate(__kernelfs_init_ipd, NULL);

  // populate with existing cache entries
  for (i = 0; ; i++) {
	file = cache_entry(i, &name, &size);
	if (file == (void *) -1)
		break;
	if (!file)
		continue;

	KernelFS_mk(name, file, size);
  }

  printkx(PK_KERNELFS, PK_INFO, "[kernelfs] up\n");
}

void KernelFS_mk(const char *name, const char *data, int dlen)
{
  FSID file;

  if (!FSID_isDir(root))
	  return;

  // HACK. see below
  if (nexusthread_current_ipd() != kernelIPD)
	  return;

  file = nexusfs_mk_bin(bin, name, (char *) data, dlen);
  if (!FSID_isFile(file)) 
	  printkx(PK_KERNELFS, PK_INFO, "[kernelfs] could not add %s\n", name);
}

void KernelFS_addIPDNode(IPD *ipd) {
  FSID dir;
  char name[32];
 
  // this function is called from console_init. pass
  if (!FSID_isDir(root))
	  return;

  // HACK. see below
  if (nexusthread_current_ipd() != kernelIPD)
	  return;

  sprintf(name, "%u", ipd->id);

  dir = nexusfs_mkdir(processes, name);
  if (!FSID_isValid(dir)) 
	  return;

  nexusfs_mk(dir, "name", ipd->name);
  nexusfs_mk(dir, "isdevice", ipd->isdevice ? "1" : "0");
}

/** Lookup a filesystem directory representing a process */
static FSID
__kernelfs_get_ipdnode(IPD *ipd)
{
	FSID node;
	char name[32];

	sprintf(name, "%u", ipd->id);
	return nexusfs_lookup(processes, name);
}

void KernelFS_add_IPCPort(IPC_Port *port) {
  FSID dir;
  char name[32];
  
  if (!FSID_isDir(root))
	  return;

  // HACK: because FS.svc:mounttable uses the same lookup structure from port to handle
  // regardless of IPD, it returns invalid handles for in-kernel servers.
  //
  // XXX fix that
  if (nexusthread_current_ipd() != kernelIPD)
	  return;

  assert(port->ipd);

  sprintf(name, "%u", port->port_num);
  dir = nexusfs_mkdir(ports, name);
  if (!FSID_isValid(dir)) 
	  return;

  // add hook for connections
  nexusfs_mkdir(dir, "connections");
  
  // point to owner process (should be a symlink)
  sprintf(name, "%u", port->ipd->id);
  nexusfs_mk(dir, "owner", name);
}

void KernelFS_del_IPCPort(IPC_Port *port) {
  FSID dir;
  char name[32];

  if (!FSID_isDir(root))
    return;

  // HACK. see above
  if (nexusthread_current_ipd() != kernelIPD)
	  return;

  dir = __kernelfs_get_ipdnode(port->ipd);
  if (!FSID_isValid(dir)) 
    return;

  sprintf(name, "%u", port->ipd->id);
  nexusfs_unlink(dir, name);
}

void KernelFS_IPCPort_addConnection(IPC_Port *port, IPC_Connection *connection) {
  FSID dir;
  char name[32];

  if (!FSID_isDir(root))
    return;

  // HACK. see above
  if (nexusthread_current_ipd() != kernelIPD)
	  return;

  if (connection->kernel)
    return; // don't display kernel connections

  dir = __kernelfs_get_ipdnode(port->ipd);
  if (!FSID_isValid(dir)) 
    return;
  dir = nexusfs_lookup(dir, "connections");
  if (!FSID_isValid(dir)) 
    return;

  sprintf(name, "%u-%u.%u", connection->source->id, 
	  connection->dest_port->ipd->id, connection->dest_port->port_num);

  nexusfs_mk(dir, name, strdup(name));
}

void
KernelFS_setenv_bin(char *name, char *value, int len) 
{
  if (!FSID_isDir(root))
    return;

  // HACK. see above
  if (nexusthread_current_ipd() != kernelIPD)
	  return;

  nexusfs_unlink(env, name);
  nexusfs_mk_bin(env, name, value, len);
  printkx(PK_KERNELFS, PK_INFO, "[kernelfs] env %s=(binary)\n", name);

}

void
KernelFS_setenv(char *name, char *value) 
{
  if (!FSID_isDir(root))
    return;
  
  // HACK. see above
  if (nexusthread_current_ipd() != kernelIPD)
	  return;


  nexusfs_unlink(env, name);
  nexusfs_mk(env, name, value);
  printkx(PK_KERNELFS, PK_INFO, "[kernelfs] env %s=%s\n", name,value);
}

