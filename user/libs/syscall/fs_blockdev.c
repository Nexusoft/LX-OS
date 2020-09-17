/** NexusOS: nxblock block-mode IO interface 
 
    Device inodes present a sequential file interface. This code implements a
    random-access block interface on top of that. It is meant to be 
    considerably faster than repeated lseek()/read() calls, but is a bit
    overengineered, to be honest. 

    The two main features are that (1) requests are written in descriptors and
    a client can send up to a page of requests at once to the server and (2)
    memory referenced in descriptors is mapped by the client into the server's
    address space using Mem_Share_Page (an odd interface). The server has to
    allow others to share pages in this way through Mem_Grant_Pages.

    WARNING: currently, the system (likely) does not handle the case where 
    the same page is shared multiple times using Mem_Share_Page. Do NOT do
    this. At present, all requests consist of a single descriptor, precluding
    multiple insertions of the same page into the server's memory map.

    HACKS to get dinesh up and running XXX FIX
    - check all DO_FIXED
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <nexus/defs.h>
#include <nexus/block.h>
#include <nexus/fs.h>
#include <nexus/ipc.h>

#include <nexus/FS.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Mem.interface.h>

/// block-mode IO commands (mutually exclusive)
#define NXBLOCK_READ	0x1
#define NXBLOCK_WRITE	0x2
#define SECTORSIZE 512

/// block-mode IO descriptor
struct nxblock_desc {
	int 		cmd:4;	
	int 		next:1;		///< if 1: another descriptor follows 
	int		port;		///< ipc port to send reply on

	unsigned long	addr;		///< address in caller VM
	unsigned long	off;		///< offset IN 512B SECTORS
	unsigned long	len;		///< length IN 512B SECTORS
};


//////// client: serialize requests

// get replies. XXX a single static port is ugly.
static int client_port = -1;

/** Open the device inode and corresponding IPC port */
int nxblock_client_open(const char *filepath)
{
	long port;
	int fd;

#ifdef BROKEN
	fd = open(filepath, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "blockdev failed to open file %s\n", filepath);
		return -1;
	}

	// read the embedded ipc port number
	if (read(fd, &port, sizeof(port)) != sizeof(port)) {
		fprintf(stderr, "blockdev failed to read portnumber\n");
		return -1;
	}
	if (close(fd)) {
		fprintf(stderr, "blockdev close failed\n");
		return -1;
	}
#else
	port = blockdev_port;
#endif

	if (client_port == -1) {
		client_port = IPC_CreatePort(0);
		if (client_port < 0) {
			fprintf(stderr, "blockdev port acquire failed\n");
			return -1;
		}
	}

	return port;
}

int nxblock_client_close(int fd)
{
	// XXX close filedescriptor here instead of in open()
	return 0;
}

/** common implementation of read and write interfaces */
static int 
nxblock_client_readwrite(int fd, void *data, int dlen, unsigned long dev_off, int do_read)
{
	// ugly hack. 
	// WARNING: can only talk to one blockdevice process at a time as a result
	static int server_pid;

	struct nxblock_desc desc;
	unsigned long _data = (unsigned long) data;
	unsigned long srvaddr, handled;

	// currently restricted to single page-aligned 512 byte sectors
	// NB: now DMA supports multiple PAGES
#if 0
	if (dlen != 1) {
		fprintf(stderr, "bdev: region exceeds single sector\n");
		return -1;
	}
	if (((_data >> 12) != ((_data + 512) >> 12))) {
		//fprintf(stderr, "bdev: region crosses pages (%lx %lx)\n", _data, _data + 512);
		return -1;
	}
#endif

	// lookup server
	if (!server_pid) {
		server_pid = IPC_Server(fd);
		if (!server_pid) {
			fprintf(stderr, "bdev: server lookup\n");
			return -1;
		}
	}

	// share underlying page
	srvaddr = Mem_Share_Pages(server_pid, _data & ~0xfff, dlen, do_read ? 1 : 0);
	if (!srvaddr) {
		fprintf(stderr, "bdev: failed to share page with server\n");
		return -1;
	}
	
	desc.cmd = do_read ? NXBLOCK_READ : NXBLOCK_WRITE;
	desc.next = 0;	// XXX support writev/readv and transfer request chains

	desc.addr = srvaddr + (_data & 0xfff);
	desc.len = dlen;
	desc.off = dev_off;
	desc.port = client_port;

	if (ipc_send(fd, &desc, sizeof(desc))) {
		fprintf(stderr, "blockdev send header failed\n");
		return -1;
	}

	if (ipc_recv(client_port, &handled, sizeof(handled)) != sizeof(handled)) {
		fprintf(stderr, "blockdev recv reply failed\n");
		return -1;
	}

	// eventually, support more than 1 request per ipc send/recv pair
	if (handled != 1) {
		fprintf(stderr, "blockdev request failed (%ld)\n", handled);
		return -1;
	}

        //printf("Returning %d bytes\n", desc.len);
	return desc.len;
}

/** Write dlen bytes at offset dev_off */
int nxblock_client_write(int fd, const void *data, int dlen, unsigned long dev_off)
{
	return nxblock_client_readwrite(fd, (void *) data, dlen, dev_off, 0);
}

/** Read at most dlen bytes at offset dev_off */
int nxblock_client_read(int fd, void *data, int dlen, unsigned long dev_off)
{
	return nxblock_client_readwrite(fd, (void *)data, dlen, dev_off, 1);
}


//////// server: demultiplex requests

int nxblock_server_register(const char *filename)
{
	FSID parent, node;
	int ipc_port;

	// find /dev
	parent = nexusfs_lookup(FSID_ROOT(KERNELFS_PORT),  "dev");
	if (!FSID_isDir(parent)) {
		fprintf(stderr, "[ide] failed to find device dir #2\n");
		return -1;
	}

	// acquire an IPC port
#ifdef BROKEN
	ipc_port = IPC_CreatePort(0);
#else
	ipc_port = IPC_CreatePort(blockdev_port);
#endif
	if (ipc_port < 0) {
		fprintf(stderr, "[ide] failed to acquire port\n");
		return -1;
	}

	// register port at /dev/<filename>
	node = nexusfs_mk_dev(parent, filename, ipc_port);
	if (!FSID_isDev(node)) {
		IPC_DestroyPort(ipc_port);
		fprintf(stderr, "[ide] failed to register inode\n");
		return -1;
	}
  
	// allow other processes to map their memory into our address space
	Mem_Set_GrantPages(100);
	return ipc_port;
}

void nxblock_server_unregister(int ipc_port)
{
	IPC_DestroyPort(ipc_port);
	// XXX unlink inode
}

/// handle a request arriving over IPC
int nxblock_server_serve(int ipc_port, struct nxblock_device_ops *ops)
{
	struct nxblock_desc *desc;
	void *mem[PAGESIZE];
	unsigned long ret, total;
	int caller;

	// wait for request
	IPC_RecvFrom(ipc_port, (char *) mem, PAGESIZE, &caller);

	// demux request
	desc = (struct nxblock_desc *) mem;
	total = 0;
	do {

		switch (desc->cmd) {
			case NXBLOCK_READ: 	ret = ops->read(desc->addr, desc->off, desc->len); break;
			case NXBLOCK_WRITE:	ret = ops->write(desc->addr, desc->off, desc->len); break;
			default:		fprintf(stderr,"[ide] illegal request %x\n", desc->cmd);
						ret = -1;
		};

		if (ret < 0) {
			total = -1;
			break;
		}

		total++;
	} while ((desc++)->next && desc < (struct nxblock_desc *) (mem + PAGESIZE));

	// unmap request pages
	desc = (struct nxblock_desc *) mem;
	do {
		// WARNING: always unmapping, could cause duplicate unmap if 
		//          two descriptors point to the same page
		Mem_FreePages(desc->addr & ~0xfff, desc->len);
		Mem_Set_GrantPages(-desc->len); // increase the number of available grantpages
	} while ((desc++)->next && desc < (struct nxblock_desc *) (mem + PAGESIZE));

	// return reply: total number of requests handled, or -1 on error
	desc = (struct nxblock_desc *) mem;
	if (ipc_send(desc->port, &total, sizeof(unsigned long)))
		return 1;

	return 0;
}

