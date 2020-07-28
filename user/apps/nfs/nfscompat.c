#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>

#include <linux/compiler.h>

#include <nexus/util.h>
#include <nexus/hashtable.h>
#include <nexus/dlist.h>
#include <nexus/fs.h>
#include <nexus/ipc.h>
#include <nexus/idl.h>
#include <nexus/debug.h>
#include <nexus/FS.interface.h>
#include <nexus/Net.interface.h>
#include <nexus/IPC.interface.h>

#include "nfs.h"

static int debug = 1;
static int rdebug = 0;

static int nfscompat_port_handle;

/** Insert an NFS node in the filesystem: 
    create a mapping from nfs_node to FSID */
static FSID node2fsid(struct nfs_node **node) {
	struct nfs_node *repl;
	int id, type;
	
	repl = fh_canonical(*node, &id);
	type = (repl->type == NFS_REGULAR_FILE ? FS_NODE_FILE : FS_NODE_DIR);
	*node = repl;
	
	return (FSID) { .port = nfscompat_port_handle, .nodetype = type, .nodeid = id };
}

static struct nfs_node *fsid2node(FSID fsid) {
	return fh_get((int)fsid.nodeid);
}

/** Lookup an NFS node by FSID */
struct nfs_node *fsid_get0(FSID fsid, char *__file__, int __line__) {
	if (fsid.nodetype == FS_NODE_DIR && fsid.nodeid == 0)
		return &root_node;
	struct nfs_node *node = fsid2node(fsid);
	if (!node) {
		printf("[%s:%d] warning: could not find node for ", __file__, __line__);
		FSID_print(fsid);
		printf("\n");
	}
	return node;
}
#define fsid_get(fsid) fsid_get0(fsid, __FILE__, __LINE__);

// Pin -- not implemented

// Unpin -- not implemented

FSID nfscompat_Create_Handler(Call_Handle call_handle,
		FSID parent_node, struct VarLen node_name, int nodeType)
{
	char filename[MAX_FNAME_LEN+1];
	if(node_name.len > MAX_FNAME_LEN) {
		if (debug) printf("create(<%d>, ...) = error (name too long)\n", (int)parent_node.nodeid);
		return FSID_ERROR(FS_INVALID);
	}
	if(IPC_TransferFrom(call_handle, node_name.desc_num,
				filename, (unsigned) node_name.data, node_name.len) != 0) {
		if (debug) printf("create(<%d>, ...) = error (name not accessible)\n", (int)parent_node.nodeid);
		return FSID_ERROR(FS_ACCESSERROR);
	}
	filename[node_name.len] = '\0';

	struct nfs_node *parent = fsid_get(parent_node);
	if (!parent) {
		if (debug) printf("create(<%d>, %s) = error (invalid parent handle)\n", (int)parent_node.nodeid, filename);
		return FSID_ERROR(FS_INVALID);
	}

	struct nfs_node *node = NULL;
	if (nodeType == FS_NODE_FILE) {
		node = nfs_create(parent, filename, 1 /*overwrite */);
	} else if (nodeType == FS_NODE_DIR) {
		printf("nfs_mkdir not yet implemented\n");
		//nfs_node *node = nfs_mkdir(*parent, filename); // not yet implemented
	} else {
		printf("nfs can only create FILE or DIR\n");
	}

	if (!node) {
		if (debug) printf("create(<%d>, %s) = error\n", (int)parent_node.nodeid, filename);
		return FSID_ERROR(FS_INVALID);
	}

	FSID rc = node2fsid(&node);
	if (debug) printf("create(<%d>, %s) = <%d>\n", (int)parent_node.nodeid, filename, (int)rc.nodeid);
	return rc;
}

static int nfscompat_ReadDir_Handler(Call_Handle call_handle,
		FSID target_node, struct VarLen dest, int offset)
{
	// HACK: we save the active NFS readdir cookie here. 
	// As a result we cannot support
	// parallel, interleaving, readdir callers. XXX fix.
	static struct nfs_readdir_cookie active_cookie;
	static char *active_res;			///< result from NFS, cached.
	static int active_off, active_count;		///< pointers into current resultset
	static int active_dir;

	struct nfs_node *node; 
	char itemcopy[255];
	char *item;
	int bytelen, eod, ilen, ioff;
	
	node = fsid_get(target_node);
	if (!node) {
		if (debug) printf("mread(<%d>) = error (invalid handle)\n", (int)target_node.nodeid);
		return -FS_ACCESSERROR;
	}

	// initialize on first call
	if (!active_count) {
		// already in use? block parallel access
		if (active_cookie.cookie) { 
			printf("[nfs] blocked parallel readdir\n");
			return -FS_ACCESSERROR;
		}
		memset(&active_cookie, 0, sizeof(active_cookie));
	}


	// ask NFS server for the next set of results
	if (active_off == active_count) {
		// issue the NFS readdir request
		active_off = active_count = 0;
		active_res = nfs_readdir(node, &bytelen, &active_cookie, &active_count, &eod);
		if (!active_res) {
			if (debug) printf("mread(<%d>) = error\n", (int)target_node.nodeid);
			return -FS_INVALID;
		}
		if (!active_count) {
			free(active_res);
			active_res = NULL;
			return 0;
		}
	}

    // fast forward to the next entry
    item = active_res + 8;
    ilen = strlen(item) + 1;
    for (ioff = 0; ioff < active_off; ioff++) {
      item += ilen + 8;
      ilen = strlen(item) + 1;
    }

    // will the name fit?
    if (dest.len < ilen) {
	printf("[nfs] insufficient room for readdir result\n");
    	return -FS_INVALID;
    }

    // transfer name
    if (IPC_TransferTo(call_handle, dest.desc_num, (unsigned int) dest.data, item, ilen))
	return -FS_INVALID;

    active_off++;

    // last element in this transfer
    if (active_off == active_count) {
      free(active_res);
      active_res = NULL;
      // last element overall
      if (eod) {
	      active_off = active_count = 0;
	      memset(&active_cookie, 0, sizeof(active_cookie));
	      return 0;
      }
    }

    return 1;
}

static int nfscompat_Read_Handler(Call_Handle call_handle,
		FSID target_node, int file_position, struct VarLen dest, int count)
{
	struct nfs_node *node = fsid_get(target_node);
	if (!node) {
	  if (rdebug) printf("read(<%d>, %d) = error (invalid handle)\n", (int)target_node.nodeid, count);
	  return -FS_NOTFOUND;
	}
	if (count < 0) {
	  if (rdebug) printf("read(<%d>, %d) = error (invalid count)\n", (int)target_node.nodeid, count);
	  return -FS_INVALID;
	}
	if (file_position < 0) {
	  if (rdebug) printf("read(<%d>, %d) = error (invalid file position)\n", (int)target_node.nodeid, count);
	  return -FS_INVALID;
	}

	int maxcount = count;
	if (file_position == node->size) {
	  if (rdebug) printf("read(<%d>, %d) = eof\n", (int)target_node.nodeid, count);
	  return 0; //end of file
	}
	if (file_position > node->size) {
	  if (rdebug) printf("read(<%d>, %d) = error (past eof)\n", (int)target_node.nodeid, count);
	  return -FS_INVALID;
	}
	if (file_position + count > node->size)
	  maxcount = node->size - file_position;

	int totread = 0;
	do {
	  int readlen = maxcount - totread;
	  char *data = cache_read(node, file_position, &readlen);
	  if (!data) {
	    if (rdebug) printf("read(<%d>, %d) = %d bytes (then error)\n", (int)target_node.nodeid, count, totread);
	    return  (totread > 0 ? totread : -1);
	  }
	  if (!readlen) break; // end of file
	  assert(readlen > 0);

	  if (rdebug) printf("sending %d bytes of %d (%d): offset %d\n", readlen, maxcount, count, totread);

	  if(IPC_TransferTo(call_handle, dest.desc_num,
				  (unsigned)dest.data + totread,
				  data, readlen) != 0) {
	    if (rdebug) printf("read(<%d>, %d) = error (access error)\n", (int)target_node.nodeid, count);
	    return -FS_ACCESSERROR;
	  }
	  totread += readlen;
	  file_position += readlen;
	} while (totread < maxcount);
	//free(data);
	if (rdebug) printf("read(<%d>, %d) = %d bytes\n", (int)target_node.nodeid, count, totread);
	return totread;
}

static int nfscompat_Write_Handler(Call_Handle call_handle,
		FSID target_node, int file_position, struct VarLen source, int count)
{
	struct nfs_node *node = fsid_get(target_node);
	if (!node) {
		if (debug) printf("write(<%d>, ..., %d) = error (invalid handle)\n", (int)target_node.nodeid, count);
		return -FS_NOTFOUND;
	}
	if (count <= 0) {
		if (debug) printf("write(<%d>, ..., %d) = error (invalid count)\n", (int)target_node.nodeid, count);
		return -FS_INVALID;
	}

	int totwrite = 0;
	do {
	  int writelen = count - totwrite;
	  char *data = cache_startwrite(node, file_position, &writelen);
	  if (!data) {
	    if (debug) printf("write(<%d>, ..., %d) = %d bytes (then error)\n", (int)target_node.nodeid, count, totwrite);
	    return  (totwrite > 0 ? totwrite : -1);
	  }
	  assert(writelen > 0);

	  if (IPC_TransferFrom(call_handle, source.desc_num,
				data, (unsigned)source.data + totwrite, writelen) != 0) {
		if (debug) printf("write(<%d>, ..., %d) = error (access error)\n", (int)target_node.nodeid, count);
		assert(0); // ugh. can't tell how much of buffer was overwritten by TransferFrom
		return -FS_ACCESSERROR;
	  }
	  cache_endwrite(node, file_position, writelen);
	  totwrite += writelen;
	  file_position += writelen;
	} while (totwrite < count);

	if (debug) printf("write(<%d>, ..., %d) = %d bytes\n", (int)target_node.nodeid, count, totwrite);
	return totwrite;
}


static int nfscompat_Truncate_Handler(Call_Handle call_handle,
		FSID target_node, int target_len)
{
	struct nfs_node *node = fsid_get(target_node);
	if (!node) {
		if (debug) printf("truncate(<%d>, %d) = error (invalid handle)\n", (int)target_node.nodeid, target_len);
		return -FS_NOTFOUND;
	}

	cache_discard(node);
	node->size = target_len;

	if (nfs_set_attr(node, target_len) < 0) {
		if (debug) printf("truncate(<%d>, %d) = error\n", (int)target_node.nodeid, target_len);
		return -1;
	}

	if (debug) printf("truncate(<%d>, %d) = ok\n", (int)target_node.nodeid, target_len);
	return target_len;
}

static int nfscompat_Sync_Handler(Call_Handle call_handle,
		FSID target_node)
{
	struct nfs_node *node = fsid_get(target_node);
	if (!node) {
		if (debug) printf("sync(<%d>) = error (invalid handle)\n", (int)target_node.nodeid);
		return -FS_NOTFOUND;
	}

	cache_commit(node);

	if (debug) printf("sync(<%d>) = %d\n", (int)target_node.nodeid, 0);
	return 0;
}

static int nfscompat_Size_Handler(Call_Handle call_handle,
		FSID target_node)
{
	struct nfs_node *node = fsid_get(target_node);
	if (!node) {
		if (debug) printf("size(<%d>) = error (invalid handle)\n", (int)target_node.nodeid);
		return -FS_NOTFOUND;
	}

	if (debug) printf("size(<%d>) = %d\n", (int)target_node.nodeid, (int)node->size);
	return (int)node->size;
}

static FSID nfscompat_Lookup_Handler(Call_Handle call_handle,
		FSID parent_node, struct VarLen node_name)
{
	struct nfs_node *parent = fsid_get(parent_node);
	if (!parent) {
		if (debug) printf("lookup(<%d>, ...) = error (invalid parent handle)\n", (int)parent_node.nodeid);
		return FSID_ERROR(FS_NOTFOUND);
	}

	char filename[MAX_FNAME_LEN+1];
	if(node_name.len > MAX_FNAME_LEN) {
		if (debug) printf("lookup(<%d>, ...) = error (file name too long)\n", (int)parent_node.nodeid);
		return FSID_ERROR(FS_INVALID);
	}
	if(IPC_TransferFrom(call_handle, node_name.desc_num,
				filename, (unsigned) node_name.data, node_name.len) != 0) {
		if (debug) printf("lookup(<%d>, ...) = error (name not accessible)\n", (int)parent_node.nodeid);
		return FSID_ERROR(FS_ACCESSERROR);
	}
	filename[node_name.len] = '\0';

	struct nfs_node *node;
	FSID nodeid;
	// ugh: filename may have embedded slashes (but hopefully no dots?)
	char *basename = filename;
	char *slash;
	do {
		slash = strchr(basename, '/');
		if (slash) *slash = '\0';
		struct nfs_node *node = nfs_lookup(parent, basename);
		if (!node) {
			if (debug) printf("lookup(<%d>, %s) = error\n", (int)parent_node.nodeid, filename);
			return FSID_ERROR(FS_INVALID);
		}
		nodeid = node2fsid(&node);
		if (debug) printf("lookup(<%d>, %s) = <%d>\n", (int)parent_node.nodeid, filename, (int)nodeid.nodeid);
		if (slash) {
			*slash = '/';
			basename = slash+1;
			parent = node;
		}
	} while (slash != NULL && basename[0]); // stops on trailing slash too

	return nodeid;
}

static int nfscompat_Unlink_Handler(Call_Handle call_handle,
		FSID parent_node, FSID src_node)
{
	struct nfs_node *parent = fsid_get(parent_node);
	if (!parent) {
		if (debug) printf("unlink(<%d>, <%d>) = error (invalid parent handle)\n",
				(int)parent_node.nodeid, (int)src_node.nodeid);
		return -FS_NOTFOUND;
	}
	struct nfs_node *node = fsid_get(src_node);
	if (!node) {
		if (debug) printf("unlink(<%d>, <%d>) = error (invalid target handle)\n",
				(int)parent_node.nodeid, (int)src_node.nodeid);
		return -FS_NOTFOUND;
	}

	/*
	if (node->parent != parent) {
		if (debug) printf("unlink(<%d>, <%d>) = error (target is not a child of parent)\n",
				(int)parent_node.nodeid, (int)src_node.nodeid);
		return -FS_INVALID;
	}
	*/

	cache_free(node); // needed in case file is linked elsewhere

	if (nfs_remove(parent, node->name) != 0) {
		if (debug) printf("remove(<%d>, <%d>) = error\n", (int)parent_node.nodeid, (int)src_node.nodeid);
		return -FS_INVALID;
	}

	if (debug) printf("remove(<%d>, <%d>) = ok\n", (int)parent_node.nodeid, (int)src_node.nodeid);

	// remove the item from the inode cache? todo maybe later
	return 0;
}


void nfscompat_processNextCommand(void) {
	char dataBuf[1024]; /* XXX Make this variable length */
	int max_dataLen = 1024;
	int dataLen = max_dataLen;

	Call_Handle call_handle;
	CallDescriptor cdesc;
	int call_result;

	call_result = IPC_RecvCall(nfscompat_port_handle, dataBuf, &dataLen, &cdesc);
	call_handle = (call_result == 0 ? cdesc.call_handle : call_result);
	// IPD_ID ipd_id = cdesc.ipd_id; // unused

	if (call_result < 0)
		return;

	if(dataLen < sizeof(int)) {
		printf("IPC does not contain command ordinal\n");
		int error = -INTERFACE_MALFORMEDREQUEST;
		IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&error, sizeof(error));
		IPC_CallReturn(call_handle);
		return;
	}
	dataLen -= sizeof(int);

	struct FS_Pin_Result no_op = { .resultCode = INTERFACE_SUCCESS, .rv = 0 };
	struct FS_Pin_Result not_impl = { .resultCode = INTERFACE_SUCCESS, .rv = -FS_UNSUPPORTED };
	int malformed = -INTERFACE_MALFORMEDREQUEST;

	char *inBuf = dataBuf + sizeof(int);
	switch(*(int *)dataBuf) {
		case SYS_FS_Pin_CMD: // todo: implement Pin and Unpin for nfs
		case SYS_FS_Unpin_CMD:
			{
				IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&no_op, sizeof(no_op));
				IPC_CallReturn(call_handle);
				break;
			}
		case SYS_FS_Mount_CMD:
		case SYS_FS_Unmount_CMD:
			{
				IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&not_impl, sizeof(not_impl));
				IPC_CallReturn(call_handle);
				return;
			}
		case SYS_FS_Sync_CMD:
			{
				const char *funcname;
				funcname = "SYS_FS_Sync_CMD";
				FSID target_node;
				if(dataLen < sizeof(*((struct FS_Sync_Args *) inBuf))) {
					printf("Source buffer length incorrect %d %d(%s:%d)\n",  dataLen, sizeof(*((struct FS_Sync_Args *) inBuf)), __FILE__, __LINE__);
					IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
					IPC_CallReturn(call_handle);
					break;
				}
				{
					int __computedLen;
					int __varPos = 0;
					__varPos = __varPos; // suppress warning
					__computedLen = __varPos + sizeof(*((struct FS_Sync_Args *) inBuf));
					if(__computedLen != dataLen) {
						printf("%s: Computed length incorrect %d %d\n", funcname, __computedLen, dataLen);
						IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
						IPC_CallReturn(call_handle);
						break;
					}
				}
				int __varPos = 0;
				__varPos = __varPos; // suppress warning
				memcpy(&target_node, &((struct FS_Sync_Args *) inBuf)->target_node, sizeof(target_node));
				struct FS_Sync_Result rbuf;
				rbuf.resultCode = INTERFACE_SUCCESS;
				rbuf.rv = nfscompat_Sync_Handler(call_handle, target_node);
				IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&rbuf, sizeof(rbuf));
				IPC_CallReturn(call_handle);
				break;
			}
		case SYS_FS_Create_CMD:
			{
				const char *funcname;
				funcname = "SYS_FS_Create_CMD";
				FSID parent_node;
				struct VarLen node_name;
				int nodeType;
				if(dataLen < sizeof(*((struct FS_Create_Args *) inBuf))) {
					printf("Source buffer length incorrect %d %d(%s:%d)\n",  dataLen, sizeof(*((struct FS_Create_Args *) inBuf)), __FILE__, __LINE__);
					IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
					IPC_CallReturn(call_handle);
					break;
				}
				{
					int __computedLen;
					int __varPos = 0;
					__varPos = __varPos; // suppress warning
					__computedLen = __varPos + sizeof(*((struct FS_Create_Args *) inBuf));
					if(__computedLen != dataLen) {
						printf("%s: Computed length incorrect %d %d\n", funcname, __computedLen, dataLen);
						IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
						IPC_CallReturn(call_handle);
						break;
					}
				}
				int __varPos = 0;
				__varPos = __varPos; // suppress warning
				memcpy(&parent_node, &((struct FS_Create_Args *) inBuf)->parent_node, sizeof(parent_node));
				memcpy(&node_name, &((struct FS_Create_Args *) inBuf)->node_name, sizeof(node_name));
				memcpy(&nodeType, &((struct FS_Create_Args *) inBuf)->nodeType, sizeof(nodeType));
				struct FS_Create_Result rbuf;
				rbuf.resultCode = INTERFACE_SUCCESS;
				rbuf.rv = nfscompat_Create_Handler(call_handle, parent_node, node_name, nodeType);
				IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&rbuf, sizeof(rbuf));
				IPC_CallReturn(call_handle);
				break;
			}
		case SYS_FS_ReadDir_CMD:
			{
				const char *funcname;
				funcname = "SYS_FS_ReadDir_CMD";
				FSID target_node;
				struct VarLen dest;
				int offset;
				if(dataLen < sizeof(*((struct FS_ReadDir_Args *) inBuf))) {
					printf("Source buffer length incorrect %d %d(%s:%d)\n",  dataLen, sizeof(*((struct FS_ReadDir_Args *) inBuf)), __FILE__, __LINE__);
					IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
					IPC_CallReturn(call_handle);
					break;
				}
				{
					int __computedLen;
					int __varPos = 0;
					__varPos = __varPos; // suppress warning
					__computedLen = __varPos + sizeof(*((struct FS_ReadDir_Args *) inBuf));
					if(__computedLen != dataLen) {
						printf("%s: Computed length incorrect %d %d\n", funcname, __computedLen, dataLen);
						IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
						IPC_CallReturn(call_handle);
						break;
					}
				}
				int __varPos = 0;
				__varPos = __varPos; // suppress warning
				memcpy(&target_node, &((struct FS_ReadDir_Args *) inBuf)->target_node, sizeof(target_node));
				memcpy(&dest, &((struct FS_ReadDir_Args *) inBuf)->dest, sizeof(dest));
				memcpy(&offset, &((struct FS_ReadDir_Args *) inBuf)->offset, sizeof(int));
				struct FS_ReadDir_Result rbuf;
				rbuf.resultCode = INTERFACE_SUCCESS;
				rbuf.rv = nfscompat_ReadDir_Handler(call_handle, target_node, dest, offset);
				IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&rbuf, sizeof(rbuf));
				IPC_CallReturn(call_handle);
				break;
			}
		case SYS_FS_Read_CMD:
			{
				const char *funcname;
				funcname = "SYS_FS_Read_CMD";
				FSID target_node;
				int file_position;
				struct VarLen dest;
				int count;
				if(dataLen < sizeof(*((struct FS_Read_Args *) inBuf))) {
					printf("Source buffer length incorrect %d %d(%s:%d)\n",  dataLen, sizeof(*((struct FS_Read_Args *) inBuf)), __FILE__, __LINE__);
					IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
					IPC_CallReturn(call_handle);
					break;
				}
				{
					int __computedLen;
					int __varPos = 0;
					__varPos = __varPos; // suppress warning
					__computedLen = __varPos + sizeof(*((struct FS_Read_Args *) inBuf));
					if(__computedLen != dataLen) {
						printf("%s: Computed length incorrect %d %d\n", funcname, __computedLen, dataLen);
						IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
						IPC_CallReturn(call_handle);
						break;
					}
				}
				int __varPos = 0;
				__varPos = __varPos; // suppress warning
				memcpy(&target_node, &((struct FS_Read_Args *) inBuf)->target_node, sizeof(target_node));
				memcpy(&file_position, &((struct FS_Read_Args *) inBuf)->file_position, sizeof(file_position));
				memcpy(&dest, &((struct FS_Read_Args *) inBuf)->dest, sizeof(dest));
				memcpy(&count, &((struct FS_Read_Args *) inBuf)->count, sizeof(count));
				struct FS_Read_Result rbuf;
				rbuf.resultCode = INTERFACE_SUCCESS;
				rbuf.rv = nfscompat_Read_Handler(call_handle, target_node, file_position, dest, count);
				IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&rbuf, sizeof(rbuf));
				IPC_CallReturn(call_handle);
				break;
			}
		case SYS_FS_Write_CMD:
			{
				const char *funcname;
				funcname = "SYS_FS_Write_CMD";
				FSID target_node;
				int file_position;
				struct VarLen source;
				int count;
				if(dataLen < sizeof(*((struct FS_Write_Args *) inBuf))) {
					printf("Source buffer length incorrect %d %d(%s:%d)\n",  dataLen, sizeof(*((struct FS_Write_Args *) inBuf)), __FILE__, __LINE__);
					IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
					IPC_CallReturn(call_handle);
					break;
				}
				{
					int __computedLen;
					int __varPos = 0;
					__varPos = __varPos; // suppress warning
					__computedLen = __varPos + sizeof(*((struct FS_Write_Args *) inBuf));
					if(__computedLen != dataLen) {
						printf("%s: Computed length incorrect %d %d\n", funcname, __computedLen, dataLen);
						IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
						IPC_CallReturn(call_handle);
						break;
					}
				}
				int __varPos = 0;
				__varPos = __varPos; // suppress warning
				memcpy(&target_node, &((struct FS_Write_Args *) inBuf)->target_node, sizeof(target_node));
				memcpy(&file_position, &((struct FS_Write_Args *) inBuf)->file_position, sizeof(file_position));
				memcpy(&source, &((struct FS_Write_Args *) inBuf)->source, sizeof(source));
				memcpy(&count, &((struct FS_Write_Args *) inBuf)->count, sizeof(count));
				struct FS_Write_Result rbuf;
				rbuf.resultCode = INTERFACE_SUCCESS;
				rbuf.rv = nfscompat_Write_Handler(call_handle, target_node, file_position, source, count);
				IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&rbuf, sizeof(rbuf));
				IPC_CallReturn(call_handle);
				break;
			}
		case SYS_FS_Size_CMD:
			{
				const char *funcname;
				funcname = "SYS_FS_Size_CMD";
				FSID target_node;
				if(dataLen < sizeof(*((struct FS_Size_Args *) inBuf))) {
					printf("Source buffer length incorrect %d %d(%s:%d)\n",  dataLen, sizeof(*((struct FS_Size_Args *) inBuf)), __FILE__, __LINE__);
					IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
					IPC_CallReturn(call_handle);
					break;
				}
				{
					int __computedLen;
					int __varPos = 0;
					__varPos = __varPos; // suppress warning
					__computedLen = __varPos + sizeof(*((struct FS_Size_Args *) inBuf));
					if(__computedLen != dataLen) {
						printf("%s: Computed length incorrect %d %d\n", funcname, __computedLen, dataLen);
						IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
						IPC_CallReturn(call_handle);
						break;
					}
				}
				int __varPos = 0;
				__varPos = __varPos; // suppress warning
				memcpy(&target_node, &((struct FS_Size_Args *) inBuf)->target_node, sizeof(target_node));
				struct FS_Size_Result rbuf;
				rbuf.resultCode = INTERFACE_SUCCESS;
				rbuf.rv = nfscompat_Size_Handler(call_handle, target_node);
				IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&rbuf, sizeof(rbuf));
				IPC_CallReturn(call_handle);
				break;
			}
		case SYS_FS_Truncate_CMD:
			{
				const char *funcname;
				funcname = "SYS_FS_Truncate_CMD";
				FSID target_node;
				int target_len;
				if(dataLen < sizeof(*((struct FS_Truncate_Args *) inBuf))) {
					printf("Source buffer length incorrect %d %d(%s:%d)\n",  dataLen, sizeof(*((struct FS_Truncate_Args *) inBuf)), __FILE__, __LINE__);
					IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
					IPC_CallReturn(call_handle);
					break;
				}
				{
					int __computedLen;
					int __varPos = 0;
					__varPos = __varPos; // suppress warning
					__computedLen = __varPos + sizeof(*((struct FS_Truncate_Args *) inBuf));
					if(__computedLen != dataLen) {
						printf("%s: Computed length incorrect %d %d\n", funcname, __computedLen, dataLen);
						IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
						IPC_CallReturn(call_handle);
						break;
					}
				}
				int __varPos = 0;
				__varPos = __varPos; // suppress warning
				memcpy(&target_node, &((struct FS_Truncate_Args *) inBuf)->target_node, sizeof(target_node));
				memcpy(&target_len, &((struct FS_Truncate_Args *) inBuf)->target_len, sizeof(target_len));
				struct FS_Truncate_Result rbuf;
				rbuf.resultCode = INTERFACE_SUCCESS;
				rbuf.rv = nfscompat_Truncate_Handler(call_handle, target_node, target_len);
				IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&rbuf, sizeof(rbuf));
				IPC_CallReturn(call_handle);
				break;
			}
		case SYS_FS_Lookup_CMD:
			{
				const char *funcname;
				funcname = "SYS_FS_Lookup_CMD";
				FSID parent_node;
				struct VarLen filename;
				if(dataLen < sizeof(*((struct FS_Lookup_Args *) inBuf))) {
					printf("Source buffer length incorrect %d %d(%s:%d)\n",  dataLen, sizeof(*((struct FS_Lookup_Args *) inBuf)), __FILE__, __LINE__);
					IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
					IPC_CallReturn(call_handle);
					break;
				}
				{
					int __computedLen;
					int __varPos = 0;
					__varPos = __varPos; // suppress warning
					__computedLen = __varPos + sizeof(*((struct FS_Lookup_Args *) inBuf));
					if(__computedLen != dataLen) {
						printf("%s: Computed length incorrect %d %d\n", funcname, __computedLen, dataLen);
						IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
						IPC_CallReturn(call_handle);
						break;
					}
				}
				int __varPos = 0;
				__varPos = __varPos; // suppress warning
				memcpy(&parent_node, &((struct FS_Lookup_Args *) inBuf)->parent_node, sizeof(parent_node));
				memcpy(&filename, &((struct FS_Lookup_Args *) inBuf)->node_name, sizeof(filename));
				struct FS_Lookup_Result rbuf;
				rbuf.resultCode = INTERFACE_SUCCESS;
				rbuf.rv = nfscompat_Lookup_Handler(call_handle, parent_node, filename);
				IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&rbuf, sizeof(rbuf));
				IPC_CallReturn(call_handle);
				break;
			}
		case SYS_FS_Unlink_CMD:
			{
				const char *funcname;
				funcname = "SYS_FS_Unlink_CMD";
				FSID parent_node;
				FSID child_node;
				if(dataLen < sizeof(*((struct FS_Unlink_Args *) inBuf))) {
					printf("Source buffer length incorrect %d %d(%s:%d)\n",  dataLen, sizeof(*((struct FS_Unlink_Args *) inBuf)), __FILE__, __LINE__);
					IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
					IPC_CallReturn(call_handle);
					break;
				}
				{
					int __computedLen;
					int __varPos = 0;
					__varPos = __varPos; // suppress warning
					__computedLen = __varPos + sizeof(*((struct FS_Unlink_Args *) inBuf));
					if(__computedLen != dataLen) {
						printf("%s: Computed length incorrect %d %d\n", funcname, __computedLen, dataLen);
						IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&malformed, sizeof(int));
						IPC_CallReturn(call_handle);
						break;
					}
				}
				int __varPos = 0;
				__varPos = __varPos; // suppress warning
				memcpy(&parent_node, &((struct FS_Unlink_Args *) inBuf)->parent_node, sizeof(parent_node));
				memcpy(&child_node, &((struct FS_Unlink_Args *) inBuf)->child_node, sizeof(child_node));
				struct FS_Unlink_Result rbuf;
				rbuf.resultCode = INTERFACE_SUCCESS;
				rbuf.rv = nfscompat_Unlink_Handler(call_handle, parent_node, child_node);
				IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&rbuf, sizeof(rbuf));
				IPC_CallReturn(call_handle);
				break;
			}
		default:
			printf("%d: Unknown call code id=%d (%d bytes)\n", nfscompat_port_handle, *(int*)dataBuf, dataLen);
			int i;for(i=0; i < dataLen; i++) { printf("%02x ", (int)(unsigned char)dataBuf[i]); }
			int nosuchmethod = -INTERFACE_NOSUCHMETHOD;
			IPC_TransferTo(call_handle, RESULT_DESCNUM, DESCRIPTOR_START, (char *)&nosuchmethod, sizeof(int));
			IPC_CallReturn(call_handle);
			break;
	}
}


static void *processing_loop(void *ctx) {
	while(1)
		nfscompat_processNextCommand();

	return NULL;
}

void nfscompat_destroy(void)
{
	if (nfscompat_port_handle < 0)
		return;
	IPC_DestroyPort(nfscompat_port_handle);
	nfscompat_port_handle = -1;
}

int nfscompat_init(char *servername, struct nfs_node *root)
{
	if (nfscompat_port_handle > 0)
		return 0;

	fh_init();
	fh_put(root);

	IPC_userInit();
	nfscompat_port_handle = IPC_CreatePort(NULL);
	if (nfscompat_port_handle <= 0)
		return 1;

	return 0;
}


static void usage(void) {
	printf("usage:  nfs --default\n");
	printf("        nfs ip.ip.ip.ip:/remote_path [-mount /mount_point] [-name name]\n");
	printf("        or use '*' instead of ip address to use the nexusbootp server address\n");
	exit(1);
}

#define SERVERIPLEN 17
int main(int argc, char **argv) {
	char lserverip[SERVERIPLEN];
	char *serverip;
	char *remotepath;
	char *mountpoint = NULL;
	char *servername = "nfs";

	// HACK hardcoded defaults.. because I'm too lazy to retype these each time
	if (argc == 2 && strlen(argv[1]) == 9 && !strcmp(argv[1], "--default")) {
		serverip = "192.168.190.1";
		remotepath = "/opt/nfs";
		mountpoint = "/mnt";
	}
	else {
		// cannot have odd number of parameters (aside from 1)
		if (argc % 2)
			usage();

		while (argc > 2) {
		  if (!strcmp(argv[argc-2], "-name"))
		    servername = argv[argc-1];
		  else if (!strcmp(argv[argc-2], "-mount"))
		    mountpoint = argv[argc-1];
		  else break;
		  argc -= 2;
		}

		serverip = strdup(argv[1]);
		remotepath = strchr(serverip, ':');
		if (!remotepath) {
			printf("bad server path: %s\n\t must be ip.ip.ip.ip:/path\n", argv[2]);
			exit(1);
		}
		*remotepath++ = '\0';
	}

	if (nfs_init(serverip, remotepath, "nexus.localdomain", 968) != 0) {
		printf("nfs_init: failed\n");
		printf("---> Are you sure you have network connectivity?\n");
		printf("---> Are you sure you are running NFS on the server?\n");
		printf("---> Are you sure you have set the right NFS permissions?\n");
		exit(1);
	}

	if (nfs_mount() != 0) {
		printf("nfs_mount: failed\n");
		exit(1);
	}

//	printf("nfs server: mounted %s:%s\n", serverip, remotepath);
//	printf("nfs server: root node = "); debug_print_node(&root_node); printf("\n");

	nfscompat_init(servername, &root_node);

	if (mountpoint) {
	  char portstring[12];

	  snprintf(portstring, 11, "%d", nfscompat_port_handle);
	  if (mount(portstring, mountpoint, NULL, 0, NULL))
	    printf("can't mount nfs (%s:%s) as %s\n", serverip, remotepath, mountpoint);
	  else
	    printf("mounted nfs (%s:%s) as %s\n", serverip, remotepath, mountpoint);
	}

	printf("NFS up at IPC port %d\n", nfscompat_port_handle);

	while (1) 
		processing_loop(NULL);

	return 0;
}

