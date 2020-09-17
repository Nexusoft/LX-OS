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
#include <nexus/filecache.h>
#include <nexus/FS.interface.h>
#include <nexus/Net.interface.h>
#include <nexus/IPC.interface.h>

#include "nfs.h"

#define NFS_CACHEREADS

static int ipcport;

/** Insert node into the node -> FSID lookup table (avoiding duplicates) */
static FSID 
fsid_add(struct nfs_node **node) 
{
	struct nfs_node *repl;
	int id, type;

	repl = fh_canonical(*node, &id);
	type = (repl->type == NFS_REGULAR_FILE ? FS_NODE_FILE : FS_NODE_DIR);
	*node = repl;
	
	return (FSID) { .port = ipcport, .nodetype = type, .nodeid = id };
}

/** Lookup a node by FSID */
static struct nfs_node *
fsid_get(FSID fsid) 
{
	struct nfs_node *node;

	if (fsid.nodetype == FS_NODE_DIR && fsid.nodeid == 0)
		return &root_node;
	
	node = fh_get((int) fsid.nodeid);
	if (!node)
		fprintf(stderr, "[nfs] warning: could not resolve a node\n");
	
	return node;
}

FSID nfscompat_Create_Handler(Call_Handle call_handle,
		FSID parent_node, struct VarLen node_name, int nodeType)
{
	char filename[MAX_FNAME_LEN+1];
	
	if (node_name.len > MAX_FNAME_LEN)
		return FSID_ERROR(FS_INVALID);
	
	if (IPC_TransferFrom(call_handle, node_name.desc_num,
				filename, 0, node_name.len) != 0) 
		return FSID_ERROR(FS_ACCESSERROR);
	filename[node_name.len] = '\0';

	struct nfs_node *parent = fsid_get(parent_node);
	if (!parent)
		return FSID_ERROR(FS_INVALID);

	struct nfs_node *node = NULL;
	if (nodeType == FS_NODE_FILE) {
		node = nfs_create(parent, filename, 1 /*overwrite */);
	} else if (nodeType == FS_NODE_DIR) {
		printf("nfs_mkdir not yet implemented\n");
		return FSID_ERROR(FS_ACCESSERROR);
	} else {
		printf("nfs can only create FILE or DIR\n");
		return FSID_ERROR(FS_ACCESSERROR);
	}

	if (!node)
		return FSID_ERROR(FS_INVALID);

	return fsid_add(&node);
}

struct readdir_state
{
	struct nfs_readdir_cookie cookie;

	char *res;	// results cached from NFS server
	int off;	// current offset in res
	int count;	// no. of items in res
	int dir;
};

/** Stateless equivalent of Unix opendir()/readdir()/closedir().
    Somewhat complex, because it has to keep state between NFS calls:
    NFS can return a set of results; we return single results at a time */
static int nfscompat_ReadDir_Handler(Call_Handle call_handle,
		FSID target_node, struct VarLen dest, int offset)
{
	// Track open directories
	// As a result of stateful FS interface, we never explicitly 
	// open or close directories. Therefore, multiple readers on
	// the same directory will confuse the system (XXX FIX).
	// XXX collect garbage after timeout
	static struct HashTable *state_table;

	struct readdir_state *state;
	struct nfs_node *node; 
	char *item;
	int bytelen, eod, ilen, ioff;
	
	node = fsid_get(target_node);
	if (!node)
		return -FS_INVALID;

	// init: create table
	if (unlikely(!state_table))
		state_table = hash_new(64, sizeof(FSID));
	
	// initialize on first call
	state = hash_findItem(state_table, &target_node);
	if (!state) {
		state = calloc(1, sizeof(*state));
		hash_insert(state_table, &target_node, state);
	}

	// ask NFS server for the next set of results
	if (state->off == state->count) {
		// issue the NFS readdir request
		state->off = state->count = 0;
		state->res = nfs_readdir(node, &bytelen, &state->cookie, &state->count, &eod);
		if (!state->res)
			return -FS_INVALID;

		// no more results
		if (!state->count) 
			goto done_last;
	}

    // fast forward to the entry at state->off
    item = state->res + 8;
    ilen = strlen(item) + 1;
    for (ioff = 0; ioff < state->off; ioff++) {
      item += ilen + 8;
      ilen = strlen(item) + 1;
    }

    // will the name fit?
    if (dest.len < ilen) {
	printf("[nfs] insufficient room for readdir result\n");
    	return -FS_INVALID;
    }

    // transfer name
    if (IPC_TransferTo(call_handle, dest.desc_num, item, 0, ilen))
	return -FS_INVALID;

    state->off++;
    
    // last element in this transfer
    if (state->off == state->count) {
      if (eod)
        goto done_last;
      else
        free(state->res);
    }

    return 1;

// cleanup state for this directory
done_last:
    free(state->res);
    free(state);
    hash_delete(state_table, &target_node);
    return 0;
}

static int nfscompat_Read_Handler(Call_Handle call_handle,
		FSID target_node, int file_position, struct VarLen dest, int count)
{
	struct nfs_node *node; 
	char *data;
	int done, curlen;

	// sanity check input
	if (count < 0 || file_position < 0)
	  return -FS_INVALID;
	
	// lookup
	node = fsid_get(target_node);
	if (!node)
	  return -FS_NOTFOUND;

	// check extents
	if (file_position == node->size)
	  return 0; //end of file
	if (file_position > node->size)
	  return -FS_INVALID;
	
	data = malloc(PAGESIZE);
	if (!data) {
		fprintf(stderr, "[nfs] out of memory in read\n");
		exit(1);
	}

	done = 0;
	while (done < count) {
#ifdef NFS_CACHEREADS
		// 1. (try to) read from cache
		curlen = nxfilecache_read(target_node, file_position + done, data);
		if (curlen < 0) {
#endif
			if (file_position + done == 0)
				printf("[nfs] read %s (network)\n", node->name);  

			// else read from network
			curlen = nfs_read(node, file_position + done, data);
			if (curlen < 0) {
				printf("[nfs] read error #1\n");
				free(data);
				return -FS_ACCESSERROR;
			}
		
			if (curlen == 0)
				break;

#ifdef NFS_CACHEREADS
			// insert into cache
			nxfilecache_write(target_node, file_position + done, data, curlen);
		}
#endif
		curlen = min(curlen, count - done);
		if (IPC_TransferTo(call_handle, dest.desc_num, data, done, curlen)) {
			printf("[nfs] read error (transfer)\n");
			free(data);
			return -FS_ACCESSERROR;
		}
		done += curlen;
	}

	free(data);

	return done;
}

static int nfscompat_Write_Handler(Call_Handle call_handle,
		FSID target_node, int file_position, struct VarLen source, int count)
{
	struct nfs_node *node = fsid_get(target_node);
	char *data;
	int written, writelen, done, curlen, off;

	if (!node)
		return -FS_NOTFOUND;
	if (count <= 0)
		return -FS_INVALID;

	if (file_position == 0)
		printf("[nfs] write %s\n", node->name);  

	fh_remove(node);

#ifdef NFS_CACHEREADS
	// remove from (new) rcache
	nxfilecache_invalidate(target_node, file_position, count);
#endif

	data = malloc(PAGESIZE);
	done = 0;
	while (done < count) {

		// read from client
		curlen = min(PAGESIZE, count - done);
		if (IPC_TransferFrom(call_handle, source.desc_num, 
				     data, done, curlen)) {
			fprintf(stderr, "[nfs] write error (transfer)\n");
			free(data);
			return -FS_ACCESSERROR;
		}

		// write to server
		written = 0;
		while (written < curlen) {
			
			// write
			writelen = nfs_write(node, 
					     file_position + done + written, 
					     data + written, 
					     curlen - written);
			
			// error check
			if (writelen < 0) {
				fprintf(stderr, "[nfs] write error\n");
				free(data);
				return -FS_ACCESSERROR;
			}

			written += writelen;
		}
		done += curlen;

		// special case: end before count was reached
		if (!curlen) {
			fprintf(stderr, "[nfs] write (warning: premature EOF)\n");
			break;
		}
	}

	free(data);
	return count;
}


static int nfscompat_Truncate_Handler(Call_Handle call_handle,
		FSID target_node, int target_len)
{
	struct nfs_node *node = fsid_get(target_node);
	if (!node) {
		fprintf(stderr, "[nfs] truncate failed: unknown inode\n");
		return -FS_NOTFOUND;
	}

	if (node->size < target_len)
		return node->size;

#ifdef NFS_CACHEREADS
	nxfilecache_invalidate(target_node, target_len, node->size - target_len);
#endif

	node->size = target_len;

	if (nfs_set_attr(node, target_len) < 0) {
		fprintf(stderr, "[nfs] truncate failed: attr %d\n", target_len);
		return -1;
	}

	return target_len;
}

static int nfscompat_Sync_Handler(Call_Handle call_handle,
		FSID target_node)
{
	struct nfs_node *node = fsid_get(target_node);
	if (!node)
		return -FS_NOTFOUND;

	return 0;
}

static int nfscompat_Size_Handler(Call_Handle call_handle,
		FSID target_node)
{
	struct nfs_node *node = fsid_get(target_node);
	if (!node)
		return -FS_NOTFOUND;

	return (int) node->size;
}

static FSID nfscompat_Lookup_Handler(Call_Handle call_handle,
		FSID parent_node, struct VarLen node_name)
{
	char filename[MAX_FNAME_LEN+1];
	struct nfs_node *parent, *node;
	char *basename;
	char *slash;
	FSID nodeid;

	parent = fsid_get(parent_node);
	if (!parent)
		return FSID_ERROR(FS_NOTFOUND);

	if (node_name.len > MAX_FNAME_LEN)
		return FSID_ERROR(FS_INVALID);
	
	if (IPC_TransferFrom(call_handle, node_name.desc_num,
			     filename, 0, node_name.len))
		return FSID_ERROR(FS_ACCESSERROR);
	
	filename[node_name.len] = '\0';

	// ugh: filename may have embedded slashes (but hopefully no dots?)
	basename = filename;
	do {
		slash = strchr(basename, '/');
		if (slash) 
			*slash = '\0';
		
		node = nfs_lookup(parent, basename);
		if (!node)
			return FSID_ERROR(FS_INVALID);
		nodeid = fsid_add(&node);
		
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
	struct nfs_node *parent, *node;
       
	parent = fsid_get(parent_node);
	if (!parent)
		return -FS_NOTFOUND;
	
	node = fsid_get(src_node);
	if (!node)
		return -FS_NOTFOUND;

#ifdef NFS_CACHEREADS
	nxfilecache_invalidate(src_node, 0, node->size);
#endif

	if (nfs_remove(parent, node->name))
		return -FS_INVALID;
	
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

	call_result = IPC_RecvCall(ipcport, dataBuf, &dataLen, &cdesc);
	call_handle = (call_result == 0 ? cdesc.call_handle : call_result);
	// IPD_ID ipd_id = cdesc.ipd_id; // unused

	if (call_result < 0)
		return;

	if(dataLen < sizeof(int)) {
		printf("IPC does not contain command ordinal\n");
		int error = -INTERFACE_MALFORMEDREQUEST;
		IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&error, 0, sizeof(error));
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
				IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&no_op, 0, sizeof(no_op));
				IPC_CallReturn(call_handle);
				break;
			}
		case SYS_FS_Mount_CMD:
		case SYS_FS_Unmount_CMD:
			{
				IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&not_impl, 0, sizeof(not_impl));
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
					IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
						IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
				IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&rbuf, 0, sizeof(rbuf));
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
					IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
						IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
				IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&rbuf, 0, sizeof(rbuf));
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
					IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
						IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
				IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&rbuf, 0, sizeof(rbuf));
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
					IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
						IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
				IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&rbuf, 0, sizeof(rbuf));
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
					IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
						IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
				IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&rbuf, 0, sizeof(rbuf));
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
					IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
						IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
				IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&rbuf, 0, sizeof(rbuf));
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
					IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
						IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
				IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&rbuf, 0, sizeof(rbuf));
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
					IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
						IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
				IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&rbuf, 0, sizeof(rbuf));
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
					IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
						IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&malformed, 0, sizeof(int));
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
				IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&rbuf, 0, sizeof(rbuf));
				IPC_CallReturn(call_handle);
				break;
			}
		default:
			printf("%d: Unknown call code id=%d (%d bytes)\n", ipcport, *(int*)dataBuf, dataLen);
			int i;for(i=0; i < dataLen; i++) { printf("%02x ", (int)(unsigned char)dataBuf[i]); }
			int nosuchmethod = -INTERFACE_NOSUCHMETHOD;
			IPC_TransferTo(call_handle, RESULT_DESCNUM, (char *)&nosuchmethod, 0, sizeof(int));
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
	if (ipcport < 0)
		return;
	IPC_DestroyPort(ipcport);
	ipcport = -1;
}

int nfscompat_init(char *servername, struct nfs_node *root)
{
	if (ipcport > 0)
		return 0;

	fh_init();
	fh_put(root);

	IPC_userInit();
	ipcport = IPC_CreatePort(0);
	if (ipcport <= 0)
		return 1;

	return 0;
}


static void __attribute__((noreturn))
usage(void) 
{
	printf("Usage:  nfs.app -k <index>\n");
	printf("   or:  nfs.app --key <index>\n");
	printf("   or:  nfs.app ip.ip.ip.ip:/remote_path [-mount /mount_point]\n");
	exit(1);
}

/// a hack to be able to have multiple users store their default path
#define MAXPATHS 10
static char ipname[15];

/// learn the default server address by taking the host ip and replacing
//  the last octet with .1
static char *
default_server(void)
{
	int ip;
	
	// default IP is the .1 host on our local network
	// in VMWare, this is the host operating system
	Net_get_ip((unsigned int *) &ip, NULL, NULL);
	snprintf(ipname, 15, "%hhu.%hhu.%hhu.%hhu", 
		 (ip)       & 0xff, (ip >> 8) & 0xff,
		 (ip >> 16) & 0xff, 1);
	return ipname;
}

#define SERVERIPLEN 17
int main(int argc, char **argv) {
	const char *remotepaths[MAXPATHS] = {
		"/opt/git/nexus/build/boot", 
		"/mnt/32bit/karmic/home/nexus/build/boot",
		"/home/willem/src/nexus/build/boot",
	};
	char *remotepath;
	char *serverip;
	char *mountpoint = NULL;
	char *servername = "nfs";
	int key;

	// use a preset option
	if (argc == 3) {
		if (!strcmp(argv[1], "-k") ||
		    !strcmp(argv[1], "--key")) {
			key = strtol(argv[2], NULL, 10);
			serverip = default_server();
			remotepath = strdup(remotepaths[key]);
			mountpoint = "/usr";
		}
		else 
			usage();
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
		printf("[nfs] init FAILED\n");
		printf("     Are you sure you have network connectivity?\n");
		printf("     Are you sure you are running NFS on the server?\n");
		printf("     Are you sure you have set the right NFS permissions?\n");
		exit(1);
	}

	if (nfs_mount() != 0) {
		printf("nfs_mount: failed\n");
		exit(1);
	}

#ifdef NFS_CACHEREADS
	printf("[nfs] caching ENABLED\n");
	nxfilecache_init(1024);
#else
	printf("[nfs] caching DISABLED\n");
#endif

	nfscompat_init(servername, &root_node);

	if (mountpoint) {
	  char portstring[12];

	  snprintf(portstring, 11, "%d", ipcport);
	  if (mount(portstring, mountpoint, NULL, 0, NULL))
	    printf("can't mount nfs (%s:%s) as %s\n", serverip, remotepath, mountpoint);
	  else
	    printf("[nfs] mounted %s:%s as %s\n", serverip, remotepath, mountpoint);
	}

	printf("[nfs] up at IPC port %d\n", ipcport);

	while (1) 
		processing_loop(NULL);

	return 0;
}


