#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <asm/types.h>

#include "xdr.h"
#include "nfs.h"


// network info
char server_addr[4];
int nfs_is_mounted = 0;
unsigned int nfs_port;	
unsigned int mount_port;	

// auth information
char *local_machinename;
unsigned int uid;

// mount info
char *mount_path;
struct nfs_node root_node;

#if 0
struct nfs_node *nfs_get(struct nfs_node *p) {
	p->refcount++;
	return p;
}

struct nfs_node *nfs_put(struct nfs_node *p) {
	p->refcount--;
	assert(p->refcount >= 0);
	if (p->refcount == 0 && /* p != &root_node */ p->parent) {
		//nfs_put(p->parent); // let the caller do this
		free(p->name);
		free(p);
		return NULL;
	}
	return p;
}
#endif

#ifndef __NEXUS__
#define fh_put(x)
#endif

struct linux_nfs_fhbase {
	// Byte fields are reversed from Linux due to xdr_decode_int()
	// of first word
	__u8            fb_fileid_type;
	__u8            fb_fsid_type;
	__u8            fb_auth_type;
	__u8            fb_version;     /* == 1, even => nfs_fhbase_old */
	__u32           fb_auth[1];
	/*      __u32           fb_fsid[0]; floating */
	/*      __u32           fb_fileid[0]; floating */
} __attribute__((packed));

enum linux_nfsd_fsid {
        FSID_DEV = 0,
        FSID_NUM,
        FSID_MAJOR_MINOR,
        FSID_ENCODE_DEV,
        FSID_UUID4_INUM,
        FSID_UUID8,
        FSID_UUID16,
        FSID_UUID16_INUM,
};

int extract_inode_number(struct nfs_fh *fh) {
	assert(fh);
	int i;
	switch(fh->len) {
	case 12: // 1/0/0 major,minor inode
		assert((fh->data[0]>>24) == 1);
		assert((fh->data[0]&0xffffff) == 0);
		return ntohl(fh->data[2]);
	case 20: // 1/0/1 major,minor root inode (?)
		assert((fh->data[0]>>24) == 1);
		assert((fh->data[0]&0xffffff) == 1);
		return ntohl(fh->data[3]);
	case 28: // 1/0/2 major,minor root inode (?) parent (?)
		if(! ( (fh->data[0]>>24) == 1 && 
		       (fh->data[0]&0xffffff) == 2 ) ) {
			goto try_new_format;
		}
		return ntohl(fh->data[3]);
	default: {
	try_new_format: ;
		struct linux_nfs_fhbase *hdr = 
			(struct linux_nfs_fhbase *)fh->data;
		if(hdr->fb_version != 1) {
			printf("Unknown old format handle\n");
			goto unknown_type;
		}
		__u8 *fileid_start = NULL;
		switch(hdr->fb_fsid_type) {
		case FSID_DEV:
			fileid_start = ((unsigned char *)hdr->fb_auth) + 8;
			break;
		case FSID_UUID16_INUM:
			fileid_start = ((unsigned char *)hdr->fb_auth) + 24;
			break;
		default:
			goto unknown_new_format;
		}
		switch(hdr->fb_fileid_type) {
		case 0:
			// return the inode # of the mount point
			return ntohl( *(unsigned int *)hdr->fb_auth );
		case 1:
			return ntohl( *(unsigned int *) fileid_start );
		default:
			goto unknown_new_format;
		}
		unknown_new_format:
			printf("Unknown new format, %d %d\n",
			       hdr->fb_fsid_type, hdr->fb_fileid_type);
			goto unknown_type;
	}
	unknown_type: ;
		printf("unknown file handle encoding -- please add a handler for this case\n");
		printf("len=%d, data = ", fh->len);
		for (i = 0; i < ((fh->len/4)&0xff); i++) // don't print too many
			printf("%08x ", fh->data[i]);
		printf("\n");
		assert(0);
	}
	return -1; // never reached
}

void debug_print_fh(struct nfs_fh *fh) {
	if (fh->len == 12) {
		printf("v%d e%x %d,%d : %d", fh->data[0]>>24, fh->data[0]&0xffffff,
			fh->data[1]>>16, fh->data[1]&0xffff, ntohl(fh->data[2]));
	} else if (fh->len == 20) {
		printf("v%d e%x %d,%d %08x%08x%08x : %d:%d", fh->data[0]>>24, fh->data[0]&0xffffff,
			fh->data[1]>>16, fh->data[1]&0xffff, 
			fh->data[4], fh->data[5], fh->data[6],
			ntohl(fh->data[2]), ntohl(fh->data[3]));
	} else if (fh->len == 28) {
		printf("v%d e%x %d,%d %08x%08x%08x : %d:%d/%d", fh->data[0]>>24, fh->data[0]&0xffffff,
			fh->data[1]>>16, fh->data[1]&0xffff, 
			fh->data[4], fh->data[5], fh->data[6],
			ntohl(fh->data[2]), ntohl(fh->data[5]), ntohl(fh->data[3]));
	} else {
		printf("???");
	}
	int inode = extract_inode_number(fh);
	printf(" <%d>", inode);
}

void debug_print_node(struct nfs_node *node) {
	debug_print_fh(&node->fh);
	printf(" : type=%d, size=%lld, name=%s%s\n", node->type, node->size, node->name,
			/* (node->parent ? "" : " (ROOT)") */ "");
}

int get_connection(int port) {
	struct sockaddr_in dest;
	int err;

	int fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0) 
		return -1;
	if (fd == 0)
		printf("warning: socket fd == 0\n");

	memcpy(&dest.sin_addr.s_addr, server_addr, sizeof(server_addr));
	dest.sin_port = htons(port);
	dest.sin_family = AF_INET;

	err = connect(fd, (struct sockaddr *)&dest, sizeof(dest));
	if (err) {
		printf("error: connect failed\n");
		close(fd);
		return -1;
	}
	return fd;
}

int last_xid;
int next_xid(void) {
	return ++last_xid;
}

u32 *xdr_encode_call(u32 *p, u32 xid, u32 prog, u32 prog_version, u32 prog_proc, u32 auth) {
	p = xdr_encode_int(p, xid);
	p = xdr_encode_int(p, CALL);
	p = xdr_encode_int(p, RPC_VERSION);
	p = xdr_encode_int(p, prog);
	p = xdr_encode_int(p, prog_version);
	p = xdr_encode_int(p, prog_proc);
	if (auth == AUTH_UNIX)
		p = xdr_encode_authunix(p, local_machinename, uid); // cred
	else
		p = xdr_encode_authnull(p); // cred
	p = xdr_encode_authnull(p); // verif
	return p;
}

u32 *xdr_encode_fh(u32 *p, struct nfs_fh *fh) {
	assert((fh->len & 0x3) == 0);
	p = xdr_encode_int(p, fh->len);
	int i;
	for (i = 0; i < fh->len/4; i++) {
		p = xdr_encode_int(p, fh->data[i]);
	}
	return p;
}

u32 *xdr_decode_fh(u32 *p, struct nfs_fh *fh, int *len) {
	*len -= 4;
	if (*len < 0)
		return NULL;
	memset(fh->data, 0, sizeof(struct nfs_fh));
	p = xdr_decode_int(p, &fh->len);
	*len -= fh->len;
	if (*len < 0)
		return NULL;
	assert(fh->len <= NFS3_FHSIZE);
	int i;
	for (i = 0; i < fh->len/4; i++) {
		p = xdr_decode_int(p, &fh->data[i]);
	}
	return p;
}

u32 *xdr_decode_attr(u32 *p, struct nfs_node *node, int *len) {
	*len -= 84;
	if (*len < 0)
		return NULL;
	p = xdr_decode_int(p, &node->type);
	p += 4; // mode, nlink, uid, gid (4-byte vals)
	p = xdr_decode_hyper(p, &node->size);
	p += 8; // used, spec, fsid, inode (8-byte vals)
	p += 2; // atime
	p = xdr_decode_int(p, &node->mtime.seconds);
	p = xdr_decode_int(p, &node->mtime.nseconds);
        p += 2;	// ctime
	return p;
}

static inline int xsattrlenlen(void) { return 6*4 + 8; }
u32 *xdr_encode_sattr_len(u32 *p, int len) {
	p = xdr_encode_int(p, 0); // mode : don't change
	p = xdr_encode_int(p, 0); // uid: don't change
	p = xdr_encode_int(p, 0); // gid: don't change
	p = xdr_encode_int(p, 1); p = xdr_encode_hyper(p, (u64)len); // size
	p = xdr_encode_int(p, 0); // atime: don't change
	p = xdr_encode_int(p, 0); // mtime: don't change
	return p;
}

static inline int xsattrmodelen(void) { return 6*4 + 4; }
u32 *xdr_encode_sattr_mode(u32 *p) {
	p = xdr_encode_int(p, 1); p = xdr_encode_int(p, 0644); // mode
	p = xdr_encode_int(p, 0); // uid: don't change
	p = xdr_encode_int(p, 0); // gid: don't change
	p = xdr_encode_int(p, 0); // size: don't change
	p = xdr_encode_int(p, 0); // atime: don't change
	p = xdr_encode_int(p, 0); // mtime: don't change
	return p;
}

u32 *xdr_decode_postop(u32 *p, struct nfs_node *node, int *len, u32 *have_post) {
	*len -= 4;
	if (*len < 0) return NULL;
	p = xdr_decode_int(p, have_post);
	if (*have_post) {
		p = xdr_decode_attr(p, node, len);
		if (!p)
		   return NULL;
	}
	return p;
}

u32 *xdr_decode_wccdata(u32 *p, struct nfs_node *node, int *len, u32 *have_pre, u32 *have_post) {
	*len -= 4;
	if (*len < 0) return NULL;
	p = xdr_decode_int(p, have_pre);
	if (*have_pre) {
		*len -= 4*6; // size, atime, mtime
		if (*len < 0) return NULL;
		p += 6;
	}

	return xdr_decode_postop(p, node, len, have_post);
}

const char *status_msg(int status) {
	switch (status) {
		case 0: return "NFS3_OK";
		case 1: return "NFS3ERR_PERM";
		case 2: return "NFS3ERR_NOENT";
		case 5: return "NFS3ERR_IO";
		case 6: return "NFS3ERR_NXIO";
		case 13: return "NFS3ERR_ACCES";
		case 17: return "NFS3ERR_EXIST";
		case 18: return "NFS3ERR_XDEV";
		case 19: return "NFS3ERR_NODEV";
		case 20: return "NFS3ERR_NOTDIR";
		case 21: return "NFS3ERR_ISDIR";
		case 22: return "NFS3ERR_INVAL";
		case 27: return "NFS3ERR_FBIG";
		case 28: return "NFS3ERR_NOSPC";
		case 30: return "NFS3ERR_ROFS";
		case 31: return "NFS3ERR_MLINK";
		case 63: return "NFS3ERR_NAMETOOLONG";
		case 66: return "NFS3ERR_NOTEMPTY";
		case 69: return "NFS3ERR_DQUOT";
		case 70: return "NFS3ERR_STALE";
		case 71: return "NFS3ERR_REMOTE";
		case 10001: return "NFS3ERR_BADHANDLE";
		case 10002: return "NFS3ERR_NOT_SYNC";
		case 10003: return "NFS3ERR_BAD_COOKIE";
		case 10004: return "NFS3ERR_NOTSUPP";
		case 10005: return "NFS3ERR_TOOSMALL";
		case 10006: return "NFS3ERR_SERVERFAULT";
		case 10007: return "NFS3ERR_BADTYPE";
		case 10008: return "NFS3ERR_JUKEBOX";
		default: return "STATUS_UNKNOWN";
	}
}

#define ERR(val, ...) do { \
		printf("[%s:%d] ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		return val; \
	} while (0)
#define FAIL(...) do { \
		printf("[%s:%d] ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		free(xdr_reply); \
		return err_val; \
	} while (0)
#define GET(var) do { \
		if (len < 4) FAIL("expected %s but got end-of-message\n", #var); \
		len -= 4; \
		p = xdr_decode_int(p, var); \
	} while (0);
#define EXPECT(val) do { \
		if (len < 4) FAIL("expected %s but got end-of-message\n", #val); \
		len -= 4; \
		u32 r_val; \
		p = xdr_decode_int(p, &r_val); \
		if (r_val != (val)) FAIL("expected %s (%d) but got %d\n", #val, val, r_val); \
	} while (0);
#define EXPECT_STATUS(val) do { \
		if (len < 4) FAIL("expected %s but got end-of-message\n", #val); \
		len -= 4; \
		u32 r_val; \
		p = xdr_decode_int(p, &r_val); \
		if (r_val != (val)) FAIL("expected %s (%d) but got %s (%d)\n", #val, val, status_msg(r_val), r_val); \
	} while (0);

int check_fh(struct nfs_node *node) {
	switch(node->fh.len) {
	case 12:
	case 20:
	case 28:
	case 36:
		return 0;
	default:
			ERR(1, "bad file handle (len=%d)\n", node->fh.len);
	}
}	

int portmapper_getport(u32 service, u32 version, u32 trans, u32 dport, u32 *port)
{
	int err_val = -1;
	char xdr_msg[4+40+16];
	u32 *p = (u32*)(xdr_msg+4);

	int xid = next_xid();

	p = xdr_encode_call(p, xid, PROG_PORTMAP, PROG_PORTMAP_VERSION, PROG_PORTMAP_GETPORT, AUTH_NULL);

	p = xdr_encode_int(p, service);
	p = xdr_encode_int(p, version);
	p = xdr_encode_int(p, trans);
	p = xdr_encode_int(p, dport);

	assert(xdr_msg + sizeof(xdr_msg) == (void*)p);

	int fd = get_connection(SUNRPC_PORT);
	if (fd < 0)
		ERR(-1, "error: no connection to SUNRPC_PORT\n");

	if (rpc_send(fd, xdr_msg, sizeof(xdr_msg)) != 0) {
		close(fd);
		ERR(-1, "error: contacting SUNRPC_PORTMAP\n");
	}

	char *xdr_reply;
	int xdr_replylen;
	if (rpc_recv(fd, &xdr_reply, &xdr_replylen) != 0) {
		close(fd);
		return -EAGAIN;
	}
	p = (u32*)xdr_reply;
	int len = xdr_replylen;

	EXPECT(xid); EXPECT(REPLY); EXPECT(MSG_ACCEPTED);
	EXPECT(AUTH_NULL); EXPECT(0); EXPECT(SUCCESS);

	GET(port);

	free(xdr_reply);
	close(fd);
	return 0;
}

int prog_nullcall(u32 port, u32 service, u32 version)
{
	int err_val = -1;
	char xdr_msg[4+40];
	u32 *p = (u32*)(xdr_msg+4);

	int xid = next_xid();

	p = xdr_encode_call(p, xid, service, version, 0, AUTH_NULL);

	assert(xdr_msg + sizeof(xdr_msg) == (void*)p);

	int fd = get_connection(port);
	if (fd < 0)
		ERR(-1, "error: connecting to service %d on port %d\n", service, port);

	if (rpc_send(fd, xdr_msg, sizeof(xdr_msg)) != 0) {
		close(fd);
		ERR(-1, "error: contacting service %d on port %d\n", service, port);
	}

	char *xdr_reply;
	int xdr_replylen;
	if (rpc_recv(fd, &xdr_reply, &xdr_replylen) != 0) {
		close(fd);
		return -EAGAIN;
	}
	p = (u32*)xdr_reply;
	int len = xdr_replylen;

	EXPECT(xid); EXPECT(REPLY); EXPECT(MSG_ACCEPTED);
	EXPECT(AUTH_NULL); EXPECT(0); EXPECT(SUCCESS);

	free(xdr_reply);
	close(fd);
	return 0;
}

int nfs_umount(void);

// length of a standard call + unix auth + 4 bytes reserved
int hdr_len(void) {
	return 4+40+20+xstrlen(local_machinename);
}

int mount_call(u32 operation, struct nfs_fh *fh)
{
	int err_val = -1;
	int xdr_msglen = hdr_len()+xstrlen(mount_path);
	char *xdr_msg = malloc(xdr_msglen);
	u32 *p = (u32*)(xdr_msg+4);

	int xid = next_xid();

	p = xdr_encode_call(p, xid, PROG_MOUNT, PROG_MOUNT_VERSION, operation, AUTH_UNIX);
	p = xdr_encode_string(p, mount_path);

	assert(xdr_msg + xdr_msglen == (void*)p);

	int fd = get_connection(mount_port);
	if (fd < 0) {
		free(xdr_msg);
		ERR(-1, "error: connecting to MOUNT\n");
	}

	if (rpc_send(fd, xdr_msg, xdr_msglen) != 0) {
		free(xdr_msg);
		close(fd);
		ERR(-1, "error: contacting MOUNT\n");
	}

	free(xdr_msg);

	char *xdr_reply;
	int xdr_replylen;
	if (rpc_recv(fd, &xdr_reply, &xdr_replylen) != 0)
		return -EAGAIN;
	p = (u32*)xdr_reply;
	int len = xdr_replylen;

	close(fd);

	EXPECT(xid); EXPECT(REPLY); EXPECT(MSG_ACCEPTED);
	EXPECT(AUTH_NULL); EXPECT(0); EXPECT(SUCCESS);

	if (operation == PROG_MOUNT_MNT) {
		EXPECT_STATUS(STATUS_OK);
		p = xdr_decode_fh(p, fh, &len);
		if (!p) FAIL("expected file handle, got end-of-stream\n");
		// don't care about flavors that follow
	}

	free(xdr_reply);
	return 0;
}

int nfs_fd = -1;
int get_nfs_connection(void) {
	if (nfs_fd < 0) {
		nfs_fd = get_connection(nfs_port);
		if (nfs_fd < 0) {
			printf("nfs_get_connection: cannot open socket... giving up\n");
			if (nfs_is_mounted)
				nfs_umount();
			exit(1);
		}
	}
	return nfs_fd;
}

int renew_nfs_connection(void) {
	if (nfs_fd >= 0) close(nfs_fd);
	nfs_fd = -1;
	printf("lost connection... reopening\n");
	sleep(1);
	return get_nfs_connection();
}

void close_nfs_connection(void) {
	if (nfs_fd >= 0) close(nfs_fd);
	nfs_fd = -1;
	printf("lost connection...\n");
}

int nfs_init(char *serverip, char *mountpath, char *localmachinename, unsigned int euid) {
	int err;

	printf("nfs server: attempting to mount %s:%s\n", serverip, mountpath);
	printf("  using local machine name: %s\n", localmachinename);
	printf("           using linux uid: %d\n", euid);

	struct timeval tv;
	gettimeofday(&tv, NULL);
	last_xid = tv.tv_sec ^ tv.tv_usec;

	int a, b, c, d;
	if (sscanf(serverip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
		ERR(-1, "error: bad server ip: %s\n", serverip);

	server_addr[0] = a; server_addr[1] = b;
	server_addr[2] = c; server_addr[3] = d;
	
	mount_path = mountpath;
	local_machinename = localmachinename;
	uid = euid;

	err = portmapper_getport(PROG_NFS, PROG_NFS_VERSION, TRANSPORT_TCP, 0, &nfs_port);
	if (err)
		ERR(-1, "error: trying to get NFS port from PORTMAP service at %s\n", serverip);
	if (!nfs_port)
		ERR(-1, "error: NFS service not available at %s\n", serverip);


	err = prog_nullcall(nfs_port, PROG_NFS, PROG_NFS_VERSION);
	if (err)
		ERR(-1, "error: can not ping NFS on port %d\n", nfs_port);

	err = portmapper_getport(PROG_MOUNT, PROG_MOUNT_VERSION, TRANSPORT_TCP, 0, &mount_port);
	if (err)
		ERR(-1, "error: trying to get MOUNT port from PORTMAP service at %s\n", serverip);
	if (!nfs_port)
		ERR(-1, "error: NFS MOUNT service not available at %s\n", serverip);

	err = prog_nullcall(mount_port, PROG_MOUNT, PROG_MOUNT_VERSION);
	if (err)
		ERR(-1, "error: can not ping MOUNT on port %d\n", mount_port);

	return 0;
}

// warning: this is not a "safe" macro -- it is not wrapped inside brackets
#define RPC_TALK() \
		assert(xdr_msg + xdr_msglen == (void*)p); \
		int err; \
		err = rpc_send(fd, xdr_msg, xdr_msglen); \
		free(xdr_msg); \
		if (err == -EAGAIN) { \
			fd = renew_nfs_connection(); \
			continue; \
		} else if (err) { \
			close_nfs_connection(); \
			ERR(err_val, "error: sending rpc to NFS\n"); \
		} \
		\
		char *xdr_reply; \
		int xdr_replylen; \
		err = rpc_recv(fd, &xdr_reply, &xdr_replylen); \
		if (err == -EAGAIN) { \
			fd = renew_nfs_connection(); \
			continue; \
		} else if (err) { \
			close_nfs_connection(); \
			ERR(err_val, "error: receiving rpc from NFS\n"); \
		} \
		\
		p = (u32*)xdr_reply; \
		int len = xdr_replylen

static inline int xcallfhlen(struct nfs_node *node) {
  return hdr_len() + 4 + node->fh.len;
}

int nfs_get_attr(struct nfs_node *node)
{
	int err_val = -1;
	int i;

	if (!node)
		ERR(-1, "node is null in nfs_get_attr()\n");
	if (check_fh(node))
		ERR(-1, "bad fh in nfs_get_attr()\n");

	int fd = get_nfs_connection();
	int xid = next_xid();
	int err;

	for (i = 0; i < 3 && fd >= 0; i++) {
		int xdr_msglen = xcallfhlen(node);
		char *xdr_msg = malloc(xdr_msglen);
		u32 *p = (u32*)(xdr_msg+4);

		p = xdr_encode_call(p, xid, PROG_NFS, PROG_NFS_VERSION, PROG_NFS_GETATTR, AUTH_UNIX);
		p = xdr_encode_fh(p, &node->fh);

		RPC_TALK();

		EXPECT(xid); EXPECT(REPLY); EXPECT(MSG_ACCEPTED);
		EXPECT(AUTH_NULL); EXPECT(0); EXPECT(SUCCESS);

		EXPECT_STATUS(STATUS_OK);

		p = xdr_decode_attr(p, node, &len);
		if (!p) FAIL("expected file attributes, got end-of-stream\n");

		free(xdr_reply);

		return node->type;
	}
	ERR(-1, "error: too many lost connections... giving up\n");
}

int nfs_set_attr(struct nfs_node *node, int file_len)
{
	int err_val = -1;
	int i;

	if (!node)
		ERR(-1, "node is null in nfs_set_attr()\n");
	if (check_fh(node))
		ERR(-1, "bad fh in nfs_set_attr()\n");

	int fd = get_nfs_connection();
	int xid = next_xid();

	for (i = 0; i < 3 && fd >= 0; i++) {
		int xdr_msglen = xcallfhlen(node)+xsattrlenlen()+4;
		char *xdr_msg = malloc(xdr_msglen);
		u32 *p = (u32*)(xdr_msg+4);

		p = xdr_encode_call(p, xid, PROG_NFS, PROG_NFS_VERSION, PROG_NFS_SETATTR, AUTH_UNIX);
		p = xdr_encode_fh(p, &node->fh);
		p = xdr_encode_sattr_len(p, file_len);
		p = xdr_encode_int(p, 0); // guard

		RPC_TALK();

		EXPECT(xid); EXPECT(REPLY); EXPECT(MSG_ACCEPTED);
		EXPECT(AUTH_NULL); EXPECT(0); EXPECT(SUCCESS);

		EXPECT_STATUS(STATUS_OK);

		u32 have_pre, have_post;
		p = xdr_decode_wccdata(p, node, &len, &have_pre, &have_post);
		if (!p) FAIL("expected file attributes, got end-of-stream\n");

		free(xdr_reply);

		if (!have_post && nfs_get_attr(node) < 0)
			ERR(-1, "error: can't get attributes\n");

		fh_put(node); // update attributes

		return node->type;
	}
	ERR(-1, "error: too many lost connections... giving up\n");
}

struct nfs_node *make_node(struct nfs_node *node, struct nfs_node *parent, char *name, int have_attr) {
		if (!have_attr && nfs_get_attr(node) < 0)
			return NULL;

		struct nfs_node *ret_node = malloc(sizeof(struct nfs_node));
		memcpy(ret_node, node, sizeof(struct nfs_node));

		//ret_node->refcount = 1;
		//ret_node->parent = nfs_get(parent);
		ret_node->name = strdup(name);
		//ret_node->mtime.seconds = 0;
		//ret_node->mtime.nseconds = 0;
		ret_node->pages = NULL;

		return ret_node;
}

struct nfs_node *nfs_remove(struct nfs_node *parent, char *name)
{
	void *err_val = NULL;
	int i;

	if (!parent)
		ERR(NULL, "node is null in nfs_remove()\n");
	if (check_fh(parent))
		ERR(NULL, "bad fh in nfs_remove()\n");

	int fd = get_nfs_connection();
	int xid = next_xid();

	for (i = 0; i < 3 && fd >= 0; i++) {
		int xdr_msglen = xcallfhlen(parent)+xstrlen(name);
		char *xdr_msg = malloc(xdr_msglen);
		u32 *p = (u32*)(xdr_msg+4);

		p = xdr_encode_call(p, xid, PROG_NFS, PROG_NFS_VERSION, PROG_NFS_REMOVE, AUTH_UNIX);
		p = xdr_encode_fh(p, &parent->fh);
		p = xdr_encode_string(p, name);

		RPC_TALK();

		EXPECT(xid); EXPECT(REPLY); EXPECT(MSG_ACCEPTED);
		EXPECT(AUTH_NULL); EXPECT(0); EXPECT(SUCCESS);

		EXPECT_STATUS(STATUS_OK);

		u32 have_pre, have_post;
		p = xdr_decode_wccdata(p, parent, &len, &have_pre, &have_post);
		if (!p) FAIL("expected file attributes, got end-of-stream\n");

		free(xdr_reply);

		return 0;
	}
	ERR(NULL, "error: too many lost connections... giving up\n");
}

u32 *xdr_encode_cookie(u32 *p, struct nfs_readdir_cookie *cookie) {
	p = xdr_encode_hyper(p, cookie->cookie);
	int i;
	for (i = 0; i < NFS3_COOKIEVERFSIZE/4; i++)
		p = xdr_encode_int(p, cookie->cookieverf[i]);
	return p;
}

u32 *xdr_decode_cookieverf(u32 *p, struct nfs_readdir_cookie *cookie, int *len) {
	*len -= sizeof(NFS3_COOKIEVERFSIZE);
	if (*len < 0)
		return NULL;
	int i;
	for (i = 0; i < NFS3_COOKIEVERFSIZE/4; i++)
		p = xdr_decode_int(p, &cookie->cookieverf[i]);
	return p;
}

char *nfs_readdir(struct nfs_node *node, int *readlen, struct nfs_readdir_cookie *u_cookie, int *n, int *eod)
{
	void *err_val = NULL;
	int i;

	if (!node)
		ERR(NULL, "node is null in nfs_readdir()\n");
	if (check_fh(node))
		ERR(NULL, "bad fh in nfs_readdir()\n");

	int fd = get_nfs_connection();
	int xid = next_xid();

	struct nfs_readdir_cookie cookie;
	if (u_cookie)
		memcpy(&cookie, u_cookie, sizeof(struct nfs_readdir_cookie));
	else
		memset(&cookie, 0, sizeof(struct nfs_readdir_cookie));

	for (i = 0; i < 3 && fd >= 0; i++) {
		int xdr_msglen = xcallfhlen(node)+sizeof(struct nfs_readdir_cookie)+4;
		char *xdr_msg = malloc(xdr_msglen);
		u32 *p = (u32*)(xdr_msg+4);

		p = xdr_encode_call(p, xid, PROG_NFS, PROG_NFS_VERSION, PROG_NFS_READDIR, AUTH_UNIX);
		p = xdr_encode_fh(p, &node->fh);
		p = xdr_encode_cookie(p, &cookie);
		p = xdr_encode_int(p, 4096); // somewhat arbitrary

		RPC_TALK();

		EXPECT(xid); EXPECT(REPLY); EXPECT(MSG_ACCEPTED);
		EXPECT(AUTH_NULL); EXPECT(0); EXPECT(SUCCESS);

		EXPECT_STATUS(STATUS_OK);

		u32 have_attr;
		p = xdr_decode_postop(p, node, &len, &have_attr);
		if (!p) FAIL("expected file attributes, got end-of-stream\n");

		memset(&cookie, 0, sizeof(struct nfs_readdir_cookie));
		p = xdr_decode_cookieverf(p, &cookie, &len);
		if (!p) FAIL("expected cookieverf, got end-of-stream\n");

		// we arrange the data in a sequence of readlen bytes, with N cookie+string
		//  cookie-8-bytes, nulltermstring
		//  cookie-8-bytes, nulltermstring
		//  ...
		//  cookie-8-bytes, nulltermstring

		u32 has_entry;
		GET(&has_entry);

		char *buf = malloc(len); // len is plenty of space
		int n_read = 0;
		int pos = 0;

		while (has_entry) {
			n_read++;
			u64 fileid;
			u32 namelen;
			len -= 24; // fileid, namelen, has_entry for next iter, cookie
			if (len < 0) {
				free(buf);
				FAIL("error: expected directory entry header, got end-of-stream\n");
			}
			p = xdr_decode_hyper(p, &fileid);
			p = xdr_decode_int(p, &namelen);
			len -= (namelen+3)&(~0x3);
			if (len < 0) {
				free(buf);
				FAIL("error: expected directory entry name, got end-of-stream\n");
			}

			// write cookie (skiping ahead in input stream)
			xdr_decode_hyper(p+(namelen+3)/4, &cookie.cookie);
			memcpy(buf+pos, &cookie.cookie, 8);
			pos += 8;
			// write name
			memcpy(buf+pos, p, namelen);
			pos += namelen;
			p += (namelen+3)/4 + 2;
			// null terminate the string
			buf[pos++] = '\0';

			p = xdr_decode_int(p, &has_entry);
		}

		len -= 4;
		if (len < 0) {
			free(buf);
			FAIL("error: expected end-of-directory marker, got end-of-stream\n");
		}
		u32 end;
		p = xdr_decode_int(p, &end);
		*eod = end;

		*readlen = pos;
		*n = n_read;

		if (u_cookie)
			memcpy(u_cookie, &cookie, sizeof(struct nfs_readdir_cookie));

		free(xdr_reply);
		return buf;
	}
	ERR(NULL, "error: too many lost connections... giving up\n");
}

struct nfs_node *nfs_lookup(struct nfs_node *parent, char *name)
{
	void *err_val = NULL;
	int i;

	if (!parent)
		ERR(NULL, "node is null in nfs_lookup()\n");
	if (check_fh(parent))
		ERR(NULL, "bad fh in nfs_lookup()\n");

	int fd = get_nfs_connection();
	int xid = next_xid();

	for (i = 0; i < 3 && fd >= 0; i++) {
		int xdr_msglen = xcallfhlen(parent)+xstrlen(name);
		char *xdr_msg = malloc(xdr_msglen);
		u32 *p = (u32*)(xdr_msg+4);

		p = xdr_encode_call(p, xid, PROG_NFS, PROG_NFS_VERSION, PROG_NFS_LOOKUP, AUTH_UNIX);
		p = xdr_encode_fh(p, &parent->fh);
		p = xdr_encode_string(p, name);

		RPC_TALK();

		EXPECT(xid); EXPECT(REPLY); EXPECT(MSG_ACCEPTED);
		EXPECT(AUTH_NULL); EXPECT(0); EXPECT(SUCCESS);

		//printf("lookup parent="); debug_print_fh(&parent->fh); printf("\n  name=%s\n", name);

		EXPECT_STATUS(STATUS_OK);

		struct nfs_node node;
		p = xdr_decode_fh(p, &node.fh, &len);
		if (!p) FAIL("expected file handle, got end-of-stream\n");

		u32 have_attr;
		p = xdr_decode_postop(p, &node, &len, &have_attr);
		if (!p) FAIL("expected file attributes, got end-of-stream\n");

		free(xdr_reply);

		struct nfs_node *ret_node = malloc(sizeof(struct nfs_node));
		memcpy(ret_node, &node, sizeof(struct nfs_node));

		return make_node(&node, parent, name, have_attr);
	}
	ERR(NULL, "error: too many lost connections... giving up\n");
}

int nfs_read(struct nfs_node *node, u64 offset, char *page)
{
	int err_val = -1;
	int i;
	int readlen = 4096;

	if (!node)
		ERR(-1, "node is null in nfs_read()\n");
	if (check_fh(node))
		ERR(-1, "bad fh in nfs_read()\n");

	int fd = get_nfs_connection();
	int xid = next_xid();

	for (i = 0; i < 3 && fd >= 0; i++) {
		int xdr_msglen = xcallfhlen(node)+8+4;
		char *xdr_msg = malloc(xdr_msglen);
		u32 *p = (u32*)(xdr_msg+4);

		p = xdr_encode_call(p, xid, PROG_NFS, PROG_NFS_VERSION, PROG_NFS_READ, AUTH_UNIX);
		p = xdr_encode_fh(p, &node->fh);
		p = xdr_encode_hyper(p, offset);
		p = xdr_encode_int(p, readlen);

		RPC_TALK();

		EXPECT(xid); EXPECT(REPLY); EXPECT(MSG_ACCEPTED);
		EXPECT(AUTH_NULL); EXPECT(0); EXPECT(SUCCESS);

		EXPECT_STATUS(STATUS_OK);

		u32 have_attr;
		p = xdr_decode_postop(p, node, &len, &have_attr);
		if (!p) FAIL("expected file attributes, got end-of-stream\n");

		u32 count, count2, eof;
		GET(&count);
		GET(&eof);
		GET(&count2);

		if (count != count2) FAIL("too few bytes in reply: %d instead of %d\n", count2, count);
		if (count > readlen) FAIL("wanted to read %d bytes, got %d instead\n", readlen, count);

		if (len < count) FAIL("expected file data, got end-of-stream\n");
		
		//*readlen = count;
		//char *buf = malloc(count);
		memcpy(page, p, count);

		free(xdr_reply);
		return count;
	}
	ERR(-1, "error: too many lost connections... giving up\n");
}

int nfs_write(struct nfs_node *node, u64 offset, char *data, int writelen, int commit_unused)
{
	int err_val = -1;
	int i;

	if (!node)
		ERR(-1, "node is null in nfs_write()\n");
	if (check_fh(node))
		ERR(-1, "bad fh in nfs_write()\n");

	int fd = get_nfs_connection();
	int xid = next_xid();

	for (i = 0; i < 3 && fd >= 0; i++) {
		int xdr_msglen = xcallfhlen(node)+8+4+4+4+4*((writelen+3)/4);
		char *xdr_msg = malloc(xdr_msglen);
		u32 *p = (u32*)(xdr_msg+4);

		p = xdr_encode_call(p, xid, PROG_NFS, PROG_NFS_VERSION, PROG_NFS_WRITE, AUTH_UNIX);
		p = xdr_encode_fh(p, &node->fh);
		p = xdr_encode_hyper(p, offset);
		p = xdr_encode_int(p, writelen);
		p = xdr_encode_int(p, FILE_SYNC); /* maybe todo: async writes */
		p = xdr_encode_int(p, writelen);
		p = xdr_encode_array(p, data, writelen);

		RPC_TALK();

		EXPECT(xid); EXPECT(REPLY); EXPECT(MSG_ACCEPTED);
		EXPECT(AUTH_NULL); EXPECT(0); EXPECT(SUCCESS);

		EXPECT_STATUS(STATUS_OK);

		u32 have_pre, have_post;
		p = xdr_decode_wccdata(p, node, &len, &have_pre, &have_post);
		if (!p) FAIL("expected file attributes, got end-of-stream\n");

		u32 count;
		GET(&count);
		EXPECT(FILE_SYNC);

		free(xdr_reply);

		if (!have_post && nfs_get_attr(node) < 0)
			ERR(-1, "error: can't get attributes\n");

		fh_put(node); // update attributes

		return count;
	}
	ERR(-1, "error: too many lost connections... giving up\n");
}

struct nfs_node *nfs_create(struct nfs_node *parent, char *name, int overwrite)
{
	void *err_val = NULL;
	int i;

	if (!parent)
		ERR(NULL, "node is null in nfs_create()\n");
	if (check_fh(parent))
		ERR(NULL, "bad fh in nfs_create()\n");

	int fd = get_nfs_connection();
	int xid = next_xid();

	for (i = 0; i < 3 && fd >= 0; i++) {
		int xdr_msglen = xcallfhlen(parent)+xstrlen(name)+4+xsattrmodelen();
		char *xdr_msg = malloc(xdr_msglen);
		u32 *p = (u32*)(xdr_msg+4);

		p = xdr_encode_call(p, xid, PROG_NFS, PROG_NFS_VERSION, PROG_NFS_CREATE, AUTH_UNIX);
		p = xdr_encode_fh(p, &parent->fh);
		p = xdr_encode_string(p, name);
		p = xdr_encode_int(p, (overwrite?UNCHECKED:GUARDED));
		p = xdr_encode_sattr_mode(p);

		RPC_TALK();

		EXPECT(xid); EXPECT(REPLY); EXPECT(MSG_ACCEPTED);
		EXPECT(AUTH_NULL); EXPECT(0); EXPECT(SUCCESS);

		EXPECT_STATUS(STATUS_OK);

		EXPECT(1); // insist that the file handle follows

		struct nfs_node node;
		p = xdr_decode_fh(p, &node.fh, &len);
		if (!p) FAIL("expected file handle, got end-of-stream\n");

		u32 have_attr;
		p = xdr_decode_postop(p, &node, &len, &have_attr);
		if (!p) FAIL("expected file attributes, got end-of-stream\n");

		free(xdr_reply);

		return make_node(&node, parent, name, have_attr);
	}
	ERR(NULL, "error: too many lost connections... giving up\n");
}

int nfs_mount(void)
{
	//root_node.parent = NULL;
	root_node.name = mount_path;
	//root_node.refcount = 1;
	if (mount_call(PROG_MOUNT_MNT, &root_node.fh) < 0) {
		ERR(-1, "error: can't mount root directory\n");
	}
	if (nfs_get_attr(&root_node) != NFS_DIRECTORY) {
		ERR(-1, "error: can't get attributes of root directory\n");
	}
	nfs_is_mounted = 1;
	return 0;
}

int nfs_umount(void)
{
	return mount_call(PROG_MOUNT_UMNT, NULL);
}


#ifndef __NEXUS__
int main(int ac, char **av) {

	if (nfs_init("127.0.0.1", "/tftpboot-ashieh", "nexus.systems.cs.cornell.edu", 968) != 0) {
		printf("nfs_init: failed\n");
		exit(1);
	}

	if (nfs_mount() != 0) {
		printf("nfs_mount: failed\n");
		exit(1);
	}

	printf("got root node : "); debug_print_node(&root_node); printf("\n");

	struct nfs_node *sub_node = nfs_lookup(&root_node, "hello");
	if (sub_node == NULL) {
		printf("can't open file\n");
		exit(1);
	}
	printf("got sub node  : "); debug_print_node(sub_node); printf("\n");

	int len = (int)sub_node->size;
	char data[4096];
	int count = nfs_read(sub_node, 0, data);
	if (count <= 0) {
		printf("can't read file\n");
	} else {
		printf("got %d bytes of data: %c %c %c %c %c...\n", len,
				data[0], data[1], data[2], data[3], data[4]);
		//write(1, data, len);
	}

	struct nfs_node *sub_dir = nfs_lookup(&root_node, "nexus");
	if (sub_dir == NULL) {
		printf("can't open subdir\n");
		exit(1);
	}
	printf("got sub dir  : "); debug_print_node(sub_dir); printf("\n");

	sub_dir = nfs_lookup(sub_dir, "io");
	if (sub_dir == NULL) {
		printf("can't open subdir\n");
		exit(1);
	}
	printf("got sub dir  : "); debug_print_node(sub_dir); printf("\n");

	// list the root directory
	int dirlen, dircount, dirend;
	struct nfs_readdir_cookie cookie;
	memset(&cookie, 0, sizeof(cookie));
	do {
		char *dirdata = nfs_readdir(sub_dir, &dirlen, &cookie, &dircount, &dirend);
		if (!dirdata) {
			printf("readdir failed for root\n");
			break;
		}

		int i;
		char *c = dirdata;
		printf("readdir returned %d entries (%d bytes):\n", dircount, dirlen);
		while (dirlen >= 9) {
			printf("  [");
			for (i = 0; i < 8; i++) printf("%02x", c[i] & 0xff);
			memcpy(&cookie.cookie, c, 8); // save the last cookie, in case we have another iter
			printf("] %s\n", c+8);
			int n = 8 + strlen(c+8) + 1;
			dirlen -= n;
			c += n;
		}
		if (dirlen != 0) {
			printf("(%d bytes leftover at end)\n", dirlen);
		}
		free(dirdata);
	} while (!dirend);

	struct nfs_node *copy = nfs_create(&root_node, "copy.txt", 1);
	if (!copy) {
		printf("can't create copy\n");
	} else {
		len = nfs_write(copy, 0, "hello world\n", strlen("hello world\n"), 0);
		if (len != strlen("hello world\n")) {
			printf("wrote only %d bytes out of %d\n", len, strlen("hello world\n"));
		} else {
			printf("wrote file copy.txt\n");
		}
	}

	if (nfs_is_mounted) {
		if (nfs_umount() != 0) {
			printf("nfs_umount: failed\n");
			exit(1);
		}
	}

	return 0;
}
#endif
