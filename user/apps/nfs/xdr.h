#ifndef XDR_H
#define XDR_H

#include <string.h>
#include <netinet/in.h>

#ifndef NEXUS
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
#else
#include <nexus/types.h>
#endif

static inline u32 * xdr_encode_hyper(u32 *p, u64 val)
{
	*p++ = htonl(val >> 32);
	*p++ = htonl(val & 0xFFFFFFFF);
	return p;
}

static inline u32 * xdr_decode_hyper(u32 *p, u64 *valp)
{
	*valp  = ((u64) ntohl(*p++)) << 32;
	*valp |= ntohl(*p++);
	return p;
}

static inline u32 * xdr_encode_int(u32 *p, u32 val)
{
	*p++ = htonl(val);
	return p;
}

static inline u32 * xdr_decode_int(u32 *p, u32 *valp) {
	*valp = ntohl(*p++);
	return p;
}

static inline int xstrlen(char *p) {
	return 4+((strlen(p)+3)&(~0x3));
}

extern u32 * xdr_encode_array(u32 *p, const char *s, unsigned int len);
extern u32 * xdr_encode_string(u32 *p, const char *s);

extern u32 *xdr_decode_string(u32 *p, int *plen, char **s);

enum msg_type {
	CALL = 0,
	REPLY = 1
};
enum reply_stat {
	MSG_ACCEPTED = 0,
	MSG_DENIED = 1
};
enum accept_stat {
	SUCCESS       = 0, /* RPC executed successfully       */
	PROG_UNAVAIL  = 1, /* remote hasn't exported program  */
	PROG_MISMATCH = 2, /* remote can't support version #  */
	PROC_UNAVAIL  = 3, /* program can't support procedure */
	GARBAGE_ARGS  = 4  /* procedure can't decode params   */
};
enum reject_stat {
	RPC_MISMATCH	= 0, /* RPC version number != 2          */
	AUTH_ERROR		= 1  /* remote can't authenticate caller */
};
enum auth_stat {
	AUTH_BADCRED      = 1,  /* bad credentials (seal broken) */
	AUTH_REJECTEDCRED = 2,  /* client must begin new session */
	AUTH_BADVERF      = 3,  /* bad verifier (seal broken)    */
	AUTH_REJECTEDVERF = 4,  /* verifier expired or replayed  */
	AUTH_TOOWEAK      = 5   /* rejected for security reasons */
};

enum auth_flavor {
	AUTH_NULL       = 0,
	AUTH_UNIX       = 1,
	AUTH_SHORT      = 2,
	AUTH_DES        = 3
};

extern u32 * xdr_encode_authnull(u32 *p);

extern u32 * xdr_encode_authunix(u32 *p, char *uname, u32 uid);

int rpc_send(int fd, char *data, int nbytes);
int rpc_recv(int fd, char **data, int *nbytes);

#if 0 // for reference only

typedef struct call_body {
	unsigned int rpcvers;       /* must be equal to two (2) */
	unsigned int prog;
	unsigned int vers;
	unsigned int proc;
	opaque_auth cred;
	opaque_auth verf;
	/* procedure specific parameters start here */
} call_body;

typedef struct accepted_reply {
	opaque_auth verf;
	enum accept_stat stat;
	union {
			char results[0];
			struct {
				unsigned int low;
				unsigned int high;
			} mismatch_info;
	} reply_data;
} accepted_reply;

typedef struct rejected_reply {
	enum reject_stat stat;
	union {
		struct {
			unsigned int low;
			unsigned int high;
		} mismatch_info;
		enum auth_stat stat;
	} reply_data;
} rejected_reply;

typedef struct reply_body {
	enum reply_stat stat;
	union {
		accepted_reply areply;
		rejected_reply rreply;
	} reply;
} reply_body;

typedef struct rpc_msg {
	unsigned int xid;
	enum msg_type type;
	union {
		call_body cbody;
		reply_body rbody;
	} body;
} rpc_msg;

#endif // 0

#endif // XDR_H
