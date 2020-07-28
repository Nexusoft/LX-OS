
#ifndef OVERLAY_H_SHIELD
#define OVERLAY_H_SHIELD

typedef struct bol_header_t {
	enum {BOL_MEMBERLIST, BOL_ERROR, BOL_WITHDRAW} type;
	unsigned int length;
} bol_header;

typedef enum {
	BOL_ERR_BAD_UPDATE,
	BOL_ERR_NO_WITHDRAWAL,
	BOL_ERR_BAD_ND_UPDATE,
	BOL_ERR_UNAUTHORIZED_CONNECT,
	BOL_ERR_PANIC_LOST_OVERLAY,
	BOL_ERR_DISCONNECTED,
} bol_error;

typedef struct bol_error_withdrawal_t {
	unsigned int reporting_AS;
	unsigned int seqno;
	unsigned int withdrawn_seqno;
} bol_error_withdrawal;

#define BOL_ERROR_REPORT_LEN(a) ((7+a)*sizeof(int) + sizeof(bol_error))

typedef struct bol_error_report_t {
	unsigned int reporting_AS;
	unsigned int affected_AS;
	int knowledge;
	bol_error error;
	unsigned int seqno;
	int prefix_len;
	unsigned int prefix;
	int aspath_len;
	unsigned int aspath[];
} bol_error_report;

typedef struct bol_member_msg_t {
	unsigned int AS;
	unsigned int ip;
	unsigned int version;
	unsigned int seqno;
	unsigned int port;
} bol_member_msg;

#define BOL_MEMBER_LIST_LEN(a) (sizeof(int) + (sizeof(bol_member_msg) * a))

typedef struct bol_member_list_t {
	unsigned int length;
	bol_member_msg members[];
} bol_member_list;

#define BOL_ERROR_LIST_LEN (2*sizeof(bol_error_list *) + sizeof(time_t))

typedef struct bol_error_list_t {
	struct bol_error_list_t *next, *prev;
	time_t wd_timestamp;
	bol_error_report *report;
} bol_error_list;

//bol_member entries will start off bzeroed.  When creating variables, account
//for this.
typedef struct bol_member_t {
	enum {BOL_UNSEEN = 0, BOL_CONNECTED, BOL_DISCONNECTED, BOL_SELF} status;
	unsigned int ip, version, seqno, port;
} bol_member;

typedef struct bol_peer_t {
	unsigned int ip, port;
	int socket;
	time_t last_attempt;
	int attempts;
	int read;
	bol_header header;
	unsigned char *buffer;
	struct bol_peer_t *next;
} bol_peer;

typedef struct bol_info_t {
	bol_member *member_list;
	bol_peer *peer_list;
	bol_error_list *error_list; //there has to be a more efficient way
	int socket;
	unsigned int ip, port, as;
} bol_info;


void bol_add_ol_connection(int ip, bol_info *info);
void bol_add_peer(unsigned int ip, unsigned int port, bol_info *info);
bol_info *bol_initialize();
void bol_set_ip(bol_info *info, unsigned int ip, unsigned int port, unsigned int AS);
int bol_set_select_fd(bol_info *info, fd_set *fds, fd_set *writes, fd_set *exception);
void bol_check_data(bol_info *info, fd_set *fds, fd_set *writes, fd_set *exception);

int bol_inject_badUpdate(bol_info *info, unsigned int affected_AS, int knowledge, int prefix_len, unsigned int prefix, int aspath_len, unsigned short *aspath);
void bol_inject_withdrawal(bol_info *info, int withdrawal);


#endif
