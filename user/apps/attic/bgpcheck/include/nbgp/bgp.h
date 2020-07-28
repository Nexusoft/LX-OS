
#ifndef BGP_H_SHIELD
#define BGP_H_SHIELD

//Customization interface
#define PIPE_TYPE bgp_datasource_ptr

struct bgp_datasource {
  enum {BGP_PIPE=1, BGP_BUFFER=2, BGP_VECTOR = 3} type;
  union {
    int pipe;
    struct {
      int cursor;
      int len;
      char *buff;
    } buffer;
    struct {
      int bcursor;
      int cursor;
      int *len;
      int blen;
      char **buff;
    } vector;
  } contents;
  int error;
};
typedef struct bgp_datasource bgp_datasource, *bgp_datasource_ptr;

//OPEN packet parameter flags
#define BGP_OPEN_AUTH_PRESENT (0x1)

//General Constants
#define BGP_MARKER_LENGTH 16
#define BGP_HEADER_LENGTH (BGP_MARKER_LENGTH+2+1)
#define BGP_OPEN_LENGTH (1+2+2+4)
#ifdef USING_SENSOR_DATA
#define DUMP_LENGTH (12+16)
#else
#define DUMP_LENGTH (0)
#endif

// Status messages
#define DEBUG_STATUS (1 << 0)
// Improperly formatted packet
#define DEBUG_FORMAT (1 << 1)
// Internal error that prevents continued operation
#define DEBUG_INTERNAL (1 << 2)
// Buffer-pipe doesn't have enough data in it to continue parsing
#define DEBUG_DATA (1 << 3)

//Structures
typedef struct bgp_ipmaskvec_t {
	unsigned int mask;
	unsigned int ip;
	struct bgp_ipmaskvec_t *next;
} bgp_ipmaskvec;

typedef struct bgp_as_path_t {
	short type;
	short len;
	unsigned short* list;
	struct bgp_as_path_t *next;
} bgp_as_path;

typedef struct bgp_packet_t {
	unsigned char marker[BGP_MARKER_LENGTH];
	enum { OPEN = 1, UPDATE = 2, NOTIFICATION = 3, KEEPALIVE = 4 } type;
	union {
		struct {
			unsigned short version;
			unsigned short sysid;
			unsigned short holdtime;
			unsigned int identifier;
			long int flags;
		} OPEN;
		struct {
			bgp_ipmaskvec *withdrawv;
			bgp_ipmaskvec *destv;
			bgp_ipmaskvec *withdrawv_store;
			bgp_ipmaskvec *destv_store;
			bgp_as_path *as_path;
			bgp_as_path *as_path_store;
			short num_communities;
			unsigned int *communities;
			int origin;
			int nexthop;
			unsigned int aggregator;
			int med;
			int preference;
			unsigned short *as_path_buf;
			unsigned short as_path_len;
			unsigned short withdrawv_len;
			unsigned short destv_len;
			unsigned short as_path_buf_len;
			unsigned short as_path_buf_fill;
			unsigned short communities_len;
		} UPDATE;
		struct {
			unsigned char error_code;
			unsigned char error_subcode;
		} NOTIFICATION;
	} contents;
} bgp_packet;

void bgp_print_hex(unsigned char *c, int len);
void bgp_print_ip(int i);
void bgp_timestamp(void);

//BGP packet interface
unsigned int bgp_read_packet(PIPE_TYPE pipe, bgp_packet *packet);
void bgp_print_aspath(bgp_packet *p);
void bgp_print_packet(bgp_packet *p);
void bgp_init_packet(bgp_packet *p);
void bgp_cleanup_packet(bgp_packet *p);

#endif
