#define MAX_BACKLOG 50

struct Endpoint {
	in_addr addr;
	unsigned short port;
};

struct Flow {
	Endpoint from, to;
	bool operator< (const Flow &other) const {
		return memcmp(this, &other, sizeof(*this)) < 0;
	}
};
struct reassemble_params {
  Minipipe *pipe;
  const char *filter;
  const char *device;
  int time;
};
void reassemble_main(reassemble_params *params);

typedef void (*TCPWriter)(const Flow &flow, const unsigned char *data, int len);
typedef void (*TCPGapHandler)(const Flow &flow, int len);

struct ShortPacket {
  int len;
  char data[];
};

struct Packet {
	Packet(const unsigned char *_data, unsigned int _seq, unsigned int _len);
	inline Packet(const Packet &other) { assign(other); }
	Packet &operator=(const Packet &other);
	inline ~Packet(void) { release(); }
	unsigned int seq;
	unsigned short len, *refcnt;
	unsigned char *data;
private:
	void assign(const Packet &other);
	void release(void);
};

inline bool operator< (const Packet &a, const Packet &b) {return a.seq<b.seq;}

struct TCPStream {
  TCPStream(Flow &_flow, TCPWriter _output, TCPGapHandler _gap)
    : received_one(false), flow(_flow), output(_output), gap(_gap) {}
  void push_packet(const unsigned char *packet, unsigned int seq, unsigned int len);
  
  int is(Flow _flow);
  Ghetto_PQueue buf;
  unsigned int expected_seq;
  bool received_one;
  Flow flow;
  TCPWriter output;
  TCPGapHandler gap;
};
