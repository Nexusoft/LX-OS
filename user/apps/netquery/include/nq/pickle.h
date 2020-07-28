#ifndef _PICKLE_H_
#define _PICKLE_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NQ_Request_Header {
  unsigned int length;
  unsigned int type;

  unsigned int id;
  int error;
} __attribute__((packed)) NQ_Request_Header;

struct NQ_Request_Pending;
typedef struct NQ_Request_Pending NQ_Request_Pending;
typedef struct NQ_Request_Data {
  NQ_Request_Header header;
  unsigned char *data;
  NQ_Request_Pending *localrequest;
} NQ_Request_Data;

void NQ_Request_respond(NQ_Socket *sock, NQ_RingBuffer *buff, NQ_Request_Data *req, int error);

#define MAKE_PICKLE(type, name) \
  void NQ_Request_pickle_##name(NQ_RingBuffer *buff, type output)
#define MAKE_UNPICKLE(type, name) \
  type NQ_Request_unpickle_##name(unsigned char **data, int *len, int *err)

#define DEFINE_PICKLE(type, name) \
  MAKE_PICKLE(type, name);	  \
  MAKE_UNPICKLE(type, name);

DEFINE_PICKLE(int, int)
DEFINE_PICKLE(NQ_UUID, uuid)
DEFINE_PICKLE(NQ_Host, host)

#undef DEFINE_PICKLE
#undef MAKE_PICKLE
#undef MAKE_UNPICKLE

void NQ_Request_pickle_attribute_name(NQ_RingBuffer *buff, NQ_Attribute_Name *name);
void NQ_Request_pickle_trigger_description(NQ_RingBuffer *output, NQ_Trigger_Description *description);

struct WG_PingInfo {
  int request_id;
  char *file;
  int line_num;
};
extern struct WG_PingInfo last_wg_ping;
#define WG_PING(REQ) do { last_wg_ping.request_id = REQ; last_wg_ping.file = __FILE__; last_wg_ping.line_num = __LINE__; } while(0)

#ifdef __cplusplus
}
#endif

#endif // _PICKLE_H_
