#ifndef NQ_SOCKET_H_SHIELD
#define NQ_SOCKET_H_SHIELD

#ifdef __cplusplus
extern "C" {
#endif

#include <nq/netquery.h>

typedef struct NQ_RingBuffer {
  unsigned char *data;
  unsigned int size;
  unsigned int read_pos;
  unsigned int write_pos;
} NQ_RingBuffer;

struct SocketStats {
  int read_contended;
  int write_contended;
  int corked;
  int uncorked;
};

extern struct SocketStats socket_stats;

int NQ_RingBuffer_init(NQ_RingBuffer *buff);
int NQ_RingBuffer_destroy(NQ_RingBuffer *buff);

unsigned int NQ_RingBuffer_size(NQ_RingBuffer *buff);
unsigned int NQ_RingBuffer_peek(NQ_RingBuffer *buff, unsigned char *data, unsigned int datalen);
unsigned int NQ_RingBuffer_nocopy_read(NQ_RingBuffer *buff, unsigned char **data);
unsigned int NQ_RingBuffer_nocopy_write(NQ_RingBuffer *buff, unsigned char **data);
unsigned int NQ_RingBuffer_data(NQ_RingBuffer *buff);
void NQ_RingBuffer_resize(NQ_RingBuffer *buff, unsigned int newsize);
void NQ_RingBuffer_skip(NQ_RingBuffer *buff, unsigned int len);
void NQ_RingBuffer_push(NQ_RingBuffer *buff, unsigned int len);
unsigned int NQ_RingBuffer_read(NQ_RingBuffer *buff, unsigned char *data, unsigned int datalen);
unsigned int NQ_RingBuffer_write(NQ_RingBuffer *buff, unsigned char *data, unsigned int datalen);

typedef struct NQ_Socket NQ_Socket;
typedef struct NQ_Socketpool NQ_Socketpool;

typedef void *(NQ_Net_Accept_cb)(NQ_Socket *server, NQ_Socket *sock);
typedef void (NQ_Net_Data_cb)(NQ_Socket *sock);
typedef void(NQ_Net_Error_cb)(NQ_Socket *sock);

NQ_Socketpool *NQ_Socketpool_create(NQ_Net_Accept_cb *accept, NQ_Net_Data_cb *data, NQ_Net_Error_cb *error);
void NQ_Socketpool_destroy(NQ_Socketpool *pool);

void NQ_Socketpool_unblock(NQ_Socketpool *pool);
void NQ_Socket_poll(NQ_Socketpool *pool, int timeout);

NQ_Socket *NQ_Socket_connect(NQ_Socketpool *pool, unsigned int ip, unsigned short port, void *userdata);
NQ_Socket *NQ_Socket_listen(NQ_Socketpool *pool, unsigned short port, void *userdata);
void NQ_Socket_close(NQ_Socket *socket);
void NQ_Socket_set_userdata(NQ_Socket *socket, void *userdata);
void *NQ_Socket_userdata(NQ_Socket *socket);
unsigned int NQ_Socket_peer(NQ_Socket *socket);
unsigned short NQ_Socket_peerport(NQ_Socket *socket);

NQ_Host NQ_Socket_get_host(NQ_Socket *socket);

int NQ_Socket_read(NQ_Socket *socket, unsigned char *buff, int len);
int NQ_Socket_peek(NQ_Socket *socket, unsigned char *buff, int len);
int NQ_Socket_write(NQ_Socket *socket, unsigned char *buff, int len);

void NQ_Socket_write_start(NQ_Socket *socket);
int NQ_Socket_write_partial(NQ_Socket *socket, unsigned char *buff, int len);
void NQ_Socket_write_flush(NQ_Socket *socket);

int NQ_Socket_data(NQ_Socket *socket);

void NQ_Socket_start_bundle(NQ_Socket *socket);
void NQ_Socket_finish_bundle(NQ_Socket *socket);
int NQ_Socket_in_bundle(NQ_Socket *socket);

#ifdef __cplusplus
}
#endif

#endif
