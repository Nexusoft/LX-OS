#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <nq/netquery.h>
#include <nq/net.h>
#include <nq/gcmalloc.h>
#include <nq/util.hh>

#include <signal.h>

//the cost of a memcpy is subsumed by the cost of lots of writes.  Should modify ringbuffer to use iovecs
#define POLL_NOCOPY

struct SocketStats socket_stats;

void NQ_Socket_error_event(NQ_Socket *socket);

void NQ_RingBuffer_dump(NQ_RingBuffer *buff){
  unsigned char *data = alloca(NQ_RingBuffer_data(buff));
  NQ_RingBuffer_peek(buff, data, NQ_RingBuffer_data(buff));
  print_hex(data, NQ_RingBuffer_data(buff));
  printf("\nread @ %d; write @ %d; buffer size: %d\n", buff->read_pos, buff->write_pos, buff->size);
}

unsigned int NQ_RingBuffer_size(NQ_RingBuffer *buff){
  if(buff->write_pos < buff->read_pos){
    return (buff->size - buff->read_pos) + buff->write_pos;
  } else {
    return buff->write_pos - buff->read_pos;
  }
}

unsigned int NQ_RingBuffer_peek(NQ_RingBuffer *buff, unsigned char *data, unsigned int datalen){
  unsigned int readlen = 0;
  if(buff->data == NULL){
    return 0;
  }
  if(buff->write_pos < buff->read_pos){
    readlen = datalen;
    if(readlen > (buff->size - buff->read_pos)){
      readlen = (buff->size - buff->read_pos);
    }
    if(readlen > 0){
      memcpy(data, &(buff->data[buff->read_pos]), readlen);
    }
    if(readlen < datalen){
      datalen -= readlen;
      if(datalen > buff->write_pos){
        datalen = buff->write_pos;
      }
      if(datalen > 0){
        memcpy(&(data[readlen]), buff->data, datalen);
      }
      readlen += datalen;
    }
  } else {
    readlen = datalen;
    if(readlen > (buff->write_pos - buff->read_pos)){
      readlen = (buff->write_pos - buff->read_pos);
    }
    if(readlen > 0){
      memcpy(data, &(buff->data[buff->read_pos]), readlen);
    }
  }
  return readlen;
}

unsigned int NQ_RingBuffer_nocopy_read(NQ_RingBuffer *buff, unsigned char **data){
  assert(data);
  *data = &(buff->data[buff->read_pos]);
  if(buff->write_pos < buff->read_pos){
    return buff->size - buff->read_pos;
  } else {
    return buff->write_pos - buff->read_pos;
  }
}

unsigned int NQ_RingBuffer_nocopy_write(NQ_RingBuffer *buff, unsigned char **data){
  assert(data);
  if(NQ_RingBuffer_data(buff)+20 >= buff->size){
    NQ_RingBuffer_resize(buff, (buff->size + 20) * 2);
  }
  *data = &(buff->data[buff->write_pos]);
  if(buff->write_pos < buff->read_pos){
    return buff->read_pos - buff->write_pos - 1;
  } else {
    if(buff->read_pos == 0){
      //don't want write_pos to move ontop of read_pos.  The subsequent op will
      //either result in a 1b read, or a buffer resize.  
      //That said, if the read_pos is at 0, the buffer resize is the more likely case.
      return buff->size - buff->write_pos - 1;
    } else {
      return buff->size - buff->write_pos;
    }
  }
}

unsigned int NQ_RingBuffer_data(NQ_RingBuffer *buff){
  if(buff->write_pos < buff->read_pos){
    return buff->size - (buff->read_pos - buff->write_pos);
  } else {
    return buff->write_pos - buff->read_pos;
  }
}

void NQ_RingBuffer_skip(NQ_RingBuffer *buff, unsigned int len){
  if(len > NQ_RingBuffer_data(buff)){
    len = NQ_RingBuffer_data(buff);
  }
  if(len > 0){
    buff->read_pos += len;
    buff->read_pos %= buff->size;
  }
}

void NQ_RingBuffer_push(NQ_RingBuffer *buff, unsigned int len){
  buff->write_pos += len;
  buff->write_pos %= buff->size;
}

unsigned int NQ_RingBuffer_read(NQ_RingBuffer *buff, unsigned char *data, unsigned int datalen){
  unsigned int readlen = NQ_RingBuffer_peek(buff, data, datalen);
  NQ_RingBuffer_skip(buff, readlen);
  return readlen;
}

void NQ_RingBuffer_resize(NQ_RingBuffer *buff, unsigned int newsize){
  if(newsize > buff->size){
    unsigned char *newbuff;
    unsigned int space_used = NQ_RingBuffer_data(buff);
    newbuff = malloc(newsize);
    if(buff->data){
      NQ_RingBuffer_peek(buff, newbuff, space_used);
      free(buff->data);
    }
    buff->data = newbuff;
    buff->size = newsize;
    buff->read_pos = 0; 
    buff->write_pos = space_used;
  }
}

unsigned int NQ_RingBuffer_write(NQ_RingBuffer *buff, unsigned char *data, unsigned int datalen){
  unsigned int space_used = NQ_RingBuffer_data(buff);
  if(space_used + datalen >= buff->size){ //make size double current requirements.
    unsigned int halfmax = ((~0)>>1);
    if((buff->size >= halfmax)||(datalen >= halfmax)||((buff->size + datalen) >= halfmax)){
      return 0; //oops.
    }
    NQ_RingBuffer_resize(buff, (buff->size + datalen)*2);
  }
  if(buff->write_pos + datalen > buff->size){
    unsigned int split = buff->size - buff->write_pos;
    memcpy(&(buff->data[buff->write_pos]), data, split);
    memcpy(buff->data, &(data[split]), datalen-split);
    buff->write_pos = datalen-split;
  } else {
    memcpy(&(buff->data[buff->write_pos]), data, datalen);
    buff->write_pos += datalen;
  }
  buff->write_pos %= buff->size;
  return datalen;
}

int NQ_RingBuffer_init(NQ_RingBuffer *buff){
  bzero(buff, sizeof(NQ_RingBuffer));
  NQ_RingBuffer_resize(buff, 100);
  return 0;
}
int NQ_RingBuffer_destroy(NQ_RingBuffer *buff){
  if(buff->data) { free(buff->data); }
  return 0;
}

///////
/// MUTEX PRIORITY ORDER
///////
// 1) Socketpool mutex
// 2) Socket write mutex
// 3) Socket read mutex
//
// If you own a mutex in the list, you CAN NOT obtain a mutex with an earlier identifier
// without releasing all of the listed mutexes.
////////

struct NQ_Socketpool {
  Queue sockets;
  NQ_Net_Accept_cb *accept;
  NQ_Net_Data_cb *data;
  NQ_Net_Error_cb *error;
  pthread_mutex_t lock;
  int unblocker[2];
};

NQ_Socketpool *NQ_Socketpool_create(NQ_Net_Accept_cb *accept, NQ_Net_Data_cb *data, NQ_Net_Error_cb *error){
  NQ_Socketpool *pool = malloc(sizeof(NQ_Socketpool));
  bzero(pool, sizeof(NQ_Socketpool));
  queue_initialize(&pool->sockets);
  pthread_mutex_init(&pool->lock, NULL);
  pool->accept = accept;
  pool->data = data;
  pool->error = error;
  if((pipe(pool->unblocker) < 0)||
    (fcntl(pool->unblocker[0], F_SETFL, O_NONBLOCK) < 0)||
    (fcntl(pool->unblocker[1], F_SETFL, O_NONBLOCK) < 0)){
    printf("could not create socket pool, fd = %d\n", pool->unblocker[0]);
    free(pool);
    return NULL;
  }
  return pool;
}
void NQ_Socketpool_destroy(NQ_Socketpool *pool){
  NQ_Socket *sock;
  
  while((sock = queue_gethead(&pool->sockets))){
    NQ_Socket_close(sock); //will remove sock from the queue and do memory management
  }
  close(pool->unblocker[0]);
  close(pool->unblocker[1]);
  free(pool);
}

void NQ_Socketpool_unblock(NQ_Socketpool *pool){
  char a = '\0';
  if(write(pool->unblocker[1], &a, sizeof(char)) < 0){
    if(errno != EAGAIN){
      //if errno == EAGAIN, it just means the buffer is full.  
      //in other words, the socketpool is quite unblocked.  We 
      //don't need to make it any more unblocked.
      perror("Error unblocking socket\n");
    }
  }
}

struct NQ_Socket {
  struct NQ_Socket *next, *prev;
  int sock;
  unsigned int peer;
  unsigned short port;
  
  void *userdata;
  int closed;
  NQ_Socketpool *pool;
  pthread_mutex_t read_lock, write_lock;
  NQ_RingBuffer read_buffer, write_buffer;

  int in_bundle;
};


//makesocket assumes that the caller will have taken pool->lock
NQ_Socket *NQ_Socket_makesocket(int sock_fd, NQ_Socketpool *pool, unsigned int ip, unsigned short port, void *userdata){
  NQ_Socket *sock = malloc(sizeof(NQ_Socket));
  bzero(sock, sizeof(NQ_Socket));
  
  NQ_RingBuffer_init(&sock->read_buffer);
  NQ_RingBuffer_resize(&sock->read_buffer, 100000);
  NQ_RingBuffer_init(&sock->write_buffer);
  NQ_RingBuffer_resize(&sock->read_buffer, 100000);

  pthread_mutex_init(&sock->read_lock, NULL);
  pthread_mutex_init(&sock->write_lock, NULL);

  sock->sock = sock_fd;
  sock->peer = ip;
  sock->port = ntohs(port);
  sock->userdata = userdata;
  sock->pool = pool;
  sock->closed = 0;

  int one = 1;
  if(setsockopt(sock->sock,IPPROTO_TCP,TCP_NODELAY, &one, sizeof(one)) < 0) {
    printf("Could not set nodelay on socket!\n");
    free(sock);
    close(sock_fd);
    return NULL;
  }

  if(setsockopt(sock->sock, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)) < 0){
    free(sock);
    close(sock_fd);
    return NULL;
  }

  if(fcntl(sock_fd, F_SETFL, O_NONBLOCK) < 0){
    free(sock);
    close(sock_fd);
    return NULL;
  }
  
  queue_prepend(&pool->sockets, sock);
  
  return sock;
}

NQ_Socket *NQ_Socket_connect(NQ_Socketpool *pool, unsigned int ip, unsigned short port, void *userdata){
  int sock, err;
  struct sockaddr_in saddr;
  
  printf("Connecting to %x\n", ip);
  bzero(&saddr, sizeof(struct sockaddr_in));
  
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = ip;
  saddr.sin_port = htons(port);
  
  sock = socket(PF_INET, SOCK_STREAM, 0);
  if(sock < 0) { goto net_connect_err; }
  
  if( (err = connect(sock, (struct sockaddr *)&saddr, sizeof(saddr))) < 0){ goto net_connect_err; }
  
  pthread_mutex_lock(&pool->lock);
  NQ_Socket *ret = NQ_Socket_makesocket(sock, pool, ip, port, userdata);
  pthread_mutex_unlock(&pool->lock);
  return ret;

net_connect_err:
  perror("connect()");
  if(sock >= 0){
    close(sock);
  }
  return NULL;
}
NQ_Socket *NQ_Socket_listen(NQ_Socketpool *pool, unsigned short port, void *userdata){
  NQ_Socket *sock = malloc(sizeof(NQ_Socket));
  struct sockaddr_in saddr;
  
  bzero(sock, sizeof(NQ_Socket));
  bzero(&saddr, sizeof(struct sockaddr_in));
  
  sock->peer = 0;
  sock->port = -1;
  sock->userdata = userdata;
  sock->pool = pool;
  sock->closed = 0;

  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = INADDR_ANY;
  saddr.sin_port = htons(port);
  
  sock->sock = socket(PF_INET, SOCK_STREAM, 0);
  if(sock->sock < 0) { goto net_listen_err; }
  
  int one = 1;
  setsockopt(sock->sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  // setsockopt(sock->sock, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
  
  if(bind(sock->sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0){ goto net_listen_err; }
  if(listen(sock->sock, 10) < 0){ goto net_listen_err; }

  struct sockaddr_in bound_addr;
  socklen_t addr_len = sizeof(bound_addr);
  if(getsockname(sock->sock, (struct sockaddr *)&bound_addr, &addr_len) < 0) {
    goto net_listen_err;
  }
  sock->port = ntohs(bound_addr.sin_port);
  printf("NetQuery bound to server port %d\n", sock->port);
  
  pthread_mutex_lock(&pool->lock);
  queue_prepend(&pool->sockets, sock);
  pthread_mutex_unlock(&pool->lock);
  
  return sock;

net_listen_err:
  if(sock){
    if(sock->sock >= 0){
      close(sock->sock);
    }
    free(sock);
  }
  return NULL;
}

//the pool lock is held when an event handler is called
#ifdef POLL_NOCOPY

void NQ_Socket_read_event(NQ_Socket *socket){
  int readsize, buffspace;
  unsigned char *buffer;
  if(pthread_mutex_trylock(&socket->read_lock) != 0) {
    socket_stats.read_contended++;
    return;
  }
  NQ_RingBuffer_resize(&socket->read_buffer, 500);
  do {
    buffspace = NQ_RingBuffer_nocopy_write(&socket->read_buffer, &buffer);
    readsize = read(socket->sock, buffer, buffspace);
    // printf("Read %d\n", readsize);
    if(readsize > 0){
      NQ_RingBuffer_push(&socket->read_buffer, readsize);
      NQ_stat.rx_byte_count += readsize;
    }
//    printf("Read: %d / %d (%d)\n", readsize, buffspace, NQ_RingBuffer_data(&socket->read_buffer));
  } while(readsize > 0);
  pthread_mutex_unlock(&socket->read_lock);
  if(readsize == 0) {
    // Return value of 0 means eof
    printf("Socket %d %08x %d disconnected\n", socket->sock, socket->peer, socket->port);
    NQ_Socket_error_event(socket);
    return;
  }
  socket->pool->data(socket);
}

#else //POLL_NOCOPY

#error "no trylock optimization "

void NQ_Socket_read_event(NQ_Socket *socket){
  int readsize;
  unsigned char buffer[500];
  pthread_mutex_lock(&socket->read_lock);
  while((readsize = read(socket->sock, buffer, sizeof(buffer))) > 0){
    printf("Read %d\n", readsize);
    NQ_RingBuffer_write(&socket->read_buffer, buffer, readsize);
//    printf("-----> Read %d bytes (buffer at %d) <----------\n", readsize, NQ_RingBuffer_data(&socket->read_buffer));
//    NQ_RingBuffer_dump(&socket->read_buffer);
//    printf("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
  }
  pthread_mutex_unlock(&socket->read_lock);
  if(readsize == 0) {
    // Return value of 0 means eof
    printf("Socket %d %08x %d disconnected\n", socket->sock, socket->peer, socket->port);
    NQ_Socket_error_event(socket);
    return;
  }
  socket->pool->data(socket);
}

#endif //POLL_NOCOPY

#ifdef POLL_NOCOPY

void NQ_Socket_write_event(NQ_Socket *socket){
  int dataleft;
  unsigned char *buffer;
  int writesize;

  if(pthread_mutex_trylock(&socket->write_lock) != 0) {
    socket_stats.write_contended++;
    return;
  }
  while((dataleft = NQ_RingBuffer_nocopy_read(&socket->write_buffer, &buffer)) > 0){
    assert(dataleft != 0);
    int last = (dataleft == NQ_RingBuffer_size(&socket->write_buffer));
    writesize = send(socket->sock, buffer, dataleft, !last ? MSG_MORE : 0);
    //printf("Writing (nocopy): %d / %d\n", writesize, dataleft);
    if(writesize <= 0){
      break;
    }
    NQ_stat.tx_byte_count += writesize;

    NQ_RingBuffer_skip(&socket->write_buffer, writesize);
  }
  pthread_mutex_unlock(&socket->write_lock);
}

#else //POLL_NOCOPY

#error "no MSG_MORE optimization"
void NQ_Socket_write_event(NQ_Socket *socket){
  int dataleft;
  unsigned char *buffer;
  int writesize;
  
  pthread_mutex_lock(&socket->write_lock);
  dataleft = NQ_RingBuffer_data(&socket->write_buffer);
  if(dataleft > 0){
    if(dataleft > 1024*256){
      dataleft = 1024*256;
    }
    buffer = alloca(dataleft);
    NQ_RingBuffer_peek(&socket->write_buffer, buffer, dataleft);
    //PRINT_NET_SIZE
//    printf("-----> Writing %d bytes %d:%d <----------\n", dataleft, socket->peer, socket->port);
//    NQ_RingBuffer_dump(&socket->write_buffer);
//    printf("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    writesize = write(socket->sock, buffer, dataleft);
    NQ_RingBuffer_skip(&socket->write_buffer, writesize);
  }
  pthread_mutex_unlock(&socket->write_lock);
}

#endif //POLL_NOCOPY

void NQ_Socket_server_event(NQ_Socket *server){
  struct sockaddr_in saddr;
  int sock;
  
  bzero(&saddr, sizeof(struct sockaddr_in));
  
  unsigned int size = sizeof(struct sockaddr_in);
  sock = accept(server->sock, (struct sockaddr *)&saddr, &size);
  if(sock < 0){
    return;
  }
  
  NQ_Socket *socket = NQ_Socket_makesocket(sock, server->pool, saddr.sin_addr.s_addr, saddr.sin_port, NULL);
  
  socket->userdata = server->pool->accept(server, socket);
  
}

void NQ_Socket_close_internal(NQ_Socket *socket){
  queue_delete(&socket->pool->sockets, socket);
  close(socket->sock);
  NQ_RingBuffer_destroy(&socket->read_buffer);
  NQ_RingBuffer_destroy(&socket->write_buffer);
  free(socket);
}
void NQ_Socket_error_event(NQ_Socket *socket){
  socket->pool->error(socket);
  NQ_Socket_close_internal(socket);
}

void NQ_Socket_poll(NQ_Socketpool *pool, int timeout){
  NQ_Socket *currsock;
  int x = 0;
  struct pollfd *fd_list;
  NQ_Socket **sock_list = NULL;
  int ret;
  int numsocks = pool->sockets.len;
  
  pthread_mutex_lock(&pool->lock);
//  if(!queue_gethead(&pool->sockets)){
//    if(timeout > 0){
//      usleep(timeout);
//  }
//    pthread_mutex_unlock(&pool->lock);
//    return;
//  }
  
  fd_list = alloca(sizeof(struct pollfd) * (numsocks+1));
  bzero(fd_list, (sizeof(struct pollfd) * (numsocks+1)));
  
  if(queue_gethead(&pool->sockets)){
    sock_list = alloca(sizeof(NQ_Socket *) * numsocks);
    bzero(sock_list, (sizeof(NQ_Socket *) * numsocks));
    
    for(currsock = queue_gethead(&pool->sockets); currsock != NULL; currsock = queue_getnext(currsock), x++){
      while(currsock->closed){
        currsock = queue_getnext(currsock);
        numsocks --;
        NQ_Socket_close_internal(sock_list[x]);
        if(!currsock) break;
      }
      if(!currsock) break;
      sock_list[x] = currsock;
      fd_list[x].fd = currsock->sock;
      fd_list[x].events = POLLIN;
      if(sock_list[x]->peer != 0){
        if(NQ_RingBuffer_data(&sock_list[x]->write_buffer) > 0){
	  // printf("have pending output\n");
          fd_list[x].events |= POLLOUT;
        }
      }
    }
  }
  fd_list[x].fd = pool->unblocker[0];
  fd_list[x].events = POLLIN;
  
  pthread_mutex_unlock(&pool->lock);
  ret = poll(fd_list, numsocks+1, timeout);

  if(ret < 0 && (DEBUG_POLL_EINTR || errno != EINTR) ) {
    printf("%lf: poll returned %d (%d)\n", doubleTime(), ret, timeout);
    printf("poll error:%s\n", strerror(errno));
  }
  // printf("poll returned: %d (out of %d sockets + unblocker)\n", ret, numsocks);
  pthread_mutex_lock(&pool->lock);
  // printf("lock acquired\n");

  for(x = 0; x < numsocks; x++){
    if(sock_list[x]->closed){
      NQ_Socket_close_internal(sock_list[x]);
    } else {
      // printf("[%d] = %x\n", (int)fd_list[x].revents);
      if(fd_list[x].revents & POLLERR){
        NQ_Socket_error_event(sock_list[x]);
      } else {
        if(sock_list[x]->peer == 0){ //server socket
          //printf("server event!\n");
          if(fd_list[x].revents & POLLIN){
            NQ_Socket_server_event(sock_list[x]);
          }
        } else {
          if(fd_list[x].revents & POLLIN){
	    //printf("got pollin event for %d\n", sock_list[x]);
            NQ_Socket_read_event(sock_list[x]);
          }
          if(fd_list[x].revents & POLLOUT){
	    //printf("got pollout event for %d\n", sock_list[x]);
            NQ_Socket_write_event(sock_list[x]);
          }
        }
        if(fd_list[x].revents & POLLHUP){ //close the connection after we've read everything we can from it
          NQ_Socket_error_event(sock_list[x]);
        }
      }
    }
  }
  if(fd_list[numsocks].revents & POLLIN){
    char a;
   while((read(pool->unblocker[0], &a, sizeof(char)) > 0)) {
     //clear the unblocking events
   }
  }
  pthread_mutex_unlock(&pool->lock);
}
void NQ_Socket_close(NQ_Socket *socket){
  pthread_mutex_lock(&socket->pool->lock);
  socket->closed = 1; //will be closed the next time NQ_Socket_poll is active.
  pthread_mutex_unlock(&socket->pool->lock);
}
void *NQ_Socket_userdata(NQ_Socket *socket){
  return socket->userdata;
}
void NQ_Socket_set_userdata(NQ_Socket *socket, void *userdata){
  socket->userdata = userdata;
}

unsigned int NQ_Socket_peer(NQ_Socket *socket){
  return socket->peer;
}

unsigned short NQ_Socket_peerport(NQ_Socket *socket){
  return socket->port;
}

NQ_Host NQ_Socket_get_host(NQ_Socket *socket) {
  NQ_Host host;
  host.addr = socket->peer;
  host.port = socket->port;
  return host;
}

int NQ_Socket_read(NQ_Socket *socket, unsigned char *buff, int len){
  pthread_mutex_lock(&socket->read_lock);
  if(NQ_RingBuffer_data(&socket->read_buffer) >= len){
//    printf("------- Buffer before read ----------\n");
//    NQ_RingBuffer_dump(&socket->read_buffer);
//    printf("------- Output after read -----------\n");
    NQ_RingBuffer_read(&socket->read_buffer, buff, len);
//    print_hex(buff, len);
//    printf("\n-------------------------------------\n");
    pthread_mutex_unlock(&socket->read_lock);
    return 0;
  }
  pthread_mutex_unlock(&socket->read_lock);
  return -1;
}
int NQ_Socket_peek(NQ_Socket *socket, unsigned char *buff, int len){
  pthread_mutex_lock(&socket->read_lock);
  if(NQ_RingBuffer_data(&socket->read_buffer) >= len){
    NQ_RingBuffer_peek(&socket->read_buffer, buff, len);
    pthread_mutex_unlock(&socket->read_lock);
    return 0;
  }
  pthread_mutex_unlock(&socket->read_lock);
  return -1;
}
int NQ_Socket_data(NQ_Socket *socket){
  int data;
  pthread_mutex_lock(&socket->read_lock);
  data = NQ_RingBuffer_data(&socket->read_buffer);
  pthread_mutex_unlock(&socket->read_lock);
  return data;
}
int NQ_Socket_write(NQ_Socket *socket, unsigned char *buff, int len){
  NQ_Socket_write_start(socket);
//  printf("------- Input to write --------------\n");
//  print_hex(buff, len);
  int ret = NQ_Socket_write_partial(socket, buff, len);
//  printf("\n------- Buffer after write ----------\n");
//  NQ_RingBuffer_dump(&socket->write_buffer);
//  printf("-------------------------------------\n");
  NQ_Socket_write_flush(socket);
  return ret;
}

void NQ_Socket_write_start(NQ_Socket *socket) {
  pthread_mutex_lock(&socket->write_lock);
}

int NQ_Socket_write_partial(NQ_Socket *socket, unsigned char *buff, int len) {
  return (NQ_RingBuffer_write(&socket->write_buffer, buff, len) >= 0)?0:-1;
}
void NQ_Socket_write_flush(NQ_Socket *socket) {
  pthread_mutex_unlock(&socket->write_lock);
  NQ_Socketpool_unblock(socket->pool);
}

void NQ_Socket_start_bundle(NQ_Socket *socket) {
  assert(!socket->in_bundle);
  socket->in_bundle = 1;
  NQ_Socket_write_start(socket);
}

void NQ_Socket_finish_bundle(NQ_Socket *socket) {
  // assert(socket->in_bundle);
  if(socket->in_bundle) {
    socket->in_bundle = 0;
    NQ_Socket_write_flush(socket);
  } else {
    printf("weird finish bundle\n");
  }
}

int NQ_Socket_in_bundle(NQ_Socket *socket) {
  return socket->in_bundle;
}

