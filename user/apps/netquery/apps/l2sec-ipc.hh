#ifndef _L2SEC_IPC_HH_
#define _L2SEC_IPC_HH_

#include "ipc.hh"
#include <nexus/l2sec.h>
#include <iostream>

static inline int tcp_socket(IP_Address addr, short port_num, bool non_blocking) {
  int fd = socket(PF_INET, SOCK_STREAM, 0);
  if(fd < 0) {
    return fd;
  }
  int on = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

  struct sockaddr_in saddr;
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = htonl(addr);
  saddr.sin_port = htons(port_num);
  int err = bind(fd, (struct sockaddr *)&saddr, sizeof(saddr));
  assert(err == 0);

  if(non_blocking) {
    err = fcntl(fd, F_SETFL, O_NONBLOCK);
    assert(err == 0);
  }

  return fd;
}

extern IPC_ServiceDesc l2sec_desc;

namespace L2Sec {
  struct Header {
    // key_length == 0 : special command to request TID
    int key_length;
    Header() { /* do nothing */ }
    Header(int len) : key_length(len) { /* do nothing */ }
  };
  struct Response {
    int val;
  };

  enum Commands {
    CMD_NewKey = 0,
    CMD_GetTID = 1,
  };

  struct Client : IPC_Client {
    Client(eventxx::dispatcher *d, int client_sock, const struct sockaddr_in &addr) : 
      IPC_Client(&l2sec_desc, d, client_sock, addr) {
      /* do nothing */
    }
    virtual ~Client() { }
    NQ_Tuple GetTID(NQ_Tuple tid) {
      DataBuffer request;
      DataBuffer response;
      tspace_marshall(tid, request);
      send(CMD_GetTID, request, &response);

      NQ_Tuple rv = NQ_uuid_null;
      CharVector_Iterator s = response.begin(), end = response.end();
      rv = *tspace_unmarshall(&rv, *(Transaction *)NULL, s, end);
      std::cerr << "GetTID() => " << rv << "\n";
      return rv;
    }
    int NewKey(const unsigned char *key, int keylen) {
      Header header(keylen);
      DataBuffer request;
      DataBuffer response;

      vector_push(request, header);
      vector_push(request, key, keylen);
      send(CMD_NewKey, request, &response);

      Response resp;
      if(response.size() != sizeof(resp)) {
        std::cerr << "bad response for newkey\n";
        return -1;
      }
      memcpy(&resp, vector_as_ptr(response), sizeof(resp));
      return resp.val;
    }
    
    void connected() {
      std::cerr << "Client connected\n";
    }
  };
}
#endif
