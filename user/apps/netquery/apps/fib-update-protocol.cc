#include <stdio.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <assert.h>
#include <errno.h>
#include "fib-update-protocol.hh"

using namespace std;

int g_send_seqnum = 0;

FIBUpdateTID::FIBUpdateTID(const struct ForwardingEntry *ent){
  entry = *ent;
  if(entry.interface != NULL) {
    tid = entry.interface->tspace_interface.tid;
  } else {
    tid = NQ_uuid_null;
  }
  entry.interface = NULL;
}

int fib_sock = -1;

int FIBUpdate_init_sock(const std::string &sock_location) {
  struct sockaddr_un local;
  int err;
  int len;

  fib_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if(fib_sock < 0) {
    cerr << "FIB sock err\n";
    exit(-1);
  }

  local.sun_family = AF_UNIX;  /* local is declared before socket() ^ */
  strcpy(local.sun_path, sock_location.c_str());
  unlink(local.sun_path);
  len = strlen(local.sun_path) + sizeof(local.sun_family);
  err = bind(fib_sock, (struct sockaddr *)&local, len);
  if(err < 0) {
    perror("FIB Bind");
    exit(-1);
  }
  return 0;
}

int FIBUpdate_connect(const std::string &sock_location) {
  struct sockaddr_un remote;
  int len;

  fib_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if(fib_sock < 0) {
    cerr << "FIB sock err\n";
    exit(-1);
  }

  remote.sun_family = AF_UNIX;
  strcpy(remote.sun_path, sock_location.c_str());
  len = strlen(remote.sun_path) + sizeof(remote.sun_family);
  if (connect(fib_sock, (struct sockaddr *)&remote, len) < 0) {
    perror("connect");
    return -1;
  }
  return 0;
}

static int send_all(int sock, const void *data, int len) {
  char *loc = (char *)data;
  int sent_len = 0;
  while(len > 0) {
    int rv = send(sock, loc, len, 0);
    if(rv < 0) {
      perror("send_all");
      exit(-1);
    }
    sent_len += rv;
    loc += rv;
    len -= rv;
  }
  return sent_len;
}

int FIBUpdate_recv_all(int s, void *dest, int len, bool block) {
  char *loc = (char *)dest;
  int read_len = 0;
  while(len > 0) {
    // once non-blocking reads the first part of a packet, commit ourselves to reading the whole thing
    int rv = recv(s, loc, len, (!block && read_len == 0) ? MSG_DONTWAIT : 0);
    if(rv < 0) {
      if(errno == EAGAIN) {
        assert(read_len == 0);
        return 0;
      }
      perror("recv_all");
      fprintf(stderr, "sock=%d, loc = %p, len = %d\n", s, loc, len);
      exit(-1);
    } else if(rv == 0) {
      cerr << "recv_all: other side gone\n";
      return -1;
    }
    read_len += rv;
    loc += rv;
    len -= rv;
  }
  return read_len;
}

static int wait_for_ack(int seqnum, bool block = true) {
  FIBUpdate_Result header;
  while(1) {
    int rv = FIBUpdate_recv_all(fib_sock, &header, sizeof(header), block);
    if(rv == 0) {
      assert(!block);
      break;
    } else if(rv == -1) {
      return -1;
    }
    assert(header.seqnum <= seqnum);
    if(header.seqnum == seqnum) {
      break;
    }
  }
  return header.result;
}

int FIBUpdate_respond(int sock, int result, int seqnum) {
  FIBUpdate_Result header;
  header.result = result;
  header.seqnum = seqnum;
  return send_all(sock, &header, sizeof(header));
}

int FIBUpdate_issue_LoadSpec(const std::string &topo_fname) {
  struct LoadSpec spec;
  strcpy(spec.topo_fname, topo_fname.c_str());
  FIBUpdate_Request header(LOADSPEC, g_send_seqnum++);

  send_all(fib_sock, &header, sizeof(header));
  send_all(fib_sock, &spec, sizeof(spec));

  cerr << "waiting for ack\n";
  wait_for_ack(header.seqnum);
  cerr << "done waiting for ack\n";
  return 0;
}

int FIBUpdate_issue_Update(int router_id, const FIBUpdates &additions, const FIBUpdates &deletions, bool wait) {
  FIBUpdate_Request header(UPDATEFIB, g_send_seqnum++);
  struct UpdateSpec update_header;
  update_header.router_id = router_id;
  update_header.num_adds = additions.size();
  update_header.num_dels = deletions.size();

  send_all(fib_sock, &header, sizeof(header));
  send_all(fib_sock, &update_header, sizeof(update_header));

  // send tids; build a common buffer to send it all in one chunk with one copy
  int tot = additions.size() + deletions.size();
  FIBUpdateTID *adds_and_dels = new FIBUpdateTID[tot];
  int add_size = additions.size();
  for(int i=0; i < add_size; i++) {
    adds_and_dels[i] = FIBUpdateTID(&additions[i]);
  }
  for(size_t j=0; j < deletions.size(); j++) {
    adds_and_dels[add_size + j] = FIBUpdateTID(&deletions[j]);
  }
  send_all(fib_sock, &adds_and_dels[0], tot * sizeof(adds_and_dels[0]));
#if 0
  send_all(fib_sock, &additions[0], sizeof(additions[0]) * additions.size());
  send_all(fib_sock, &deletions[0], sizeof(deletions[0]) * deletions.size());
#endif
  delete [] adds_and_dels;
  wait_for_ack(header.seqnum, wait);
  return 0;
}

int FIBUpdate_issue_CommitAll(void) {
  FIBUpdate_Request header(COMMITALL, g_send_seqnum++);
  send_all(fib_sock, &header, sizeof(header));
  wait_for_ack(header.seqnum);
  return 0;
}
