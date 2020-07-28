#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <time.h>

#include "bgp.h"
#include "overlay.h"
#include "bgpcheck.h"
#include "nbgp.h"
#include "common.h"

#define BGP_MAX_ASCOUNT 65536
#define NBGP_PORT 52982
#define BOL_SERVER_BACKLOG 3

//a = # of prior attempts
//this value is the most recent last attempt for which we should attempt a retry
#define BOL_RETRY_TIME(a) (time(NULL) - (a) * 15)
#define BOL_TIMEOUT_TIME (time(NULL) - 5)
#define BOL_MAX_RETRIES 20

static int bol_socket_ready(bol_peer *peer, bol_info *info);

void bol_abort_socket(bol_peer *peer){
  close(peer->socket);

  printf("Closing connection to ");
  bgp_print_ip(peer->ip);
  printf(":%d\n", peer->port);

  peer->socket = -1;
  peer->read = 0;
  peer->attempts++;
  peer->last_attempt = time(NULL);
}

void bol_configure_socket(bol_peer *peer, bol_info *info){
  fcntl(peer->socket, F_SETFL, O_NONBLOCK);

  peer->read = -1; //we're not ready to read yet... wait for confirmation
  peer->buffer = NULL; //we haven't read a header yet
}

void bol_try_connect(bol_peer *peer, bol_info *info){
  struct sockaddr_in address;

  //printf("time remaining: %d (%d)\n", peer->last_attempt - BOL_RETRY_TIME(peer->attempts), peer->attempts);

  if(BOL_RETRY_TIME(peer->attempts) < peer->last_attempt){
    return;
  }

  printf("Attempting to connect to ");
  bgp_print_ip(peer->ip);
  printf(":%d\n", peer->port);

  bzero(&address, sizeof(struct sockaddr_in));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(peer->ip);
  address.sin_port = htons(peer->port);

  //NEXUS FUNKYNESS GOES HERE

  peer->socket = socket(AF_INET, SOCK_STREAM, 0);

  if(peer->socket < 0){
    perror("Error: unable to allocate socket for NBGP peer");
    peer->last_attempt = time(NULL);
    peer->attempts ++;
  } else {
    bol_configure_socket(peer, info);
    if(connect(peer->socket, (struct sockaddr *)&address, sizeof(struct sockaddr_in))){
      if(errno == EINPROGRESS){
	printf("Connection in progress...\n");
	peer->last_attempt = time(NULL);
      } else {
	perror("Error, unable to establish initial connection to NBGP peer");
	peer->last_attempt = time(NULL);
	peer->attempts ++;
	bol_abort_socket(peer);
      }
    } else {
      peer->read = 0;
    }
  }

}

void bol_add_peer(unsigned int ip, unsigned int port, bol_info *info){
  bol_peer *peer = malloc(sizeof(bol_peer));
  assert(peer);

  bzero(peer, sizeof(bol_peer));

  peer->ip = ip;
  peer->port = port==0?NBGP_PORT:port;
  peer->socket = -1;
  peer->last_attempt = 0;
  peer->attempts = 0;

  peer->next = info->peer_list;
  info->peer_list = peer;

  bol_try_connect(peer, info);	
}

bol_info *bol_initialize(){
  bol_info *info = malloc(sizeof(bol_info));

  printf("Allocating buffers\n");

  //for O(1) access times to member information, we just treat it as one
  //bigass array indexed on ASID.  Considering, that eventually most of the
  //empty elements of that array will get filled in, this isn't that big
  //a deal
  info->member_list = malloc(BGP_MAX_ASCOUNT * sizeof(bol_member));

  if(info->member_list == NULL){
    printf("Out of memory!");
    exit(1);
  }

  info->error_list = NULL;	

  assert(NULL == 0);
  //NULL should be zero (we check that), and we define BOL_UNSEEN to be
  //zero as well.  This'll set them all to their defaults.
  bzero(info->member_list, BGP_MAX_ASCOUNT * sizeof(bol_member));


  info->peer_list = NULL;

  return info;
}

void bol_set_ip(bol_info *info, unsigned int ip, unsigned int port, unsigned int AS){
  struct sockaddr_in saddr;

  info->as = AS;
  info->member_list[AS].status = BOL_SELF;
  info->member_list[AS].ip = ip;
  info->member_list[AS].version = 1;
  info->member_list[AS].seqno = 0;

  info->ip = ip;
  info->port = (port==0)?NBGP_PORT:port;
  printf("Creating server on port %d\n", info->port);

  //NEXUS FUNKYNESS GOES HERE
  info->socket = socket(AF_INET, SOCK_STREAM, 0);
  fcntl(info->socket, F_SETFL, O_NONBLOCK);

  if(info->socket < 0){
    perror("Error: unable to allocate a socket for the NBGP Overlay server");
    exit(1);
  }

  bzero(&saddr, sizeof(struct sockaddr_in));
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = INADDR_ANY;
  saddr.sin_port = htons(info->port);

  if(bind(info->socket, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) ){
    perror("Error: unable to bind the NBGP Overlay server");
    exit(1);
  }

  if(listen(info->socket, BOL_SERVER_BACKLOG)){
    perror("Error: unable to start the NBGP Overlay server listening");
    exit(1);
  }
}

int bol_set_select_fd(bol_info *info, fd_set *set, fd_set *writes, fd_set *exception){
  int maxfd = info->socket;
  bol_peer *peer = info->peer_list;

  FD_SET(info->socket, set);

  for(; peer != NULL; peer = peer->next){
    if(peer->socket >= 0){
      if(peer->socket >= maxfd){
	maxfd = peer->socket;
      }
      if(peer->read < 0){
	FD_SET(peer->socket, writes);
      } else {
	FD_SET(peer->socket, set);
      }
      FD_SET(peer->socket, exception);
    }
  }

	return maxfd;
}

int bol_write(bol_header *header, unsigned char *buffer, int len, bol_peer *destination){
  ssize_t bytes, written = 0;

  written = 0;
  bytes = 0;
  while(bytes < sizeof(bol_header)){
    written = write(destination->socket, &(((unsigned char *)header)[bytes]), sizeof(bol_header) - bytes);
    if(written <= 0){
      bol_abort_socket(destination);
      return -1;
    }
    bytes += written;
  }

  written = 0;
  bytes = 0;
  while(bytes < len){
    written = write(destination->socket, &(buffer[bytes]), len - bytes);
    if(written <= 0){
      bol_abort_socket(destination);
      return -1;
    }
    bytes += written;
  }

  return 0;
}

int bol_socket_ready(bol_peer *peer, bol_info *info){
  unsigned int x, y, count = 0;
  bol_member_list *list;
  bol_header header;

  peer->attempts = 0;
  peer->read = 0;

  //now we should forward our status

  //first a message with our member list
  printf("Generating member list\n");
  for(x = 0; x < BGP_MAX_ASCOUNT; x++){
    if(info->member_list[x].status != BOL_UNSEEN){
      count++;
    }
  }

  printf("%d members known\n", count);
  header.length = BOL_MEMBER_LIST_LEN(count);
  header.type = BOL_MEMBERLIST;
  list = malloc(header.length);
  list->length = count;
  for(x = 0,y = 0; (x < BGP_MAX_ASCOUNT)&&(y < count); x++){
    if(info->member_list[x].status != BOL_UNSEEN){
      list->members[y].AS = x;
      list->members[y].ip = info->member_list[x].ip;
      list->members[y].version = info->member_list[x].version;
      list->members[y].seqno = info->member_list[x].seqno;
      list->members[y].port = info->member_list[x].port;
      y++;
    }
  }

  printf("sending!\n");
  bol_write(&header, (unsigned char *)list, header.length, peer);
  printf("sent!");

  free(list);
  return 0;
}

void bol_try_accept(bol_info *info){
  struct sockaddr_in sockaddy;
  bol_peer *peer = info->peer_list;
  int socket;
  unsigned int len = sizeof(struct sockaddr_in);

  socket = accept(info->socket, (struct sockaddr *)&sockaddy, &len);
  
  if(socket < 0){
    if(errno != EWOULDBLOCK){
      perror("Error accepting");
    }
    return;
  }

  printf("Got connection from : ");
  bgp_print_ip(ntohl(sockaddy.sin_addr.s_addr));
  printf("\n");

  for(; peer != NULL; peer = peer->next){
    if(peer->ip == ntohl(sockaddy.sin_addr.s_addr)){
      if(peer->socket < 0){
	peer->socket = socket;
	bol_configure_socket(peer, info);
	bol_socket_ready(peer, info);
      } else {
	//uhoh, race condition!
	//both of us have tried to establish a connection at the
	//same time!  The connection originated by the higher 
	//IP is preferred.
	if(info->ip < peer->ip){
	  printf("Detected simultaneous connection attempts; dropping my attempt\n");
	  close(peer->socket);
	  peer->socket = socket;
	  bol_configure_socket(peer, info);
	  bol_socket_ready(peer, info);
	} else {
	  printf("Detected simultaneous connection attempts; dropping peer's attempt\n");
	  close(socket);
	  return;
	}
      }
    }
  }
}

int bol_read(bol_peer *peer, unsigned char *buffer, int buffsize){
  int readcount;

  readcount = read(peer->socket, &(buffer[peer->read]), buffsize - peer->read);
  printf("read %d+%d / %d bytes\n", peer->read, readcount, buffsize);
  if(readcount < 1){
    if(errno == EAGAIN){
      //odd, we shouldn't have gotten this...
      //... unless we're trying to read a header and a buffer
      printf("Select returned a socket that wasn't available (this is only bad if you receive a flurry of these messages)\n");
      return 0;
    } else {
      //something bad happened... assume the connection
      //just died
      printf("Socket dead, aborting\n");
      bol_abort_socket(peer);
      if(peer->buffer != NULL){
	free(peer->buffer);
	peer->buffer = NULL;
      }
      return 0;
    }
  }

  peer->read += readcount;

  return (peer->read >= buffsize);
}

static void bol_broadcast(int type, unsigned int len, unsigned char *buffer, bol_info *info, bol_peer *exclude){
  bol_peer *curr;
  bol_header header;

  header.type = type;
  header.length = len;

  for(curr = info->peer_list; curr != NULL; curr = curr->next){
    if(curr != exclude){
      if((curr->socket > 0) && (curr->attempts >= 0)){
	bol_write(&header, buffer, len, curr);
      }
    }
  }
}

void bol_process_memberlist(bol_member_list *list, bol_info *info, bol_peer *peer){
  unsigned int x, y, as, resend_cnt = 0;
  unsigned char *resend = malloc(list->length);
  bol_member_list *relist;

  bzero(resend, list->length);

  printf("got list: %d\n", list->length);

  for(x = 0; x < list->length; x++){
    as = list->members[x].AS;
    printf("checking %u\n", as);
    if(info->member_list[as].status == BOL_UNSEEN){
      info->member_list[as].status = BOL_CONNECTED;
      info->member_list[as].ip = list->members[x].ip;
      info->member_list[as].version = list->members[x].version;
      info->member_list[as].seqno = list->members[x].seqno;
      info->member_list[as].port = list->members[x].port;
      printf("Found a new peer!  (");
      bgp_print_ip(info->member_list[as].ip);
      printf(":%d)\n", info->member_list[as].port);
      resend[x] = 1;
      resend_cnt++;
    } else {
      printf("known\n");
    }
  }

  if(resend_cnt > 0){
    relist = malloc(BOL_MEMBER_LIST_LEN(resend_cnt));
    relist->length = resend_cnt;
    y = 0;
    for(x = 0; x < list->length;x++){
      if(resend[x]){
	relist->members[y] = list->members[x];
	y++;
      }
    }
    bol_broadcast(BOL_MEMBERLIST, BOL_MEMBER_LIST_LEN(resend_cnt), (unsigned char *)relist, info, peer);
    free(relist);
  }
}

int bol_compare_report(bol_error_report *a, bol_error_report *b){
  int x, len;

  if(a->reporting_AS != b->reporting_AS)
    return 0;

  if(a->affected_AS != b->affected_AS)
    return 0;

  if(a->prefix_len != b->prefix_len)
    return 0;

  if(a->prefix != b->prefix)
    return 0;

  //we may want to replace this with an equality check... 
  //look into it
  len = MIN(a->aspath_len, b->aspath_len);

  for(x = 0; x < len; x++){
    if(a->aspath[x] != b->aspath[x]){
      return 0;
    }
  }

  return 1;
}

void bol_make_report(bol_info *info, bol_peer *peer, bol_error_report *report){
  //see if we've got this report already
  //since we're using reliable transport in a predominantly fixed 
  //configuration, we can use simple sequence numbers... we just need to 
  //find some way to reset this number << insert handwaving >>
  if(info->member_list[report->reporting_AS].seqno < report->seqno){
    //this message is newer than any we've seen so far.  
    //we're guaranteed not to have any reports skipped
    info->member_list[report->reporting_AS].seqno = report->seqno;

    //forward the report
    bol_broadcast(BOL_ERROR, BOL_ERROR_REPORT_LEN(report->aspath_len), (unsigned char *)report, info, peer);

    //don't forget to let ourselves know as well...
    nbgp_make_report(report); //make_report will retain report
  } else {
    free(report);
  }
}

void bol_withdraw_report(bol_info *info, bol_peer *peer, bol_error_withdrawal *report){
  if(info->member_list[report->reporting_AS].seqno < report->seqno){
    info->member_list[report->reporting_AS].seqno = report->seqno;
    
    bol_broadcast(BOL_WITHDRAW, sizeof(bol_error_withdrawal), (unsigned char *)report, info, peer);
    
    nbgp_withdraw_report(report); //withdraw report will free report when needed
    
    return;
  } else {
    free(report);
  }
}

int bol_inject_badUpdate(bol_info *info, unsigned int affected_AS, int knowledge, int prefix_len, unsigned int prefix, int aspath_len, unsigned short *aspath){
  bol_error_report *report = malloc(BOL_ERROR_REPORT_LEN(aspath_len));

  report->reporting_AS = info->as;
  report->affected_AS = affected_AS;
  report->knowledge = knowledge;
  report->seqno = info->member_list[info->as].seqno;
  report->prefix_len = prefix_len;
  report->prefix = prefix;
  report->aspath_len = aspath_len;
  memcpy(report->aspath, aspath, sizeof(int) * aspath_len);
  bol_make_report(info, NULL, report);
  info->member_list[info->as].seqno ++; //have to call this after make_report
  //make_report saves a copy of report or frees it by itself
  return info->member_list[info->as].seqno -1;
}

void bol_inject_withdrawal(bol_info *info, int withdrawal){
  bol_error_withdrawal *report = malloc(sizeof(bol_error_withdrawal));

  assert(withdrawal < info->member_list[info->as].seqno);

  report->reporting_AS = info->as;
  report->seqno = info->member_list[info->as].seqno;
  report->withdrawn_seqno = withdrawal;
  bol_withdraw_report(info, NULL, report);
  info->member_list[info->as].seqno ++; //have to call this after withdraw...
}

void bol_handle_packet(bol_peer *peer, bol_info *info){
  switch(peer->header.type){
  case BOL_MEMBERLIST:
    if((peer->header.length < sizeof(int)) || (peer->header.length < BOL_MEMBER_LIST_LEN(((bol_member_list *)peer->buffer)->length))){
      printf("GOT MALFORMED PACKET FROM OVERLAY PEER: ");
      bgp_print_ip(peer->ip);
      printf(":%d\n", peer->port);
      break;
    }
    bol_process_memberlist((bol_member_list *)peer->buffer, info, peer);
    free(peer->buffer);
    break;
  case BOL_ERROR:
    if((peer->header.length < BOL_ERROR_REPORT_LEN(0)) || (peer->header.length < BOL_ERROR_REPORT_LEN(((bol_error_report *)peer->buffer)->aspath_len))){
      printf("GOT MALFORMED PACKET FROM OVERLAY PEER: ");
      bgp_print_ip(peer->ip);
      printf(":%d\n", peer->port);
      break;
    }
    bol_make_report(info, peer, (bol_error_report *)peer->buffer);
    //make_report frees or keeps the buffer as needed
    break;
  case BOL_WITHDRAW:
    if(peer->header.length < sizeof(bol_error_withdrawal)){
      printf("GOT MALFORMED PACKET FROM OVERLAY PEER: ");
      bgp_print_ip(peer->ip);
      printf(":%d\n", peer->port);
      break;
    }
    bol_withdraw_report(info, peer, (bol_error_withdrawal *)peer->buffer);
    break;
  default:
    free(peer->buffer);
    break;
  }
}

void bol_try_read(bol_peer *peer, bol_info *info){
  //read only one message at a time.  If we have any more to read
  //we'll get called immediately after the next select

  //try to read the header if we have any left to read
  if(!peer->buffer){
    if(peer->read == 0){
      peer->header.type = 0xDEADBEEF;
      peer->header.length = 0xDEADBEEF;
    }
    printf("Reading header\n");
    if(bol_read(peer, (unsigned char *)&(peer->header), sizeof(bol_header))){
      peer->buffer = malloc(peer->header.length);
      peer->read = 0;
    }
    return;
  }

  if(peer->socket < 0){
    return;
  }

  //try to read the body if we have any left to read
  if(peer->buffer){
    printf("reading buffer: %d bytes, type %d\n", peer->header.length, peer->header.type);
    if(bol_read(peer, peer->buffer, peer->header.length)){
      bol_handle_packet(peer, info);
      //handle packet will free the buffer
      peer->buffer = NULL;
      peer->read = 0;
    }
  }

}

void bol_check_data(bol_info *info, fd_set *set, fd_set *writes, fd_set *exception){
  bol_peer *peer = info->peer_list;
  int error;
  socklen_t optlen = sizeof(int); 

  //  if(FD_ISSET(info->socket, set)){
  //printf("Ready to accept\n");
    bol_try_accept(info);
    //}
	
  for(; peer != NULL; peer = peer->next){
    if(peer->socket >= 0){
      if(FD_ISSET(peer->socket, exception)){
	bol_abort_socket(peer);
	continue;
      } else if(FD_ISSET(peer->socket, set)){
	getsockopt(peer->socket, SOL_SOCKET, SO_ERROR, &error, &optlen);
	if(error){
	  perror("Error on socket");
	  bol_abort_socket(peer);
	  continue;
	}
	bol_try_read(peer, info);
      } else if(FD_ISSET(peer->socket, writes)){
	if(peer->read >= 0){
	  continue;
	}

	getsockopt(peer->socket, SOL_SOCKET, SO_ERROR, &error, &optlen);
	
	switch(error){
	case 0: //no error, we're good to go
	  bol_socket_ready(peer, info);
	  break;
	case EINPROGRESS: //odd, we shouldn't have gotten this; 
	  //some funky socket implementation might get us here
	  break;
	default:
	  switch(error){
	  case ECONNREFUSED:
	    printf("Connection refused\n");
	  case ETIMEDOUT:
	    printf("Connection timed out at the socket layer\n");
	  case ENETUNREACH:
	    printf("Couldn't reach destination\n");
	  default:
	    printf("Unknown error %d\n", error);
	  }
	  bol_abort_socket(peer);
	  break;
	}
      } else {
	if((peer->read < 0)&&(peer->last_attempt < BOL_TIMEOUT_TIME)){
	  printf("Connection attempt timed out, hanging up for now\n");
	  bol_abort_socket(peer);
	}
	//printf("%d not ready (%d)\n", peer->socket, peer->read);
      }
    } else {
      bol_try_connect(peer, info);
    }
  }
	
}
