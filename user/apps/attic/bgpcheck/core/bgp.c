#include <arpa/inet.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>

#include "../include/util/common.h"
#include "../include/nbgp/bgp.h"

// Exit on the following message types
#define DEBUG_EXIT (DEBUG_INTERNAL)
// Print the following message types
#define DEBUG_PRINT (DEBUG_EXIT | DEBUG_STATUS ) 
//| DEBUG_FORMAT)

//#define PRINT_DEBUG_BGP


void *bgp_realloc(void *buff, unsigned short *elements, unsigned short req_elements, int element_size){
  //printf("bgp_realloc: %p (%d elements out of %d required)\n", buff, *elements, req_elements);
  if(req_elements <= *elements){
    return buff;
  }
  if(*elements <= 0){
    *elements = 1;
    buff = NULL;
  }
  do {
    *elements *= 2;
  } while (req_elements >= *elements);
  if(buff == NULL){
    return malloc(element_size * (*elements));
  }
  
  return realloc(buff, element_size * (*elements));
}

// Print a set of bytes in hexadecimal pair notation
//  c: The start of the byte array to be printed
//  len: the length of the byte array to be printed
void bgp_print_hex(unsigned char *c, int len){
  static char hexlist[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  int x;
  for(x = 0; x < len; x++){
    if(x > 0){
      if((x % 8) == 0){
	putchar(' ');
	if((x % 16) == 0){
	  putchar('\n');
	}
      }
    }
    putchar(hexlist[((c[x]&0xf0)>>4)]);
    putchar(hexlist[(c[x]&0xf)]);
  }
}

// Print out a timestamp
void bgp_timestamp(){
  time_t stime = time(NULL);
  struct tm *ltime = localtime(&stime);
  printf("[%02d/%02d/%04d %02d:%02d:%02d]", 
	 ltime->tm_mon+1,
	 ltime->tm_mday,
	 ltime->tm_year+1900,
	 ltime->tm_hour,
	 ltime->tm_min,
	 ltime->tm_sec);
}

// If a pipe is of a buffered form, dump the entire buffer to the screen
//  pipe: the pipe to be dumped
void bgp_print_pipe(PIPE_TYPE pipe){
  int i, j, count = 0;
  switch(pipe->type){
  case BGP_PIPE:
    break;
  case BGP_BUFFER:
    for(j = 0; j < pipe->contents.buffer.len; j+= 8){
      printf("%d) ", count);
      bgp_print_hex((unsigned char *)&(pipe->contents.buffer.buff[j]), MIN(pipe->contents.buffer.len - j, 8));
      printf("\n");
      count += MIN(pipe->contents.buffer.len - j, 8);
    }
    break;
  case BGP_VECTOR:
    for(i = 0; i < pipe->contents.vector.blen; i++){
      for(j = 0; j < pipe->contents.vector.len[i]; j+= 8){
	printf("%d) ", count);
	bgp_print_hex((unsigned char *)&(pipe->contents.vector.buff[i][j]), MIN(pipe->contents.vector.len[i] - j, 8));
	printf("\n");
	count += MIN(pipe->contents.vector.len[i] - j, 8);
      }
    }
  }
}

// Signal a parser error, flag the associated pipe to that effect.
// see the above defines DEBUG_PRINT and DEBUG_EXIT
//  msg: If class is defined above as a member of DEBUG_PRINT, this will be echoed
//  class: The class of error.  Special action is taken if this is a member of DEBUG_PRINT or DEBUG_EXIT (see above)
//  pipe: This pipe will be flagged as having caused an error
void bgp_parse_error(char *msg, int class, PIPE_TYPE pipe){
  if(!pipe->error){
    if(msg && (class & DEBUG_PRINT)){
      if(pipe->type == BGP_PIPE){
	perror(msg);
      } else {
	printf("Error: %s\n", msg);
      }
    }
  }
  pipe->error |= class;
  if(class & DEBUG_EXIT){
    bgp_print_pipe(pipe);
    printf("Aborting\n");
    exit(1);
  }
}

// Verify that it will be possible to read a certain number of bytes from
// a pipe without running out of buffered bytes.
// Always returns true for non-buffer pipes
//  pipe: the pipe to be checked
//  len: the number of bytes we expect to read from the pipe
//  returns: 1 if pipe contains at least len bytes and may be read from; else 0
unsigned int bgp_check_pipe(PIPE_TYPE pipe, int len){
  int i;

  if(pipe->error){
    return 0;
  }
  switch(pipe->type){
  case BGP_PIPE:
    return 1;
  case BGP_BUFFER:
    return len <= pipe->contents.buffer.len - pipe->contents.buffer.cursor;
  case BGP_VECTOR:
    i = pipe->contents.vector.bcursor;
    if(i < pipe->contents.vector.blen){
      len -= pipe->contents.vector.len[i] - pipe->contents.vector.cursor;
      i++;
      while((len > 0) && (i < pipe->contents.vector.blen)){
	len -= pipe->contents.vector.len[i];
	i++;
      }
    }
    return len <= 0;
  }

  assert(!"not reached");
  return 0;
}

// Read len bytes out of a pipe
//  pipe: the pipe to be read from
//  buff: the buffer to read into
//  len: the maximum number of bytes to read
//  returns: 	-1 if the pipe is flagged with an error
//				0 if EOF has been reached
//				else the number of bytes read
unsigned int bgp_read(PIPE_TYPE pipe, char *buff, int len){
  int lenread = 0, lentoread;
  if(pipe->error){
    return -1;
  }

  //printf("Trying to read from a datasource of type %d\n", pipe->type);
  switch(pipe->type){
  case BGP_PIPE:
    lenread =  read(pipe->contents.pipe, buff, len);
    if(lenread <= 0){
      pipe->error = 1;
    }
    return lenread;
  case BGP_BUFFER:
    if(len > pipe->contents.buffer.len - pipe->contents.buffer.cursor){
      len = pipe->contents.buffer.len - pipe->contents.buffer.cursor;
    }
    memcpy(buff, &(pipe->contents.buffer.buff[pipe->contents.buffer.cursor]), len);
    pipe->contents.buffer.cursor += len;
    return len;
  case BGP_VECTOR:
    //			printf("trying to read %d bytes (%d/%d:%d/%d)\n", len, pipe->contents.vector.bcursor+1, pipe->contents.vector.blen, pipe->contents.vector.cursor+1, pipe->contents.vector.len[pipe->contents.vector.bcursor]);
    while((lenread < len) && 
	  (pipe->contents.vector.bcursor < pipe->contents.vector.blen)){
      lentoread = pipe->contents.vector.len[pipe->contents.vector.bcursor] - pipe->contents.vector.cursor;
      if(lentoread > len - lenread){
	lentoread = len - lenread;
      }
      memcpy(&(buff[lenread]), &(pipe->contents.vector.buff[pipe->contents.vector.bcursor][pipe->contents.vector.cursor]), lentoread);
      lenread += lentoread;
      pipe->contents.vector.cursor += lentoread;
      if(pipe->contents.vector.cursor >= pipe->contents.vector.len[pipe->contents.vector.bcursor]){
	pipe->contents.vector.bcursor++;
	pipe->contents.vector.cursor = 0;
      }
    }
    return lenread;
  }
  return 0;
}

// discard a chunk of data
//  len: the number of bytes to discard
//  pipe: the pipe to discard from
//  returns: the number of bytes actually discarded
unsigned int bgp_dump_data(int len, PIPE_TYPE pipe){
  char buf[20];
  int r, tot = 0;
  while(len > 0){
    r = bgp_read(pipe, buf, MIN(len, 20));
    if(r > 0){
      len -= r;
      tot += r;
    } else {
      bgp_parse_error("Insufficient data to parse packet (p)", DEBUG_FORMAT, pipe);
      break;
    }
  }
  return tot;
}

// discard a chunk of data and print it to the screen
//  len: the number of bytes to discard
//  pipe: the pipe to discard from
//  returns: the number of bytes actually discarded
unsigned int bgp_dump_print(int len, PIPE_TYPE pipe){
  unsigned char buf[20];
  int r, tot = 0;
  while(len > 0){
    r = bgp_read(pipe, (char *)buf, MIN(len, 20));
    if(r > 0){
      len -= r;
      tot += r;
      bgp_print_hex(buf, r);
    } else {
      bgp_parse_error("Insufficient data to parse packet (d)", DEBUG_FORMAT, pipe);
      break;
    }
  }
  return tot;
}

// Read a number from the pipe and convert to host byte order
//  len: 1, 2 or 4 (the size of the number: byte, short, int)
//  pipe: the pipe to read from
//  returns: the number read
unsigned int bgp_read_num(int len, PIPE_TYPE pipe){
  unsigned char ret[4] = {0,0,0,0};
  int c;

  if(pipe->error){
    return 0;
  }

  *((int *)ret) = 0;
  if((len > 4) || (len < 1)){
    printf("ERROR: read length %d\n", len);
    bgp_parse_error("READ NUM: Invalid length", DEBUG_INTERNAL, pipe);
  }
  c = bgp_read(pipe, (char *)ret, len);
  if(c < len){
    printf("ERROR: read %u / %u\n", c, len);
    bgp_parse_error("Insufficient data to parse packet (n)", DEBUG_FORMAT, pipe);
    return 0;
  }
  if(len == 2){
    return ntohs(*((unsigned short *)ret));
  } else if(len == 4) {
    return ntohl(*((unsigned long *)ret));
  } else {
    return (unsigned int)(*ret);
  }
}

// Free the dynamically allocated resources associated with the packet p
// note: this does not actually free p, just the resources associated with it
// This function should be called on all packets before they are freed or 
// re-used
//  p: the packet to be cleaned up
void bgp_cleanup_packet(bgp_packet *p){
  if(p->type == UPDATE){
    if(p->contents.UPDATE.withdrawv_store != NULL){
      free(p->contents.UPDATE.withdrawv_store);
      p->contents.UPDATE.withdrawv_store = NULL;
      p->contents.UPDATE.withdrawv = NULL;
    }
    p->contents.UPDATE.withdrawv_len = 0;
    
    if(p->contents.UPDATE.destv_store != NULL){
      free(p->contents.UPDATE.destv_store);
      p->contents.UPDATE.destv_store = NULL;
      p->contents.UPDATE.destv = NULL;
    }
    p->contents.UPDATE.destv_len = 0;
    
    if(p->contents.UPDATE.as_path_store != NULL){
      free(p->contents.UPDATE.as_path_store);
      p->contents.UPDATE.as_path_store = NULL;
      p->contents.UPDATE.as_path = NULL;
    }
    p->contents.UPDATE.as_path_len = 0;
    
    if(p->contents.UPDATE.as_path_buf != NULL){
      free(p->contents.UPDATE.as_path_buf);
      p->contents.UPDATE.as_path_buf = NULL;
    }
    p->contents.UPDATE.as_path_buf_len = 0;
    p->contents.UPDATE.as_path_buf_fill = 0;
    
    if(p->contents.UPDATE.as_path_buf != NULL){
      free(p->contents.UPDATE.as_path_buf);
      p->contents.UPDATE.as_path_buf = NULL;
    }
    p->contents.UPDATE.as_path_buf_len = 0;
  }
}

// Inline utility function: prints the OPEN specific contents of a message.
// This should only be called by bgp_print_packet()
//  p: the OPEN message to be printed
void bgp_print_open(bgp_packet *p){
  printf("Type: OPEN\n");
  printf("AS VERSION: %d\n", p->contents.OPEN.version);
  printf("AS ID: %d\n", p->contents.OPEN.sysid);
  printf("HOLD TIME: %d\n", p->contents.OPEN.holdtime);
  printf("SENDER ID: %d\n", p->contents.OPEN.identifier);
  if(p->contents.OPEN.flags && BGP_OPEN_AUTH_PRESENT){
    printf("Optional parameter: AUTHENTICATION\n");
  }
}

// Utility function: prints an IP address in dotted octet form
void bgp_print_ip(int i){
  printf("%d.%d.%d.%d", (i >> (24))&0xff, (i >> (16))&0xff, (i >> (8))&0xff, (i)&0xff);
}

//prints the AS_PATH attribute of an UPDATE packet (or none at all)
//  p: The UPDATE message to have its AS_PATH printed
void bgp_print_aspath(bgp_packet *p){
  bgp_as_path *y;
  int i;

  if(p->type != UPDATE){
    return;
  }

  y = p->contents.UPDATE.as_path;
  for(; y != NULL; y = y->next){
    if(y->type == 1){
      printf(" SET:");
    } else {
      printf(" SEQ:");
    }
    for(i = 0; i < y->len; i++){
      printf(" [%u]", y->list[i]);
    }
  }
}

// Inline utility function: prints the UPDATE specific contents of a message.
// This should only be called by bgp_print_packet()
//  p: the UPDATE message to be printed
void bgp_print_update(bgp_packet *p){
  bgp_ipmaskvec *x;
  int i;
  printf("Type: UPDATE\n");
  switch(p->contents.UPDATE.origin){
  case 0:
    printf("Origin: IGP\n");
    break;
  case 1:
    printf("Origin: EGP\n");
    break;
  case 2:
    printf("Origin: Incomplete\n");
    break;
  }
  printf("AS_PATH: ");
  bgp_print_aspath(p);
  printf("\n");
  printf("Next Hop: ");
  bgp_print_ip(p->contents.UPDATE.nexthop);
  printf("\n");
  printf("Preference Degree: %d\n", p->contents.UPDATE.preference); 
  x = p->contents.UPDATE.withdrawv;
  printf("Communities: ");
  for(i = 0; i < p->contents.UPDATE.num_communities; i++){
    printf("(%d:%04x) ", (p->contents.UPDATE.communities[i] >> 16), (p->contents.UPDATE.communities[i] & 0xffff));
  }
  printf("\n");
  printf("Withdrawn Routes: \n");
  while(x != NULL){
    printf("\t");
    bgp_print_ip(x->ip);
    printf("/%d\n", x->mask);
    //		printf("\t%d.%d.%d.%d/%d\n", (x->ip >> (24))&0xff, (x->ip >> (16))&0xff, (x->ip >> (8))&0xff, (x->ip)&0xff, x->mask);
    x = x->next;
  }

  x = p->contents.UPDATE.destv;
  printf("Advertised Routes: \n");
  while(x != NULL){
    printf("\t");
    bgp_print_ip(x->ip);
    printf("/%d\n", x->mask);
    //		printf("\t%d.%d.%d.%d/%d (%x)\n", (x->ip >> (24))&0xff, (x->ip >> (16))&0xff, (x->ip >> (8))&0xff, (x->ip)&0xff, x->mask, x->ip);
    x = x->next;
  }

}

void bgp_print_notification(bgp_packet *p){
  printf("Type: NOTIFICATION\n");
  switch(p->contents.NOTIFICATION.error_code){
  case 2:
    printf("OPEN message error: ");
    switch(p->contents.NOTIFICATION.error_subcode) {
    case 2:
      printf("Bad peer AS\n");
      break;
    default:
      printf("subcode = %d\n", p->contents.NOTIFICATION.error_subcode);
      break;
    }
    break;
  default:
    printf("Error code = %d, Subcode = %d\n", 
           p->contents.NOTIFICATION.error_code,
           p->contents.NOTIFICATION.error_subcode);
    break;
  }
}

// Print a packet in human readable form
//  p: the packet to be printed
void bgp_print_packet(bgp_packet *p){
  unsigned int x;
  printf("----BEGIN PACKET----\n");
  printf("Marker: ");
  for(x = 0; x < BGP_MARKER_LENGTH; x+= 8){
    printf("\n\t");
    bgp_print_hex(p->marker+x, 8);
  }
  printf("\n");
  switch(p->type){
  case OPEN:
    bgp_print_open(p);
    break;
  case UPDATE:
    bgp_print_update(p);
    break;
  case KEEPALIVE:
    printf("Type: KEEPALIVE\n");
    break;
  case NOTIFICATION:
    bgp_print_notification(p);
    break;
  }
  printf("----END PACKET----\n");
}

// Inline utility function: parse the OPEN specific contents of a message.
// this should only be called by bgp_read_packet()
//  pipe: the pipe to read from
//  packet: the memory region to parse into
//  bytecount: the advertised size of the packet
//  returns: the number of bytes read from the pipe
unsigned int bgp_read_open_packet(PIPE_TYPE pipe, bgp_packet *packet, unsigned int bytecount){
  unsigned int i, paramsize, paramtype, paramlen;

  if(bytecount < BGP_OPEN_LENGTH){
    //note that bytecount is the number of bytes the BGP header claimed
    //this packet contained.  We have already verified that the stream can
    //feed us at least this many bytes.
    bgp_parse_error("Improperly formatted OPEN packet: Insufficient data!", DEBUG_FORMAT, pipe);
    return 0;
  }

  packet->contents.OPEN.version = bgp_read_num(1, pipe);
  packet->contents.OPEN.sysid = bgp_read_num(2, pipe);
  packet->contents.OPEN.holdtime = bgp_read_num(2, pipe);
  packet->contents.OPEN.identifier = bgp_read_num(4, pipe);
  packet->contents.OPEN.flags = 0;

  i = BGP_OPEN_LENGTH;

  if((i >= bytecount) || (pipe->error)){
    //the parameter field is optional.  We determine whether it is
    //present by seeing if (according to the BGP header) there are more
    //bytes to be read after we read the OPEN header.
    //alternatively, if something went wrong we return here as well.
    return i;
  }

  paramsize = bgp_read_num(1, pipe);
  i += 1;

  if((paramsize > bytecount - i)){
    bgp_parse_error("Improperly formatted OPEN packet: incomplete parameter list", DEBUG_FORMAT, pipe);
    return i;
  }

  paramsize += i;

  while((paramsize > i) && (pipe->error != 0)){
    if(paramsize < i + 2){
      bgp_parse_error("Improperly formatted OPEN packet: incomplete parameter", DEBUG_FORMAT, pipe);
      return i;
    }
    paramtype = bgp_read_num(1, pipe);
    paramlen = bgp_read_num(1, pipe);
    if(paramlen + i + 2 > paramsize){
      bgp_parse_error("Improperly formatted OPEN packet: oversized parameter", DEBUG_FORMAT, pipe);
      return i;

    }

    i += paramlen + 2;

    switch(paramtype){
    case 1: //OPEN_AUTH
      packet->contents.OPEN.flags |= BGP_OPEN_AUTH_PRESENT;
      //there's supposedly some data here, but it's not exactly
      //well defined or anything... 
      //For now, we can just discard it (no break following this line)
    default:
      bgp_dump_data(paramlen, pipe);
      break;
    }
  } 

  return i;
}

// Inline utility function: parse a BGP prefix (allocating space for it)
// (this function should only be called by bgp_read_update_packet()
//  pipe: the pipe to parse out of
//  bytesleft: the number of bytes left in this chunk of the UPDATE
//  vec: a pointer to a pointer that will point to the prefix after return
//  returns: the number of bytes read
unsigned int bgp_read_ip_vec_linklist(PIPE_TYPE pipe, unsigned int bytesleft, bgp_ipmaskvec **vec){
  //the IPVEC is of the form [len][b1][b2][b3][b4] where b2-b4 are optional
  //len is the number of nonzero bytes in the prefix's mask.
  //b1-b4 are those nonzero bytes.  The latter bytes are left out if they
  //would be masked out completely. 
  //ie: a /8 prefix uses only b1, while a /21 prefix would use b1-b3
  unsigned int len = bgp_read_num(1, pipe); //the number of nonzero bits in the mask
  unsigned int bytes = (len + 7) / 8; //the number of bytes needed to express that
  unsigned int x;

#ifdef PRINT_DEBUG_BGP
  printf("Reading ipvec: len = %d (for %d bytes of data)\n", len, bytes);
#endif

  if((bytes+1 > bytesleft) || (len < 0) || (len > 32)){
    bgp_parse_error("Improperly formatted IPVEC: Insufficient data or out of bounds length", DEBUG_FORMAT, pipe);
    //printf(" (((( %u, %u, %u )))\n", bytes, bytesleft, len);
    return 1;
  }

  *vec = malloc(sizeof(bgp_ipmaskvec));
  if(*vec == NULL){
    bgp_parse_error("Out of memory! in bgp_read_ip_vec()", DEBUG_INTERNAL, pipe);
    return 1;
  }

  vec[0]->next = NULL;

  vec[0]->ip = 0;
  for(x = 0; x < 4; x++){
    vec[0]->ip <<= 8;
    if(x < bytes){
      vec[0]->ip |= (bgp_read_num(1, pipe) & 0xff);
    }
  }
  vec[0]->mask = len;

  return bytes + 1;
}

unsigned int bgp_read_ip_vec_array(PIPE_TYPE pipe, unsigned int bytesleft, bgp_ipmaskvec **vec, unsigned short *vec_len, unsigned int index){
  //the IPVEC is of the form [len][b1][b2][b3][b4] where b2-b4 are optional
  //len is the number of nonzero bytes in the prefix's mask.
  //b1-b4 are those nonzero bytes.  The latter bytes are left out if they
  //would be masked out completely. 
  //ie: a /8 prefix uses only b1, while a /21 prefix would use b1-b3
  unsigned int len = bgp_read_num(1, pipe); //the number of nonzero bits in the mask
  unsigned int bytes = (len + 7) / 8; //the number of bytes needed to express that
  unsigned int x;
  
  if((bytes+1 > bytesleft) || (len < 0) || (len > 32)){
    bgp_parse_error("Improperly formatted IPVEC: Insufficient data or out of bounds length", DEBUG_FORMAT, pipe);
    //printf(" (((( %u, %u, %u )))\n", bytes, bytesleft, len);
    return 1;
  }
  
  *vec = bgp_realloc(*vec, vec_len, index + 1, sizeof(bgp_ipmaskvec));
  if(*vec == NULL){
    bgp_parse_error("Out of memory! in bgp_read_ip_vec()", DEBUG_INTERNAL, pipe);
    return 1;
  }
  
  (*vec)[index].next = NULL;
  if(index > 0){
    (*vec)[index-1].next = &((*vec)[index]);
  }

  (*vec)[index].ip = 0;
  for(x = 0; x < 4; x++){
    (*vec)[index].ip <<= 8;
    if(x < bytes){
      (*vec)[index].ip |= (bgp_read_num(1, pipe) & 0xff);
    }
  }
  (*vec)[index].mask = len;

  return bytes + 1;
}

// utility function: Recursively read an AS_PATH
// (this function should only be called by bgp_read_pathattr() and itself
//  pipe: the pipe to read from
//  path: a pointer to a pointer which will point to a valid path after return
//  bytesleft: the maximum number of bytes we can read
//  returns: the number of bytes actually read
unsigned int bgp_read_aspath(PIPE_TYPE pipe, 
                             bgp_packet *p,
                             int index,
                             int bytesleft){
  int tot, i, buf_start_index = -1;

  //The AS_PATH is a strange two tier list.  It consists of multiple segments
  //of which this function reads one.  Each segment has a type followed by
  //a list of ASIDs.  The type is either sequential or unordered.  For our
  //purposes this is irrelevant, but the user may derive some benefit from
  //the difference.  

  if(bytesleft < 2){
    //since we're doing this recursively, check to see if we've
    //reached the end of the recursion
    return 0;
  }

#ifdef PRINT_DEBUG_BGP
  printf("Reading AS_PATH Segment (%d bytes left)\n", bytesleft);
#endif

  p->contents.UPDATE.as_path_store = 
    bgp_realloc(p->contents.UPDATE.as_path_store, 
                &(p->contents.UPDATE.as_path_len), 
                index+1, sizeof(bgp_as_path));
  
  p->contents.UPDATE.as_path_store[index].type = bgp_read_num(1, pipe);
  //the length is a 1 byte value.  Unlike just about every other length
  //field in the BGP spec, this one lists the number of entries rather than
  //the bytes in the field.  Fortunately, the byte length is deterministically
  //related to the number of entries, since each entry is exactly 2 bytes long
  tot = bgp_read_num(1, pipe);
  if(tot > 0){
    p->contents.UPDATE.as_path_buf = 
      bgp_realloc(p->contents.UPDATE.as_path_buf, 
                  &(p->contents.UPDATE.as_path_buf_len), 
                  p->contents.UPDATE.as_path_buf_fill + tot, 
                  sizeof(unsigned short));
    buf_start_index = p->contents.UPDATE.as_path_buf_fill;
  } else {
    p->contents.UPDATE.as_path_store[index].list = NULL;
  }
  i = 0;
  bytesleft -= 2;

  while((bytesleft >= 2) && (i < tot) && (pipe->error == 0)){
    p->contents.UPDATE.as_path_buf[p->contents.UPDATE.as_path_buf_fill] = bgp_read_num(2, pipe);
    i++;
    p->contents.UPDATE.as_path_buf_fill ++;
    bytesleft -= 2;
  }
  p->contents.UPDATE.as_path_store[index].len = i;

  tot = 2 + (i * 2);
  i = bgp_read_aspath(pipe, p, index+1, bytesleft); 
  
  if(buf_start_index >= 0){ 
    // The list pointer can't be created until after we're finished since the buffer might be realloced
    p->contents.UPDATE.as_path_store[index].list = 
      &(p->contents.UPDATE.as_path_buf[buf_start_index]);
  }
  
  if(i > 0){
    p->contents.UPDATE.as_path_store[index].next = &(p->contents.UPDATE.as_path_store[index+1]);
  } else {
    p->contents.UPDATE.as_path_store[index].next = NULL;
  }
  p->contents.UPDATE.as_path = p->contents.UPDATE.as_path_store;  //this works properly with the recursion
  
  return tot + i;
}

// Inline utility function: Read a path attribute field from an UPDATE
// (this function should only be called by bgp_read_update_packet())
//  pipe: the pipe to read from
//  packet: the packet to parse the path attribute into
//  bytesleft: the number of bytes remaining in the path attribute chunk
//  returns: the number of bytes read

#define BGP_ATTR_EXTENDED_LEN 0x10
unsigned int bgp_read_pathattr(PIPE_TYPE pipe, bgp_packet *packet, int bytesleft){
  unsigned short flags;
  short type;
  unsigned int len = 0, lenleft;

  if(bytesleft < 2){
    bgp_parse_error("Improperly formatted path attribute field: Insufficient data to read flags", DEBUG_FORMAT, pipe);
    return 0;
  }

  //Each path attribute has 3 fields: a path, a type, and a length.
  //in their infinite wisdom, BGP's creators decided to save a byte on the
  //length field where it wasn't necessary.  As a result, the length of the 
  //length field is set by flag field 0x10.  If set, the length field is 2
  //bytes.  If unset, it is 1 byte long.

  flags = bgp_read_num(1, pipe);
  type = bgp_read_num(1, pipe);

  if(bytesleft < (1 + ((flags & BGP_ATTR_EXTENDED_LEN) >> 4))){
    bgp_parse_error("Improperly formatted path attribute field: Insufficient data to read length field", DEBUG_FORMAT, pipe);
    return 2;
  }

  if(flags & BGP_ATTR_EXTENDED_LEN){
    len = bgp_read_num(2, pipe);
  } else {
    len = bgp_read_num(1, pipe);
  }

  lenleft = len;

  if(lenleft > bytesleft){
    bgp_parse_error("Improperly formatted path attribute field: Insufficient data to read data field", DEBUG_FORMAT, pipe);
    printf("  ((((( %u > %u (%x, %x) )))))  \n", lenleft, bytesleft, flags, flags & BGP_ATTR_EXTENDED_LEN);
    return 3 + ((flags & BGP_ATTR_EXTENDED_LEN) >> 4);
  }

#ifdef PRINT_DEBUG_BGP
  printf("Got pathattribute: %d (len = %d; flags = 0x%2x)\n", type, len, flags&0xff);
#endif

  switch(type){
  case 1: //origin
    //if for some reason we've got a length greater than the size
    //of an int, discard the later bytes;
    packet->contents.UPDATE.origin = bgp_read_num(MIN(len, 4), pipe);
    lenleft -= MIN(len, 4);
    break;
  case 2: //the AS_PATH attribute.  We've got a utility function for this
    packet->contents.UPDATE.as_path_buf_fill = 0;
    lenleft -= bgp_read_aspath(pipe, packet, 0, lenleft);
    break;
  case 3: //next hop IP address
    //if for some reason we've got a length greater than the size
    //of an int, discard the later bytes;
    packet->contents.UPDATE.nexthop = bgp_read_num(MIN(len, 4), pipe);
    lenleft -= MIN(len, 4);
    break;
  case 4: //discriminator for multiple AS exit points
    packet->contents.UPDATE.med = bgp_read_num(MIN(len, 4), pipe);
    lenleft -= MIN(len, 4);
    break;
  case 5: //Internal preferences (path weighting)
    //if for some reason we've got a length greater than the size
    //of an int, discard the later bytes;
    packet->contents.UPDATE.preference = bgp_read_num(MIN(len, 4), pipe);
    lenleft -= MIN(len, 4);
    break;
  case 6: //Indication that routes have been aggregated
    //The presence of this attribute means something.  It also means
    //that there's going to be an attribute 7...  sooo... do we actually care?
    break;
  case 7: //ID of aggregating AS
    packet->contents.UPDATE.aggregator = bgp_read_num(MIN(len, 4), pipe);
    lenleft -= MIN(len, 4);
    break;
  case 8: //communities attribute
    {
      int count;
      count = len / 4;
      packet->contents.UPDATE.communities = malloc(sizeof(unsigned int) * count);
      packet->contents.UPDATE.num_communities = count;
      for(count = 0; count < packet->contents.UPDATE.num_communities; count++){
        packet->contents.UPDATE.communities[count] = bgp_read_num(4, pipe);
      }
      lenleft -= count * 4;
    }
    break;
  default:
    break;
  }
#ifdef PRINT_DEBUG_BGP
  if(lenleft > 0){
    printf("Dumping excess contents (%d): ", lenleft);
    bgp_dump_print(lenleft, pipe);
    printf("\n");
  }
#else
  bgp_dump_data(lenleft, pipe);
#endif
  return len + 3 + ((flags & BGP_ATTR_EXTENDED_LEN) >> 2);
}

// Inline utility function: parse the UPDATE specific contents of a message.
// this should only be called by bgp_read_packet()
//  pipe: the pipe to read from
//  packet: the memory region to parse into
//  bytecount: the advertised size of the packet
//  returns: the number of bytes read from the pipe
unsigned int bgp_read_update_packet(PIPE_TYPE pipe, bgp_packet *packet, unsigned int bytesleft){
  unsigned int i = 0, bytesread = 0, bytesinchunk, x;

  packet->contents.UPDATE.num_communities = 0;
  packet->contents.UPDATE.withdrawv = NULL;
  packet->contents.UPDATE.destv = NULL;
  packet->contents.UPDATE.as_path = NULL;

  //again, note that bytesleft is the number of bytes the BGP header
  //tells us are in this packet.  Also note that bgp_read_packet() verifies
  //that there are at least bytesleft bytes in the stream before calling us

  if(bytesleft < 2){
    bgp_parse_error("Improperly formatted UPDATE packet: Empty packet!", DEBUG_FORMAT, pipe);
    return 0;
  }

  //the first chunk of this message contains the list of withdrawn prefixes

  bytesinchunk = bgp_read_num(2, pipe);

  bytesleft -= 2;
  bytesread += 2;

  if(bytesleft < bytesinchunk){
    bgp_parse_error("Improperly formatted UPDATE packet: Withdrawn block too large!", DEBUG_FORMAT, pipe);
    return bytesread;
  }

#ifdef PRINT_DEBUG_BGP
  printf("Reading withdrawn block: %d bytes\n", bytesinchunk);
#endif

  //this is a little bit of a hack...
  //An IP vector is a list of prefixes.  The fun part is that BGP's creators
  //decided to save a few bytes by making each entry in this list have a
  //variable size.  To make matters worse, the vector's size is given in 
  //bytes rather than entries.  Consequently, we don't actually know the size 
  //of the list until AFTER we've parsed it.  As a result, we use a variable
  //length array to store the list.  This is going to be less efficient for some
  //packet lengths, but will speed things up incredibly if we re-use the same
  //packet datastructure WITHOUT cleaning it.
  i = x = 0;
  while((bytesinchunk > i)&&(pipe->error == 0)){
    i += bgp_read_ip_vec_array(pipe, 
                              bytesinchunk - i, 
                              &(packet->contents.UPDATE.withdrawv_store),
                              &(packet->contents.UPDATE.withdrawv_len),
                              x);
#ifdef PRINT_DEBUG_BGP
    printf("read %d bytes of %d withdrawn paths so far\n", i, x);
#endif
    if(packet->contents.UPDATE.withdrawv_store == NULL){
      bgp_parse_error("Out of memory in bgp_read_update_packet: withdrawv", DEBUG_FORMAT, pipe);
      return bytesread + i;
    }
    x++;
  }
  if(x > 0){
    packet->contents.UPDATE.withdrawv = packet->contents.UPDATE.withdrawv_store;
    for(x --; x > 0; x--){
      packet->contents.UPDATE.withdrawv_store[x-1].next = &(packet->contents.UPDATE.withdrawv_store[x]);
    }
  }

  if(pipe->error){
    return bytesread + i;
  }

  bytesleft -= i;
  bytesread += i;

  // Chunk #2 contains a list of path attributes

#ifdef PRINT_DEBUG_BGP
  printf("Read %d bytes so far\n", bytesread);
#endif
  if(bytesleft < 2){
    bgp_parse_error("Improperly formatted UPDATE packet: No path attribute length field!", DEBUG_FORMAT, pipe);
    return bytesread;
  }

  bytesinchunk = bgp_read_num(2, pipe);

  bytesleft -= 2;
  bytesread += 2;

  if(bytesinchunk > bytesleft){
    bgp_parse_error("Improperly formatted UPDATE packet: Path attribute block too large!", DEBUG_FORMAT, pipe);
    return bytesread;		
  }

#ifdef PRINT_DEBUG_BGP
  printf("Reading path attributes: %d bytes\n", bytesinchunk);
#endif

  //As before, we have a number of variable length path attributes
  //We parse the relevant ones out using bgp_read_pathattr()
  i = 0; 
  while((bytesinchunk > i)&&(pipe->error == 0)){
    i += bgp_read_pathattr(pipe, packet, bytesinchunk - i);
#ifdef PRINT_DEBUG_BGP
    printf("Read %d bytes of attributes so far\n", i);
#endif
  }

  if(pipe->error){
    return bytesread + i;
  }

  bytesread += i;
  bytesleft -= i;

  //The last part of the UPDATE contains a list of destination prefixes
  // (prefixes that are now being advertised to us)
  //As with the widrawn list, we need to use assorted trickery to parse it
  //out.  Unlike the previous two chunks, the destination vector does not
  //include a size.  Instead we use the bytes remaining in the packet (based
  //on the BGP header) after the withdrawn and pathattribute vectors have
  //been removed.
  if(bytesleft <= 0){ //no advertised prefixes
    return bytesread;
  }

#ifdef PRINT_DEBUG_BGP
  printf("Reading destination paths: %d bytes\n", bytesleft);
#endif

  i = x = 0;
  while((bytesleft > i)&&(pipe->error == 0)){
    i += bgp_read_ip_vec_array(pipe, 
                              bytesleft - i, 
                              &(packet->contents.UPDATE.destv_store),
                              &(packet->contents.UPDATE.destv_len),
                              x);
#ifdef PRINT_DEBUG_BGP
    printf("read %d bytes of %d destination paths so far\n", i, x);
#endif
    if(packet->contents.UPDATE.destv_store == NULL){
      bgp_parse_error("Out of memory in bgp_read_update_packet: destv", DEBUG_FORMAT, pipe);
      return bytesread + i;
    }
    x++;
  }
  if(x > 0){
    packet->contents.UPDATE.destv = packet->contents.UPDATE.destv_store;
    for(x --; x > 0; x--){
      packet->contents.UPDATE.destv_store[x-1].next = &(packet->contents.UPDATE.destv_store[x]);
    }
  }  return bytesread + i;
}

unsigned int bgp_read_notification_packet(PIPE_TYPE pipe, bgp_packet *packet, unsigned int bytesleft){
  memset(&packet->contents.NOTIFICATION, 0,
         sizeof(packet->contents.NOTIFICATION));
  int bytesread = 0;
  if(bytesleft < 2) {
    printf("ERROR: notification packet is too short\n");
    return bytesread;
  }
  packet->contents.NOTIFICATION.error_code = bgp_read_num(1, pipe);
  packet->contents.NOTIFICATION.error_subcode = bgp_read_num(1, pipe);
  bytesleft -= 2;
  bytesread += 2;

  return bytesread;
}

// Parse a BGP packet out of a stream
//  pipe: the pipe to read a packet out of
//  packet: the memory region to parse into
//  returns: the number of bytes read from pipe
unsigned int bgp_read_packet(PIPE_TYPE pipe, bgp_packet *packet){
  unsigned int i, r, totalbytes, bytesleft;

  //memset(packet, 0, sizeof(packet));

  pipe->error = 0;

  if(!bgp_check_pipe(pipe, BGP_HEADER_LENGTH)){
    bgp_parse_error("Insufficient Data: Header", DEBUG_DATA, pipe);
    return 0;
  }

  r = 0;
  //printf("reading marker: packet %p: marker %p\n", packet, packet->marker);
  for(i = 0; i < BGP_MARKER_LENGTH; i += r){
    r = bgp_read(pipe, (char *)&(packet->marker[i]), BGP_MARKER_LENGTH - i);
    if(r < 0){
      bgp_parse_error("Insufficient Data: Marker", DEBUG_DATA, pipe);
      return i;
    }
    if (r == 0) return 0;  /* eof */
  }
  //printf("read marker\n");

  for(i = 0; i < BGP_MARKER_LENGTH; i++){
    if(packet->marker[i] != 0xff){
      bgp_parse_error("Invalid Header Marker", DEBUG_FORMAT, pipe);
      return 16;
    }
  }

  totalbytes = bytesleft = bgp_read_num(2, pipe);
  packet->type = bgp_read_num(1, pipe);
  bytesleft -= BGP_HEADER_LENGTH;

#ifdef PRINT_DEBUG_BGP
  printf("read header: %d (length: %d)\n", packet->type, bytesleft+BGP_HEADER_LENGTH);
#endif

  if(!bgp_check_pipe(pipe, bytesleft)){
    bgp_parse_error("Insufficient Data: Packet", DEBUG_DATA, pipe);
    return 0;
  }

  switch(packet->type){
  case OPEN:
    bytesleft -= bgp_read_open_packet(pipe, packet, bytesleft);
    break;
  case UPDATE:
    bytesleft -= bgp_read_update_packet(pipe, packet, bytesleft);
    break;
  case KEEPALIVE:
    //no body to be read
    break;
  case NOTIFICATION:
    bytesleft -= bgp_read_notification_packet(pipe, packet, bytesleft);
    break;
  }

  //it's possible that a later version of the protocol will include other
  //optional fields.  We don't particularly care about them, so we read all
  //that we're expected to read and dump the rest.
  // (this also serves to discard the body of the now unparsed NOTIFICATION)
  bgp_dump_data(bytesleft, pipe);
  return totalbytes;
}

void bgp_init_packet(bgp_packet *p){
  memset(p, 0, sizeof(bgp_packet));
}
