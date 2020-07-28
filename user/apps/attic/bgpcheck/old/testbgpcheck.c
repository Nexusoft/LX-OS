#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bgp.h"
#include "bgpcheck.h"

extern bc_prefix *bc_create_prefix(bc_prefix *parent, int bit);
static int bc_monitor_incoming_stream_sb(char *buffer, int bufflen, bc_global_data *data);

int main(int argc, char **argv){
  char buffer[2000];
  int cursor = 1000, end = 1000, readcnt, fdepth = -1000;
  int count = 0, i;
  int pipe = open("binary", O_RDONLY, 755);
  if (pipe == -1) { perror("binary"); exit(1); }
  bc_global_data d;
  bgp_packet packet;

  d.root = bc_create_prefix(NULL, 0);
  d.as_id = 73; //dummy variables; Normally these would be user configged
  d.my_id = 42;

#ifndef PARSE_ONE
  while(1){
    printf("==== %d ====\n", ++count);
#endif
    if(end - cursor < 1000){
      if(end != cursor){
	for(i = 0; i <= end-cursor; i++){
	  buffer[i] = buffer[i+cursor];
	}
      }
      end -= cursor;
      fdepth += cursor;
      cursor = 0;
      readcnt = read(pipe, &(buffer[end]), 1000);
#ifndef PARSE_ONE
      if(readcnt < 1){
	break;
      }
      end += readcnt;
#else
      if(readcnt > 0){
	end += readcnt;
      }
#endif
    }
    cursor += DUMP_LENGTH;
    readcnt = bc_monitor_incoming_stream_sb(&(buffer[cursor]), end-cursor, &d);
    if(readcnt > 0){
      cursor += readcnt;
      //			printf("Read 0x%x bytes of packet, cursor at 0x%x\n", readcnt, cursor);
    } else {
#ifndef PARSE_ONE
      break;
      return 0;
#else
      printf("Couldn't read a whole packet!");
      return 0;
#endif		
    }
#ifndef PARSE_ONE
  }
#endif

  //now some quick checks

  printf("\n\n\n==== PARSING COMPLETE; START TESTS ====\n");
  printf("--- Lookup test ---\n");
  bc_test_prefix(&d, 0xFFAF5200, 32, "should have been withdrawn");
  bc_test_prefix(&d, 0xFFFFD300, 32, "should have a valid path");
  bc_test_prefix(&d, 0xFFFFC000, 32, "has been subdivided, searching for specific IP so should still be valid");
  bc_test_prefix(&d, 0xFFFFC000, 19, "has been subdivided, the old prefix should no longer be valid");
  bc_test_prefix(&d, 0xFFFFC000, 21, "has been subdivided, a prefix of the correct depth should work");


  printf("\n\n\n--- Packet test (good packet) ---\n");
  memset(packet.marker, 0xff, BGP_MARKER_LENGTH);
  packet.type = UPDATE;
  packet.contents.UPDATE.withdrawv = NULL;
  packet.contents.UPDATE.destv = malloc(sizeof(bgp_ipmaskvec));
  packet.contents.UPDATE.destv->ip = 0xFFFFD300;
  packet.contents.UPDATE.destv->mask = 24;
  packet.contents.UPDATE.destv->next = NULL;	
  packet.contents.UPDATE.as_path = malloc(sizeof(bgp_as_path));
  packet.contents.UPDATE.as_path->list = malloc(sizeof(short) * 7);
  packet.contents.UPDATE.as_path->list[0] = 42;
  packet.contents.UPDATE.as_path->list[1] = 73;
  packet.contents.UPDATE.as_path->list[2] = 101;
  packet.contents.UPDATE.as_path->list[3] = 2914;
  packet.contents.UPDATE.as_path->list[4] = 3356;
  packet.contents.UPDATE.as_path->list[5] = 19159;
  packet.contents.UPDATE.as_path->len = 6;
  packet.contents.UPDATE.as_path->type = 2;
  packet.contents.UPDATE.as_path->next = NULL;
  bgp_print_packet(&packet);
  if(bc_parse_outgoing_packet(&packet, &d) > 0){
    printf("SUCCESS (packet permitted)\n");
  } else {
    printf("FAILED\n");
  }

  printf("--- Packet test (advertising an unknown prefix; rule 1) ---\n");
  packet.contents.UPDATE.destv->mask = 22;
  bgp_print_packet(&packet);
  if(bc_parse_outgoing_packet(&packet, &d) > 0){
    printf("FAILED\n");
  } else {
    printf("SUCCESS (packet blocked)\n");
  }

  printf("--- Packet test (advertising a withdrawn prefix; rule 1) ---\n");
  packet.contents.UPDATE.destv->mask = 23;
  packet.contents.UPDATE.destv->ip = 0xFFAF5200;
  bgp_print_packet(&packet);
  if(bc_parse_outgoing_packet(&packet, &d) > 0){
    printf("FAILED\n");
  } else {
    printf("SUCCESS (packet blocked)\n");
  }


  printf("--- Packet test (someone else as the next hop; rule 2) ---\n");
  packet.contents.UPDATE.destv->ip = 0xFFFFD300;
  packet.contents.UPDATE.destv->mask = 24;
  packet.contents.UPDATE.as_path->list[0] = 43;
  bgp_print_packet(&packet);
  if(bc_parse_outgoing_packet(&packet, &d) > 0){
    printf("FAILED\n");
  } else {
    printf("SUCCESS (packet blocked)\n");
  }

  printf("--- Packet test (missing elements in the route; rule 3) ---\n");
  packet.contents.UPDATE.as_path->list[0] = 42;
  packet.contents.UPDATE.as_path->len = 5;
  bgp_print_packet(&packet);
  if(bc_parse_outgoing_packet(&packet, &d) > 0){
    printf("FAILED\n");
  } else {
    printf("SUCCESS (packet blocked)\n");
  }

  printf("--- Packet test (loop in route; rule 4) ---\n");
  packet.contents.UPDATE.as_path->len = 7;
  packet.contents.UPDATE.as_path->list[6] = 42;
  bgp_print_packet(&packet);
  if(bc_parse_outgoing_packet(&packet, &d) > 0){
    printf("FAILED\n");
  } else {
    printf("SUCCESS (packet blocked)\n");
  }

  return 0;
}

static int bc_monitor_incoming_stream_sb(char *buffer, int bufflen, bc_global_data *data){
	bgp_datasource p;
	bgp_packet packet;
	p.type = BGP_BUFFER;
	p.error = 0;
	p.contents.buffer.cursor = 0;
	p.contents.buffer.len = bufflen;
	p.contents.buffer.buff = buffer;
	int readcount = bc_monitor_incoming_stream(&p, data, &packet);
	bgp_cleanup_packet(&packet);
	return readcount;
}
