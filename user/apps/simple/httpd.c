#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <nexus/debug.h>
#include <nexus/Profile.interface.h>

#define LOCAL_ADDR (0)

#define NUM_FILE_INSTANCES (4)
// #define SERVER_PORT (80)
int server_port = 80;
int server_fd;

extern void *lastbrk;
extern int amt_small_alloced;
extern int amt_small_freed;
extern int amt_big_alloced;
extern int amt_big_freed;

int skip_spaces(char *src) {
  int i;
  for(i=0; i < strlen(src); i++) {
    if(!isspace(src[i])) {
      break;
    }
  }
  return i;
}

const char *err_format =
"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
"<html><head>\n"
"<title>404 Not Found</title>\n"
"</head><body>\n"
"<h1>Not Found</h1>\n"
"<p>The requested URL %s was not found on this server.</p>\n"
"<hr>\n"
"</body></html>\n";

char last_filename[128] = "";

void send_404(int client_fd, char *filename) {
  char err_output[1024];
  sprintf(err_output, err_format, filename);
  send(client_fd, err_output, strlen(err_output), 0);
}

#define SEND_ZERO
#define min(X,Y) (((X) < (Y)) ? (X) : (Y))
void send_file(int client_fd, int file_fd) {
#ifdef SEND_ZERO
  int tot_len = 50000000;
  static char transfer_buffer[1024 * 1024] = {0xff};
  int first = 1;
  int len;
#else
  static char transfer_buffer[1024 * 1024];
#endif
  while(1) {
#ifdef SEND_ZERO
    if(first) {
      first = 0;
      len = read(file_fd, transfer_buffer, sizeof(transfer_buffer));
    }
    len = min(len, tot_len);
    tot_len -= len;
#else
    int len = read(file_fd, transfer_buffer, sizeof(transfer_buffer));
#endif
    if(len <= 0) {
      printf("done with file\n");
      return;
    }

    char *buffer_pos = transfer_buffer;
    while(buffer_pos - transfer_buffer < len) {
      int actual_len = send(client_fd, buffer_pos,
	len - (buffer_pos - transfer_buffer), 0);
      if(actual_len <= 0) {
	printf("send client error!\n");
	return;
      }
      // sleep(1);
      buffer_pos += actual_len;
    }
  }
}

unsigned int *profile_data;

int main(int argc, char **argv) {
  profile_data = malloc(16000000);

  if(argc >= 2) {
    server_port = atoi(argv[1]);
    printf("using server port %d\n", server_port);
  }

  server_fd = socket(PF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  addr.sin_addr.s_addr = LOCAL_ADDR;
  addr.sin_port = htons(server_port);
  if(bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    printf("bind error\n");
    exit(-1);
  }

  if(listen(server_fd, 4) != 0) {
    printf("listen error\n");
    exit(-1);
  }

  int client_fd;
  int file_fd = -1;
  while(1) {
  next_connection: ;
    struct sockaddr_in addr_in;
    socklen_t addr_len = sizeof(addr_in);
    client_fd = accept(server_fd, (struct sockaddr*)&addr_in, &addr_len);
    if(client_fd < 0) {
      if(errno != EAGAIN)
	printf("bad fd!\n");
      continue;
    }
    printf("got client socket %d\n", client_fd);
    char recv_buf[1024];
    int offset = 0;
    while(1) {
    read_again: ;
#if 0
      printf("sleeping\n");
      sleep(10);
#endif
      int len = recv(client_fd, recv_buf + offset, sizeof(recv_buf) - 1 - offset, 0);
      if(len < 0) {
	if(errno != EAGAIN) {
	  printf("read error\n");
	  close(client_fd);
	  goto next_connection;
	} else {
	  goto read_again;
	}
      }
      printf("read %d\n", len);
      offset += len;
      int i;
      for(i=0; i < offset - 1; i++) {
	if(recv_buf[i] == '\r' &&  recv_buf[i + 1] == '\n') {
	  recv_buf[i+2] = '\0';
	  goto done_with_request;
	}
      }
      if(offset == sizeof(recv_buf)) {
	printf("out of buffer space!\n");
	close(client_fd);
	goto next_connection;
      }
    }
  done_with_request: ;
    char *parse_loc = recv_buf;
    parse_loc += skip_spaces(parse_loc);
    if((strncasecmp(parse_loc, "GET", 3)) != 0) {
    bad_request:
      printf("Bad request\n%s\n%s\n", recv_buf, parse_loc);
      close(client_fd);
      goto next_connection;
    }
    // skip past get
    parse_loc += 3;
    int delta = skip_spaces(parse_loc);
    if(delta == 0) {
      printf("bad request 0\n");
      goto bad_request;
    }
    parse_loc += delta;
    if(*parse_loc != '/') {
      printf("bad request 1\n");
      goto bad_request;
    }
    parse_loc++;
    int i;
    char filename[80];
    for(i=0; !isspace(parse_loc[i]); i++) {
      filename[i] = parse_loc[i];
    }
    filename[i] = '\0';
    if(strcmp(filename, last_filename) != 0) {
      if(file_fd >= 0) close(file_fd);
      printf("opening '%s'\n", filename);
      file_fd = open(filename, O_RDONLY);
      if(file_fd < 0) {
	printf("sending 404\n");
	send_404(client_fd, filename);
	close(client_fd);
	goto next_connection;
      }
      strcpy(last_filename, filename);
    } else {
      printf("reusing '%s'\n", filename);
    }

    printf("sending file\n");
    const char *ok = "HTTP/1.1 200 OK\r\n";
    send(client_fd, ok, strlen(ok), 0);
    Profile_Enable(1);
    for(i=0; i < NUM_FILE_INSTANCES; i++) {
      lseek64(file_fd, 0, SEEK_SET);
      send_file(client_fd, file_fd);
    }
    close(client_fd);
    Profile_Enable(0);
    //printf("%p (+%d)(-%d)(+%d)(-%d)\n", lastbrk, amt_small_alloced, amt_small_freed, amt_big_alloced, amt_big_freed);
    //dump_small_lists();

    {
      static int sample_filenum = 0;
      char sample_filename[80];
      int data_size = Profile_ReadSamples((unsigned char *) profile_data);
      sprintf(sample_filename, "httpd-profile-%d", sample_filenum++);
      printf("writing %d bytes to %s\n", data_size, sample_filename);
      writefile(sample_filename, profile_data, data_size);
    }
    goto next_connection;
  }
}
