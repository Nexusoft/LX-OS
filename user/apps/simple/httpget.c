#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <nexus/util.h>
//#include <nexus/KernelFS.interface.h>
#include <nexus/Net.interface.h>


int client_port = 0; /* set to 1100 (or other) to use a specific client port */
		     /* or, use -1 to pick a client port based on name of file
		      * to fetch */
static int debug = 0;

// XXX use dynamic allocation based on HTTP reply header
#define BUFLEN (16384) /* size of single read */

static char readbuf[BUFLEN+1]; /* read buffer */

char *destbuf = NULL;
int destbuf_pos = 0;
int destbuf_len = 0;
int destbuf_size = 1000000;

int dotsprinted = 0;

static void init_save(void) {
  destbuf = malloc(destbuf_size);
}
static void save(const char *buf, int len) {
  if (debug) printf("saving %d start...", len);
  if(destbuf_pos + len > destbuf_size) {
    // resize
    int newsize = max(destbuf_size * 2, destbuf_len + len);
    char *temp = malloc(newsize);
    memcpy(temp, destbuf, destbuf_len);
    free(destbuf);
    destbuf = temp;
    if (debug) printf("resizing from %d to %d\n", destbuf_size, newsize);
    destbuf_size = newsize;
  }
  memcpy(destbuf + destbuf_pos, buf, len);
  destbuf_pos += len;
  destbuf_len += len;

#if 1
  int i;
  int totaldots = destbuf_len / 16384;
  for(i = 0; i < totaldots - dotsprinted; i++) {
    printf(".");
  }
  dotsprinted = totaldots;
#endif
}

int send_http_request(struct sockaddr_in dest, char *buf, int buflen) {
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(client_port);

  int fd = socket(PF_INET, SOCK_STREAM, 0);
  int err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (err) {
    printf("could not bind to local address\n");
    return -1;
  }

  err = connect(fd, (struct sockaddr *)&dest, sizeof(dest));
  if (err) {
    printf("could not connect\n");
    return -1;
  }

  write(fd, buf, buflen);

  int total = 0;
  int sleep_count = 0;
  for (;;) {
    int len = read(fd, readbuf, BUFLEN);
    if (len > 0) {
      sleep_count = 0;
      readbuf[len] = '\0';
      total += len;
    } else if (len == 0) { // got FIN
      printf("Finished transfer, got %d bytes\n", total);
      return total;
    } else {
      printf("read() interrupted. Continuing\n");
      if (sleep_count++ > 3) {
	printf("Aborted transfer after %d bytes\n", total);
	return -1;
      }
      sleep(1);
    }
  }
}

int main(int argc, char **argv) {
  struct sockaddr_in dest;
  unsigned int address[4];
  char buffer[255]; // URL. XXX make sure it does not overflow

  init_save();
  if (argc != 3) {
    printf("usage: %s ip.ip.ip.ip filepath (on server)\n", argv[0]);
    return 0;
  }

  if (sscanf(argv[1], "%d.%d.%d.%d", 
      &address[0], &address[1], &address[2], &address[3]) != 4) {
    printf("bad server ip: %s\n", argv[1]);
    exit(1);
  }

  dest.sin_family = AF_INET;
  dest.sin_port = htons(80);
  unsigned char *address_dest = (unsigned char *)&dest.sin_addr.s_addr;
  int i;
  for(i=0; i < 4; i++) address_dest[i] = address[i];

  printf("httpget: fetching %s\n", argv[2]);

  sprintf(buffer, "GET /%s\r\n", argv[2]);

  struct timeval tv_start, tv_end;
  gettimeofday(&tv_start, NULL);
  int total = send_http_request(dest, buffer, strlen(buffer));
  gettimeofday(&tv_end, NULL);

  printf("took %ld ms\n", (tv_end.tv_sec - tv_start.tv_sec) * 1000 + (tv_end.tv_usec - tv_start.tv_usec) / 1000);

  if(total > 0) {
    printf("http://%s/%s [%dB]\n%s\n", argv[1], argv[2], total, readbuf);
    return 0;
  } else {
    printf("Error fetching data\n");
    return -1;
  }
}

