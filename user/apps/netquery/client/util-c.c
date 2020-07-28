#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <nq/netquery.h>
#include <nq/gcmalloc.h>
#include <stdio.h>

// Print a set of bytes in hexadecimal pair notation
//  c: The start of the byte array to be printed
//  len: the length of the byte array to be printed
void print_hex(unsigned char *c, int len){
  static char hexlist[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  int x;
  for(x = 0; x < len; x++){
    if(x > 0){
      if((x % 2) == 0){
        putchar(' ');
        if((x % 40) == 0){
          putchar('\n');
        }
      }
    }
    putchar(hexlist[((c[x]&0xf0)>>4)]);
    putchar(hexlist[(c[x]&0xf)]);
  }
}

void fprint_ip(FILE *fp, int i){
  fprintf(fp, "%d.%d.%d.%d", (i)&0xff, (i >> (8))&0xff, (i >> (16))&0xff, (i >> (24))&0xff);
}

void print_ip(int i){
  fprint_ip(stdout, i);
}

int parse_addr_spec(const char *str, struct sockaddr_in *output) {
  int result;
  char *ip = strdup(str);
  char *port = strchr(str, ':') + 1;
  memset(output, 0, sizeof(*output));
  if(port != NULL) {
    *(port - 1) = '\0';
    struct in_addr addr;
    if(!inet_aton(str, &addr)) {
      goto parse_err;
    }
    output->sin_family = AF_INET;
    output->sin_addr = addr;
    output->sin_port = htons(atoi(port));
    result = 0;
  } else {
  parse_err:
    result = -1;
  }
  free(ip);
  return result;
}

