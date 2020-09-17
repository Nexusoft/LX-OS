#ifndef COMMON_H
#define COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <libtcpa/identity_private.h>
#include <libtcpa/keys.h>

#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <string.h>

#include <nexus/util.h>
#include <nexus/ca.h>

int send_data(int fd, unsigned char *data, int len);
int init_server(int port);
int server_wait(int s, int good, int bad);

#endif // COMMON_H
