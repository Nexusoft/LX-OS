#ifndef SOCKLIB_H
#define SOCKLIB_H

#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

int resolve(const char *server, struct in_addr *addr);
int sock_connect(const char *host, unsigned short port);

/* Initiate a TCP connection in non-blocking mode.  The function will
 * return immediately rather than waiting for the connection to succeed.
 * So it might fail, even if sock_connect_nb returns success.
 *
 * When the connection is established (or failed) the socket fd will
 * become writeable.
 *
 * To check for failure, use sock_nb_finish.
 */
int sock_connect_nb(const char *host, unsigned short port);
int sock_nb_finish(int fd);
int sock_listen(unsigned short port);
int sock_listen_anonymous(unsigned short *port_return);

#ifdef __cplusplus
}
#endif

#endif
