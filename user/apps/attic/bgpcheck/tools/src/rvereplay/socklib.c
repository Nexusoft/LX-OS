#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "socklib.h"

int resolve(const char *server, struct in_addr *addr) {
  struct hostent *hent;

  if (inet_aton(server, addr) != 0) return 0;
  hent = gethostbyname(server);
  if (!hent) {
		herror(server);
		return -1;
	}
  memcpy(addr, hent->h_addr_list[0], sizeof(*addr));
  return 0;
}

static int sock_connect_common(const char *host, unsigned short port, int nb) {
  int fd;
  struct in_addr addr;
  struct sockaddr_in sock;

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return -1;
  }
  if (resolve(host, &addr) < 0) {
    fprintf(stderr, "Cannot resolve %s\n", host);
    return -1;
  }
	if (nb) {  /* non-blocking connect */
		int flags;

		flags = fcntl(fd, F_GETFL);
		if (flags == -1) {
			perror("fcntl");
			close(fd);
			return -1;
		}
		flags |= O_NONBLOCK;
		if (fcntl(fd, F_SETFL, flags) == -1) {
			perror("fcntl");
			close(fd);
			return -1;
		}
	}
  bzero(&sock, sizeof(sock));
  sock.sin_family = AF_INET;
  sock.sin_addr = addr;
  sock.sin_port = htons(port);
  if (connect(fd, (struct sockaddr*)&sock, sizeof(sock)) < 0) {
		if (errno != EINPROGRESS || !nb) {
			perror("connect");
			close(fd);
			return -1;
		}
  }

  return fd;
}

int sock_connect(const char *host, unsigned short port) {
	return sock_connect_common(host, port, 0);
}

int sock_connect_nb(const char *host, unsigned short port) {
	return sock_connect_common(host, port, 1);
}

int sock_nb_finish(int fd) {
	int status;
	socklen_t len = sizeof(status);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &status, &len) < 0) {
		perror("getsockopt");
		return -1;
	}
	else
		return status;
}

int sock_listen(unsigned short port) {
  int fd;
  struct sockaddr_in sock;
  int one = 1;

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return -1;
  }
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
    perror("warning: setsockopt");
  bzero(&sock, sizeof(sock));
  sock.sin_family = AF_INET;
  sock.sin_port = htons(port);
  if (bind(fd, (struct sockaddr*)&sock, sizeof(sock)) < 0) {
    perror("bind");
    close(fd);
    return -1;
  }

  if (listen(fd, 5) < 0) {
    perror("listen");
    close(fd);
    return -1;
  }

  return fd;
}

int sock_listen_anonymous(unsigned short *port_return) {
  int fd;
  struct sockaddr_in sock;
	socklen_t addrlen = sizeof(sock);

	fd = sock_listen(0);
	if (fd == -1) return -1;
	if (getsockname(fd, (struct sockaddr*)&sock, &addrlen) == -1) {
		close(fd);
		return -1;
	}
	*port_return = ntohs(sock.sin_port);

	return fd;
}
