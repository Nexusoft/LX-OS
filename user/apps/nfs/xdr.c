#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include "xdr.h"

#define FRAG_SIZE (32*1024-4)

u32 * xdr_encode_array(u32 *p, const char *s, unsigned int len)
{
	int i;
	for (i = 0; i < len/4; i++) {
		*p++ = htonl((((u8)s[4*i]) << 24) | (((u8)s[4*i+1]) << 16) | (((u8)s[4*i+2]) << 8) | ((u8)s[4*i+3]));
	}
	switch (len & 0x3) {
		case 3: *p++ = htonl((((u8)s[4*i]) << 24) | (((u8)s[4*i+1]) << 16) | (((u8)s[4*i+2]) << 8));
				break;
		case 2: *p++ = htonl((((u8)s[4*i]) << 24) | (((u8)s[4*i+1]) << 16));
				break;
		case 1: *p++ = htonl((((u8)s[4*i]) << 24));
				break;
		case 0: break;
	}
	return p;
}

u32 * xdr_decode_array(u32 *p, char *s, unsigned int len) {
	int i;
	memcpy(s, p, len);
	return p + ((len+3) & ~0x3);
}

u32 * xdr_encode_string(u32 *p, const char *s)
{
	int n = strlen(s);
	p = xdr_encode_int(p, n);
	p = xdr_encode_array(p, s, n);
	return p;
}

extern u32 *xdr_decode_string(u32 *p, int *plen, char **s) {
	*plen -= 4;
	if (*plen < 0)
		return NULL;
	unsigned int slen;
	p = xdr_decode_int(p, &slen);
	*plen -= ((slen + 3) & ~0x3);
	if (*plen < 0)
		return NULL;
	char *str = malloc(slen + 1);
	*s = str;
	return xdr_decode_array(p, str, slen);
}

u32 * xdr_encode_authnull(u32 *p) {
	p = xdr_encode_int(p, 0);
	p = xdr_encode_int(p, 0);
	return p;
}

u32 * xdr_encode_authunix(u32 *p, char *uname, u32 uid) {
	p = xdr_encode_int(p, AUTH_UNIX);
	p = xdr_encode_int(p, 5*4 + xstrlen(uname));
	p = xdr_encode_int(p, uid); // stamp: arbitrary int 
	p = xdr_encode_string(p, uname);
	p = xdr_encode_int(p, uid);
	p = xdr_encode_int(p, uid); // gid
	p = xdr_encode_int(p, 1);
	p = xdr_encode_int(p, uid); // gids
	return p;
}

int rpc_send(int fd, char *data, int nbytes) {
	assert((nbytes&0x3) == 0);
	assert(nbytes >= 4); // first 4 bytes reserved
	nbytes -= 4;

	int nfrags = (nbytes == 0 ? 1 : (nbytes + FRAG_SIZE - 1) / FRAG_SIZE);

	// send all but last fragment
	int i;
	for (i = 0; i < nfrags-1; i++) {
		xdr_encode_int((u32*)data, FRAG_SIZE);
		if (write(fd, data, FRAG_SIZE+4) != FRAG_SIZE+4)
			return -EAGAIN; // stream closed most likely
		data += FRAG_SIZE;
	}

	int nleft = nbytes - (nfrags-1)*FRAG_SIZE;
	xdr_encode_int((u32*)data, nleft | 0x80000000);
	if (write(fd, data, nleft+4) != nleft+4)
		return -EAGAIN; // stream closed most likely

	return 0;
}

static int read_n(int fd, char *buf, int len, int max) {
	int got = 0;
	while (got < len) {
		int addl = read(fd, buf+got, max-got);
		if (addl <= 0) {
			return -EAGAIN;
		}
		got += addl;
	}
	return got;
}

int rpc_recv(int fd, char **data, int *nbytes) {
	int buflen = FRAG_SIZE+4;
	char *buf = malloc(FRAG_SIZE+4);
	char *retbuf = NULL;
	int retlen = 0;

	int lastfrag;
	do {
		int got = read_n(fd, buf, 4, FRAG_SIZE+4); // we can only safely read this much b/c only one outstanding request
		if (got < 0) {
			free(buf);
			if (retbuf) free(retbuf);
			return -EAGAIN;
		}

		unsigned int fh;
		xdr_decode_int((u32*)buf, &fh);

		lastfrag = fh & 0x80000000;
		int fragsize = fh & 0x7FFFFFFF;
		if (fragsize + 4 > buflen) {
			buf = realloc(buf, buflen = fragsize + 4);
		}

		got = read_n(fd, buf+got, fragsize+4-got, fragsize+4-got);
		if (got < 0) {
			free(buf);
			if (retbuf) free(retbuf);
			return -EAGAIN;
		}

		retbuf = realloc(retbuf, retlen + fragsize);
		memcpy(retbuf+retlen, buf+4, fragsize);
		retlen += fragsize;
	} while (!lastfrag);

	assert((retlen & 0x3) == 0);
	free(buf);

	*data = retbuf;
	*nbytes = retlen;

	return 0;
}
