#ifndef __SERVICE_H__
#define __SERVICE_H__

struct Service{
  char name[64];
  int ret;
  Sema *req;
  Sema *done;
  unsigned char data[64];
#if 0 //XXX implement for more general data transfer
  Map *srcmap;
  unsigned int srcvaddr;
  int size;
#endif
};

struct ServiceReq{
  char name[64];
  unsigned char data[0];
};

#define MAXSERVICES 128
extern Service services[MAXSERVICES];
extern Sema *servicesema;
extern int servicecount;

#endif
