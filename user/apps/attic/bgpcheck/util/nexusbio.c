#include <stdio.h>
#include <openssl/bio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include "../include/util/nexusbio.h"

static int nsd_write(BIO *b, const char *in, int inl);
static int nsd_read(BIO *b, char *out,int outl);
static int nsd_puts(BIO *bp, const char *str);
static long nsd_ctrl(BIO *b, int cmd, long num, void *ptr);
static int nsd_new(BIO *bi);
static int nsd_free(BIO *a);

static BIO_METHOD methods_nsdp=
	{
	52982,"Nexus Socket",
	nsd_write,
	nsd_read,
	nsd_puts,
	NULL, /*nsd_gets,*/
	nsd_ctrl,
	nsd_new,
	nsd_free,
	NULL,
	};

BIO_METHOD *Nexus_Sock_BIO(void){
  return &methods_nsdp;
}

static int nsd_write(BIO *b, const char *in, int inl){
  int ret;
  errno=0;

  ret=send(b->num,in,inl,0);
  BIO_clear_retry_flags(b);
  if (ret <= 0){
    if (BIO_fd_should_retry(ret))
      BIO_set_retry_write(b);
  }
  return(ret);
}
static int nsd_read(BIO *b, char *out,int outl){
  int ret=0;
  int tot=0;
  
  if (out != NULL){
    errno = 0;
    //recv has some funky blocking semantics under Nexus
    while(tot < outl){
      ret=recv(b->num,out+tot,outl-tot,0);
      if(ret > 0){
	tot += ret;
      }
    }
    BIO_clear_retry_flags(b);
    if (ret <= 0){
      if (BIO_fd_should_retry(ret))
	BIO_set_retry_read(b);
    }
  }
  return(ret);
}
static int nsd_puts(BIO *bp, const char *str){
  int n,ret;
  
  n=strlen(str);
  ret=nsd_write(bp,str,n);
  return(ret);
}
static long nsd_ctrl(BIO *b, int cmd, long num, void *ptr){
  long ret=1;
  int *ip;
  
  switch (cmd)
    {
    case BIO_CTRL_RESET:
      num=0;
    case BIO_C_FILE_SEEK:
      ret=-1;
      break;
    case BIO_C_FILE_TELL:
    case BIO_CTRL_INFO:
      ret=-1;
      break;
    case BIO_C_SET_FD:
      nsd_free(b);
      b->num= *((int *)ptr);
      b->shutdown=(int)num;
      b->init=1;
      break;
    case BIO_C_GET_FD:
      if (b->init)
	{
	  ip=(int *)ptr;
	  if (ip != NULL) *ip=b->num;
	  ret=b->num;
	}
      else
	ret= -1;
      break;
    case BIO_CTRL_GET_CLOSE:
      ret=b->shutdown;
      break;
    case BIO_CTRL_SET_CLOSE:
      b->shutdown=(int)num;
      break;
    case BIO_CTRL_PENDING:
    case BIO_CTRL_WPENDING:
      ret=0;
      break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
      ret=1;
      break;
    default:
      ret=0;
      break;
    }
  return(ret);
}
static int nsd_new(BIO *bi){
  bi->init=0;
  bi->num=0;
  bi->ptr=NULL;
  bi->flags=0;
  return(1);
}
static int nsd_free(BIO *a){
  if (a == NULL) return(0);
  if (a->shutdown)
    {
      if (a->init)
	{
	  close(a->num);
	}
      a->init=0;
      a->flags=0;
    }
  return(1);
}
