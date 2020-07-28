/** NexusOS: implementation of audio, stdin, stdout, stderr, random, urandom
             special files

    XXX split into audio.c, pipe.c, stdio.c, ...
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

#include <openssl/rand.h>
#include <linux/soundcard.h>

#include <nexus/init.h>
#include <nexus/sema.h>
#include <nexus/mt19937ar.h>
#include <nexus/linuxcalls_io.h>
#include <nexus/idl.h>
#include <nexus/mt19937ar.h>

#include <nexus/Console.interface.h>
#include <nexus/Audio.interface.h>
#include <nexus/Crypto.interface.h>
#include <nexus/UserAudio.interface.h>

#include "io.private.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

#define KERNEL_AUDIO

static int audio_handle = -1;

static int audio_open(GenericDescriptor *d, 
	       const char*filename, int flags, mode_t mode) {
  d->private = "audio";
#ifdef KERNEL_AUDIO
  audio_handle = Audio_Init((flags & O_NONBLOCK)?0:1);
#else
  audio_handle = UserAudio_Init((flags & O_NONBLOCK)?0:1);
#endif
  if(audio_handle < 0) {
    return -1;
  } else {
    return 0;
  }
}

static int audio_ioctl(GenericDescriptor *d, int flag, void *data) {
  int len = 0;
  switch(flag){
  case SNDCTL_DSP_BIND_CHANNEL:
  case SNDCTL_DSP_GETCHANNELMASK:
  case SNDCTL_DSP_GETSPDIF: /* Get S/PDIF Control register */
  case SNDCTL_DSP_SETSPDIF: /* Set S/PDIF Control register */
  case SOUND_PCM_READ_BITS:
  case SOUND_PCM_READ_CHANNELS:
  case SOUND_PCM_READ_RATE:
  case SNDCTL_DSP_GETODELAY:
  case SNDCTL_DSP_GETTRIGGER:
  case SNDCTL_DSP_GETCAPS:
  case SNDCTL_DSP_CHANNELS:
  case SNDCTL_DSP_SETFMT: /* Select sample format */
  case SNDCTL_DSP_GETFMTS: /* Returns a mask of supported sample format*/
  case SNDCTL_DSP_GETBLKSIZE:
  case SNDCTL_DSP_STEREO: /* set stereo or mono channel */
  case SNDCTL_DSP_SPEED: /* set smaple rate */
  case OSS_GETVERSION:  
    len = sizeof(int);
    break;
  case SNDCTL_DSP_GETOSPACE:
  case SNDCTL_DSP_GETISPACE:
    len = sizeof(audio_buf_info);
    break;
  case SNDCTL_DSP_GETOPTR:
  case SNDCTL_DSP_GETIPTR:
    len = sizeof(count_info);
    break;
  }

#ifdef KERNEL_AUDIO
  return Audio_Ioctl(audio_handle, flag, (unsigned int)data);
#else
  struct VarLen result = {.data = data, .len = len};
  return UserAudio_Ioctl(audio_handle, flag, result, result);
#endif
}

static ssize_t audio_write(GenericDescriptor *d, const void *buf, size_t count) {
  if(count == 0)
    return 0;
#ifdef KERNEL_AUDIO
  return Audio_Write(audio_handle, (char *)buf, count);
#else
  struct VarLen vlen = {.data = (char *)buf,
			.len = count};
  int ret = UserAudio_Write(audio_handle, vlen);
  return ret;
#endif
}

static int audio_fcntl(GenericDescriptor *d, int cmd, long arg) {
  // fprintf(stderr, "fcntl(%d, %ld)", cmd, arg);
  return 0;
}

static int unsupported(GenericDescriptor *d, const char *opname, int is_sock) {
  fprintf(stderr, "Special '%s()' (on %s) unsupported!\n", opname,
	  d->private ? (char *)d->private : "std*");
  if(is_sock) {
    errno = ENOTSOCK;
  }
  return -1;
}

static int destroy(GenericDescriptor *d) {
  // no private data for audio or standard i/o
  return 0;
}

static int special_generic_close(GenericDescriptor *d) {
  // do nothing
  return 0;
}

static int special_generic_ioctl(GenericDescriptor *d, int flag, void *data) {
  // ignore
  return -1;
}

//GenericDescriptor_operations Audio_ops = {
GenericDescriptor_operations UserAudio_ops = {
  .unsupported = unsupported,
  .open = audio_open,
  .destroy = destroy,
  .fcntl = audio_fcntl,
  .ioctl = audio_ioctl,
  .write = audio_write,
  .close = special_generic_close,
};

static ssize_t 
stdin_read(GenericDescriptor *d, void *buf, size_t count) 
{
  /* XXX this should be buffered, because the fgets layer is calling this one
   * byte at a time. */
  return Console_GetData(kbdhandle, (struct VarLen) {.data=buf, .len=count}, count);
}

static ssize_t 
stderrout_write(GenericDescriptor *d, const void *buf, size_t count) 
{
  return Console_PrintString(printhandle, (char *) buf, count);
}

static int 
stderrout_fsync(GenericDescriptor *d) 
{
  return 0;
}

static int
__stdio_fcntl(GenericDescriptor *d, int cmd, long arg)
{
  switch(cmd) {
	case F_SETFL:		
	case F_GETFD:
	case F_SETFD:
	case F_GETSIG:
	case F_SETSIG:
	case F_SETOWN:	return 0;	
	case F_GETOWN:	return 1; /* fake a pid */
	case F_GETLEASE: return F_UNLCK;
  	default :
		fprintf(stderr, "NXLIBC stdio fcntl: unsupported %d\n", cmd);
		return -1;
  }
}

static int 
stdin_fcntl(GenericDescriptor *d, int cmd, long arg) 
{
	if (cmd == F_GETFL)
		return O_RDONLY;
	else
		return __stdio_fcntl(d, cmd, arg);
}

static int 
stderrout_fcntl(GenericDescriptor *d, int cmd, long arg) 
{
	if (cmd == F_GETFL)
		return O_WRONLY;
	else
		return __stdio_fcntl(d, cmd, arg);
}

const GenericDescriptor_operations Stdin_ops = {
  .unsupported = unsupported,
  .open = NULL, /* No way to open such a device */
  .destroy = destroy,
  .read = stdin_read,
  .ioctl = special_generic_ioctl,
  .close = special_generic_close,
  .fcntl = stdin_fcntl
};

const GenericDescriptor_operations Stdout_ops =  {
      .unsupported = unsupported,				
      .open = NULL, /* No way to open such a device */	
      .destroy = destroy,				
      .write = stderrout_write,				
      .fsync = stderrout_fsync,				
      .ioctl = special_generic_ioctl,			
      .close = special_generic_close,			
      .fcntl = stderrout_fcntl
};

const GenericDescriptor_operations Stderr_ops =  {
      .unsupported = unsupported,				
      .open = NULL, /* No way to open such a device */	
      .destroy = destroy,				
      .write = stderrout_write,				
      .fsync = stderrout_fsync,				
      .ioctl = special_generic_ioctl,			
      .close = special_generic_close,			
      .fcntl = stderrout_fcntl
};

static int random_mt_seed = 0;
static int random_mt_seeded = 0;

static int random_open(GenericDescriptor *d, const char* filename, 
		       int flags, mode_t mode) {
  if (strcmp("/dev/random", filename) == 0) {
    d->private = (void *) 1;  
  }
  else if(strcmp("/dev/urandom/", filename) == 0) {
    d->private = (void *) 0;
    random_mt_seeded = 1;
    init_genrand(time(NULL));
  }
  return 0;
}

static ssize_t random_read(GenericDescriptor *d, void *buf, size_t count) {
  if(d->private){ //aka do we go to the TPM?
    return RAND_bytes(buf, count);
  } else {
    unsigned char *cbuf = buf;
    int x;
    for(x = 0; x < count; x++){
      cbuf[x] = (unsigned char)(genrand_int32() & 0xff);
    }
	return count;
  }
  return count;
}
static int random_ioctl(GenericDescriptor *d, int flag, void *data) {
  //ignore for now
  fprintf(stderr, "/dev/%srandom IOCTL(0x%0x) unhandled!\n", (d->private)?"":"u", flag);
  return -1;
}

/** there is always data to read 
    XXX this is not correct for /dev/random */
int random_poll(GenericDescriptor *d, short events, short *revents){

  if (events & POLLIN) {
    *revents |= POLLIN;
    return 1;
  }
  else {
    *revents = 0;
    return 0;
  }

}

const GenericDescriptor_operations urandom_ops = {
  .unsupported = unsupported,
  .open = random_open,
  .write = NULL, //writing to /dev/random ???
  .read = random_read,
  .ioctl = random_ioctl,
  ._poll = random_poll,
  .close = special_generic_close,
};

const GenericDescriptor_operations random_ops = {
  .unsupported = unsupported,
  .open = random_open,
  .write = NULL, //writing to /dev/random ???
  .read = random_read,
  .ioctl = random_ioctl,
  ._poll = random_poll,
  .close = special_generic_close,
};

#define MAX_PIPE_DATA_SIZE (4096)

struct Pipe_Private;
typedef struct Pipe_Wrapper {
  enum {
    READER, WRITER,
  } type;
  struct Pipe_Private *priv;
  int flags; // O_NONBLOCK, etc
} Pipe_Wrapper;

typedef struct Pipe_Private {
  Sema mutex;
  CondVar free_space_change;
  int refcnt; // one ref per server and one per client, regardless of file descriptor dup()

  int len;
  int offset;

  Pipe_Wrapper reader;
  Pipe_Wrapper writer;

  GenericDescriptor *read_poll;
  GenericDescriptor *write_poll;  

  unsigned char data[0];
} Pipe_Private;

Pipe_Private *Pipe_Private_create(void) {
  Pipe_Private *priv = malloc(sizeof(*priv) + MAX_PIPE_DATA_SIZE);
  priv->mutex = ((Sema) SEMA_MUTEX_INIT);
  priv->free_space_change = ((CondVar) CONDVAR_INIT);
  priv->refcnt = 2;
  priv->len = 0;
  priv->offset = 0;

  priv->reader.type = READER;
  priv->reader.priv = priv;
  priv->reader.flags = 0;
  priv->writer.type = WRITER;
  priv->writer.priv = priv;
  priv->reader.flags = 0;

  priv->read_poll = NULL;
  priv->write_poll = NULL;
  return priv;
}

int Pipe_Private_extract(Pipe_Private *priv, void *dest, int len) {
  assert(len <= priv->len);
  unsigned char *pdest = dest;
  int tot_len = 0;
  int copy_remaining = MIN(priv->len, len);

  int head_max = MAX_PIPE_DATA_SIZE - priv->offset;
  int head_len = MIN(copy_remaining, head_max);
  memcpy(pdest, priv->data + priv->offset, head_len);

  copy_remaining -= head_len;
  priv->len -= head_len;
  priv->offset = (priv->offset + head_len) % MAX_PIPE_DATA_SIZE;
  pdest += head_len;
  tot_len += head_len;

  memcpy(pdest, priv->data + priv->offset, copy_remaining);
  priv->len -= copy_remaining;
  priv->offset = (priv->offset + copy_remaining) % MAX_PIPE_DATA_SIZE;
  pdest += copy_remaining;
  tot_len += copy_remaining;

  return tot_len;
}

void Pipe_Private_append(Pipe_Private *priv, const void *src, int len) {
  int orig_len = priv->len;
  assert(priv->len + len <= MAX_PIPE_DATA_SIZE);
  int tail_offset = (priv->offset + priv->len) % MAX_PIPE_DATA_SIZE;
  const unsigned char *psrc = src;

  int head_len = MIN(len, MAX_PIPE_DATA_SIZE - tail_offset);
  memcpy(priv->data + tail_offset, psrc, head_len);
  psrc += head_len;
  priv->len += head_len;
  tail_offset = (tail_offset + head_len) % MAX_PIPE_DATA_SIZE;

  int tail_len = MIN(len - head_len, MAX_PIPE_DATA_SIZE - tail_offset);
  memcpy(priv->data + tail_offset, psrc, tail_len);
  psrc += tail_len;
  priv->len += tail_len;

  assert(priv->len - orig_len == len);
}

void Pipe_Private_destroy(Pipe_Private *priv) {
  assert(priv->refcnt == 0);
  free(priv);
}

void pipe_init(GenericDescriptor *reader, GenericDescriptor *writer) {
  Pipe_Private *priv = Pipe_Private_create();
  reader->private = &priv->reader;
  writer->private = &priv->writer;
}

int pipe_destroy(GenericDescriptor *d) {
  Pipe_Wrapper *_priv = d->private;
  Pipe_Private *priv = _priv->priv;
  priv->refcnt--;
  if(priv->refcnt == 0) {
    Pipe_Private_destroy(priv);
  }
  return 0;
}

static ssize_t pipe_write(GenericDescriptor *d, const void *buf, size_t count) {
  Pipe_Wrapper *_priv = d->private;
  if(_priv->type != WRITER) {
    fprintf(stderr, "PIPE: Tried to write to non-reader descriptor\n");
    errno = EINVAL;
    return -1;
  }
  Pipe_Private *priv = _priv->priv;

  if(count > MAX_PIPE_DATA_SIZE) {
    fprintf(stderr, "can't write %d to pipe: max pipe write is %d\n",
	    count, MAX_PIPE_DATA_SIZE);
    return -1;
  }

  P(&priv->mutex);
  while(priv->len + count > MAX_PIPE_DATA_SIZE) {
    if(_priv->flags & O_NONBLOCK) {
      // printf("<pipe write would block>");
      V_nexus(&priv->mutex);
      return -EAGAIN;
    }
    CondVar_wait(&priv->free_space_change, &priv->mutex);
  }

  Pipe_Private_append(priv, buf, count);

  CondVar_broadcast(&priv->free_space_change);
  V_nexus(&priv->mutex);

  // release mutex before poll to avoid deadlock
  if(priv->read_poll) {
    Poll_notify(priv->read_poll, POLLIN);
    priv->read_poll = NULL;
    // printf("pipe poll read notify\n");
  }

  return count;
}

static ssize_t pipe_read(GenericDescriptor *d, void *buf, size_t count) {
  Pipe_Wrapper *_priv = d->private;
  if(_priv->type != READER) {
    fprintf(stderr, "PIPE: Tried to read from non-reader descriptor\n");
    errno = EINVAL;
    return -1;
  }
  Pipe_Private *priv = _priv->priv;

  P(&priv->mutex);
  while(priv->len == 0) {
    if(_priv->flags & O_NONBLOCK) {
      // printf("<pipe read would block>");
      V_nexus(&priv->mutex);
      return -EAGAIN;
    }
    CondVar_wait(&priv->free_space_change, &priv->mutex);
  }
  int copy_len = MIN(priv->len, count);

  int extracted = Pipe_Private_extract(priv, buf, copy_len);
  assert(extracted == copy_len);
  CondVar_broadcast(&priv->free_space_change);
  V_nexus(&priv->mutex);

  // release mutex before poll to avoid deadlock
  if(priv->write_poll) {
    Poll_notify(priv->write_poll, POLLOUT);
    priv->write_poll = NULL;
    printf("pipe poll write notify\n");
  }

  return copy_len;
}

static int pipe_fcntl(GenericDescriptor *d, int cmd, long arg) {
  if(cmd == F_SETFL && arg == O_NONBLOCK) {
    Pipe_Wrapper *_priv = d->private;
    _priv->flags |= O_NONBLOCK;
    return 0;
  } else {
    printf("pipe_fcntl(): unsupported\n");
    return -1;
  }
}

int pipe_poll(GenericDescriptor *d, short events, short *revents){
  Pipe_Wrapper *_priv = d->private;
  Pipe_Private *priv = _priv->priv;

  P(&priv->mutex);

  int err = 0;
  *revents = 0;
  if( (events & POLLIN) && _priv->type == READER) {
    if(priv->len > 0) {
      *revents |= POLLIN;
      err = 1;
      goto done;
    }
    priv->read_poll = d;
  } else if( (events & POLLOUT) && _priv->type == WRITER) {
    if(priv->len < MAX_PIPE_DATA_SIZE) {
      *revents |= POLLOUT;
      err = 1;
      goto done;
    }
    priv->write_poll = d;
  }

 done:
  V_nexus(&priv->mutex);
  return err;
}

const GenericDescriptor_operations pipe_ops = {
  .unsupported = unsupported,
  .open = NULL, // pipes are opened with "pipe()"
  .destroy = pipe_destroy,
  .write = pipe_write,
  .read = pipe_read,
  .fcntl = pipe_fcntl,
  ._poll = pipe_poll,
  .close = special_generic_close,
};

