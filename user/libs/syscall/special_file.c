/** NexusOS: implementation of audio, stdin, stdout, stderr, random, urandom
             special files
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>

#include <openssl/rand.h>

#include <linux/soundcard.h>
#include <linux/tty.h>
#include <asm/ioctls.h>

#include <nexus/idl.h>
#include <nexus/sema.h>
#include <nexus/syscalls.h>
#include <nexus/linuxcalls_io.h>

#include <nexus/IPC.interface.h>
#include <nexus/Console.interface.h>
#include <nexus/UserAudio.interface.h>

#include "io.private.h"

#define MIN(a,b) (((a)<(b))?(a):(b))


////////  support functions (shared by all)  ////////

static int 
__noop_close(GenericDescriptor *d) 
{
	// do nothing
	return 0;
}

static int 
__noop_ioctl(GenericDescriptor *d, int flag, void *data) 
{
	fprintf(stderr, "[%s] no ioctl %d (0%o 0x%x)\n", 
		d->ops->name, flag, flag, flag);
	return -1;
}

static int 
__noop_unsupported(GenericDescriptor *d, const char *opname, int is_sock) 
{
  fprintf(stderr, "Special '%s()' (on %s) unsupported!\n", opname,
	  d->private ? (char *)d->private : "std*");
  return -1;
}


////////  audio device  ////////

static int audio_handle = -1;

static int audio_open(GenericDescriptor *d, 
	       const char*filename, int flags, mode_t mode) {
  d->private = "audio";
  audio_handle = UserAudio_Init((flags & O_NONBLOCK)?0:1);
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

  struct VarLen result = {.data = data, .len = len};
  return UserAudio_Ioctl(audio_handle, flag, result, result);
}

static ssize_t audio_write(GenericDescriptor *d, const void *buf, size_t count) {
  if (!count)
    return 0;

  return UserAudio_Write(audio_handle, (struct VarLen) {.data = (char *) buf, .len = count});
}

static int audio_fcntl(GenericDescriptor *d, int cmd, long arg) {
  return 0;
}

GenericDescriptor_operations UserAudio_ops = {
  .name = "user audio",
  .unsupported = __noop_unsupported,

  .open = audio_open,
  .close = __noop_close,
  
  .write = audio_write,
  
  .fcntl = audio_fcntl,
  .ioctl = audio_ioctl,
};


////////  stdio  ////////

static ssize_t 
stdin_read(GenericDescriptor *d, void *buf, size_t count) 
{
  return Console_GetData((struct VarLen) {.data=buf, .len=count}, count);
}

static int
stdin_poll(GenericDescriptor *d, int dir)
{
	return dir & (Console_HasLine() ? IPC_READ : 0);
}

static ssize_t 
stderrout_write(GenericDescriptor *d, const void *buf, size_t count) 
{
  return Console_PrintString((char *) buf, count);
}

static int 
stderrout_fsync(GenericDescriptor *d) 
{
  return 0;
}

static int
stderrout_poll(GenericDescriptor *d, int dir)
{
	return dir & IPC_WRITE;
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
	case F_SETLK:
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
stdin_port(GenericDescriptor *d)
{
	return default_keyboard_port;
}

static int 
stderrout_fcntl(GenericDescriptor *d, int cmd, long arg) 
{
	if (cmd == F_GETFL)
		return O_WRONLY;
	else
		return __stdio_fcntl(d, cmd, arg);
}

// mimic the linux kernel termios structure, not the libc interface
#define NCC 17
struct ktermios {
	unsigned short c_iflag;		/* input mode flags */
	unsigned short c_oflag;		/* output mode flags */
	unsigned short c_cflag;		/* control mode flags */
	unsigned short c_lflag;		/* local mode flags */
	unsigned char c_line;		/* line discipline */
	unsigned char c_cc[NCC];	/* control characters */
};
/** Terminal specific ioctls */
static int
stdio_ioctl_termios(int flag, void *data)
{
        static struct ktermios nxterm = {
            .c_iflag = IGNBRK | IGNCR | IGNPAR ,
            .c_oflag = 0,
            .c_cflag = CS8 | CLOCAL,
            .c_lflag = ECHO | ECHOE | ECHONL | ICANON,
        };
	static int initialized;

	// poor man's array init 
	// not multithread safe
	if (!initialized) {
		nxterm.c_cc[VEOF]   =  4 	/* Ctrl-D */;
		nxterm.c_cc[VEOL]   = '\n';
		nxterm.c_cc[VERASE] = 127	/* delete */;		
		
		nxterm.c_cc[VINTR]  =  3 	/* Ctrl-C */;
		nxterm.c_cc[VKILL]  = 21 	/* clear line: Ctrl-U */;
		//nxterm.c_cc[VDSUSP] = 25 	/* Ctrl-Y */;
		nxterm.c_cc[VSUSP]  = 26 	/* Ctrl-Z */;
		nxterm.c_cc[VQUIT]  = 28 	/* Ctrl-\ */;
		
		nxterm.c_cc[VSTOP]  = 19 	/* Ctrl-S */;
		nxterm.c_cc[VSTART] = 17 	/* Ctrl-Q */;
		initialized = 1;
	}

	if (flag == TCGETS) {
		memcpy(data, &nxterm, sizeof(nxterm));
	}
	else {
		struct ktermios *newterm = data;

		// update mode: raw or cooked
		if (nxterm.c_lflag & ICANON) {
		    if (!(newterm->c_lflag & ICANON))
//			Console_SetInputMode(KBD_RAW);
			fprintf(stderr, "SET INPUT RAW\n");
		}
		else {
		    if (newterm->c_lflag & ICANON)
//			Console_SetInputMode(KBD_COOKED);
			fprintf(stderr, "SET INPUT COOKED\n");
		}

		// XXX handle all terminal changes
		
		memcpy(&nxterm, data, sizeof(nxterm));
	}

	return 0;
}

struct kwinsize {
	unsigned short ws_row;
	unsigned short ws_col;
	unsigned short ws_xpixel;
	unsigned short ws_ypixel;
};

static int
stdio_ioctl_winsize(void *data)
{
	struct kwinsize *ws = data;

	ws->ws_row = 128;
	ws->ws_col = 44;
	ws->ws_xpixel = 1024;
	ws->ws_ypixel = 768 - 32 /* subtract exactly nexus secure region at top: 2 lines */;

	return 0;
}

static int 
stdio_ioctl(GenericDescriptor *d, int flag, void *data) 
{
	switch (flag) {
		case TCGETS:	
		case TCSETS:	return -ENOTTY; // return stdio_ioctl_termios(flag, data);
		case TIOCGWINSZ:return -ENOTTY; // return stdio_ioctl_winsize(data); 
		default: 	return __noop_ioctl(d, flag, data);
	}

	fprintf(stderr, "[%s] no ioctl %d (0%o 0x%x)\n", 
		d->ops->name, flag, flag, flag);
	return -1;
}

const GenericDescriptor_operations Stdin_ops = {
	.name = "stdin",
	.unsupported = __noop_unsupported,

	.open = NULL, /* No way to open such a device */
	.close = __noop_close,
	
	.read = stdin_read,
	
	.fcntl = stdin_fcntl,
	.ioctl = stdio_ioctl,
	.port = stdin_port,
	.poll = stdin_poll,
};

const GenericDescriptor_operations Stdout_ops =  {
	.name  = "stdout",
	.unsupported = __noop_unsupported,

	.open  = NULL, /* No way to open such a device */	
	.close = __noop_close,			
	
	.write = stderrout_write,				
	
	.fsync = stderrout_fsync,				
	.fcntl = stderrout_fcntl,
	.ioctl = stdio_ioctl,	
	.poll  = stderrout_poll,
};

const GenericDescriptor_operations Stderr_ops =  {
	.name = "stderr",
	.unsupported = __noop_unsupported,				

	.open = NULL, /* No way to open such a device */	
	.close = __noop_close,			
	
	.write = stderrout_write,				
	
	.fsync = stderrout_fsync,				
	.fcntl = stderrout_fcntl,
	.ioctl = stdio_ioctl,
	.poll = stderrout_poll,
};


////////  (u)random devices  ////////

// XXX static seed: hardly random
static int 
random_open(GenericDescriptor *d, const char* filename, 
	    int flags, mode_t mode) 
{
  if (!strcmp("/dev/random", filename)) {
    RAND_seed(random_open, 1024);
    d->private = (void *) 1;  
  }
  else if (!strcmp("/dev/urandom/", filename)) {
    srandom(0);
    d->private = (void *) 0;
  }

  return 0;
}

static ssize_t 
random_read(GenericDescriptor *d, void *buf, size_t count) 
{
  unsigned char*cbuf = buf;
  int x;
  
  if (d->private) {
    printf("blocking read\n");
    return RAND_bytes(buf, count);
  }
  
  for (x = 0; x < count; x++)
    cbuf[x] = random();

  return count;
}

static int 
random_ioctl(GenericDescriptor *d, int flag, void *data) 
{
  // ignore 
  return 0;
}

static int 
random_port(GenericDescriptor *d)
{
    return -1;
}

const GenericDescriptor_operations urandom_ops = {
  .name = "urandom",
  .unsupported = __noop_unsupported,
  
  .open = random_open,
  .close = __noop_close,
  
  .read = random_read,
  
  .ioctl = random_ioctl,
  .port = random_port,
  .poll = stderrout_poll,
};

const GenericDescriptor_operations random_ops = {
  .name = "random",
  .unsupported = __noop_unsupported,
 
  .open = random_open,
  .close = __noop_close,

  .read = random_read,
  
  .ioctl = random_ioctl,
  .port = random_port,
  .poll = stderrout_poll,
};


////////  Unix Pipes  ////////
//
// these pipes are not pure continuous bitstreams:
// ipc channels return bytes as packets. Thus, for
//   write(..., 1); 
//   write(..., 1);
//   len = read(..., 100);
// len will read 1. This is allowed by the spec, but non-standard.

static int 
pipe_open(GenericDescriptor *d, const char* filename, 
	  int flags, mode_t mode) 
{
	if (filename != NULL)
		return -1;

	d->private = (void *) IPC_CreatePort(0);
	return 0;
}

static int 
pipe_close(GenericDescriptor *d) 
{
	// noop: called for both descriptors. 
	//       destroy(), OTOH, is called only once
	return 0;
}

static int
pipe_destroy(GenericDescriptor *d)
{
	IPC_DestroyPort((long) d->private);
	return 0;
}

static ssize_t 
pipe_write(GenericDescriptor *d, const void *buf, size_t count) 
{
	int ret;

	ret = ipc_send((long) d->private, (void *) buf, count);
	return ret ? -1 : count;
}

static ssize_t 
pipe_read(GenericDescriptor *d, void *buf, size_t count) 
{
	return ipc_recv((long) d->private, buf, count);
}

static int 
pipe_fcntl(GenericDescriptor *d, int cmd, long arg) 
{
	if (cmd == F_GETFD || cmd == F_SETFD)
		return 0;

	fprintf(stderr, "pipe_fcntl(): unimplement cmd %d. Aborting\n", cmd);
	abort();
}

static int 
pipe_port(GenericDescriptor *d)
{
	return (int) d->private;
}

static int
pipe_poll(GenericDescriptor *d, int dir)
{
	return IPC_Poll((long) d->private, dir);
}

const GenericDescriptor_operations pipe_ops = {
  .name = 	"pipe",
  .unsupported = __noop_unsupported,

  .open = 	pipe_open,
  .close = 	pipe_close,
  .destroy = 	pipe_destroy,

  .read = 	pipe_read,
  .write = 	pipe_write,
  
  .fcntl = 	pipe_fcntl,
  .port = 	pipe_port,
  .poll =	pipe_poll,
};

