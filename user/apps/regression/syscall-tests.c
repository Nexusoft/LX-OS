#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <nexus/sema.h>
#include <nexus/Thread.interface.h>
#include <nexus/Console.interface.h>
#include <nexus/Audio.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/debug.h>
#include "../nameserver/NS.interface.h"
#include <compat/commoncompat.h>
#include <compat/tpmcompat.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <fcntl.h>

#include <linux/soundcard.h>

extern int ioctl(int fd, int flag, void *data);
extern unsigned int getmyinet_addr(void);

#define MAX_NUM_THREADS (16)
pthread_t t[MAX_NUM_THREADS];

#include "nexus/syscalls.h"

#define DEST_ADDR (0x8054df8f)

struct TestContext {
  int tid;
};

void line_pause(void) {
  char data[80];
  fgets(data, sizeof(data), stdin);
}


#define FORK_KILL(N)							\
void *N##_fork(int *done_flag) {					\
  pthread_t thread;							\
  struct TestContext *ctx = (struct TestContext *)malloc(sizeof(struct TestContext)); \
  int err = pthread_create(&thread, NULL, N##_fn, done_flag);	\
  if(err != 0) {							\
    printf("pthread fork returned %d\n", err);				\
    return NULL;							\
  }									\
  ctx->tid = thread;							\
  printf("fork thread id = %d\n", ctx->tid);				\
  return ctx;								\
}									\
void N##_kill(void *_ctx) {					\
  struct TestContext *ctx = (struct TestContext *)_ctx;			\
  Thread_Kill(ctx->tid); printf("issued kill of %d\n", ctx->tid);	\
  /* pthread_kill(ctx->tid, 9); */					\
  free(ctx);								\
}

#if 0
void *recv_block_fn(void *ctx) {
  int *done_flag = (int *)ctx;
  char buffer[1600];
  printf("before block\n");
  int handle = nexuscall3(SYS_RECV_BLOCK, (int)buffer, 1999, -1);
  printf("ERROR: returned from recv_block!\n");
  *done_flag = 1;
  return NULL;
}
FORK_KILL(recv_block);
#endif

static void *t0_proc(void *ctx) {
  int id = Thread_GetID();
  printf("id=%d\n", id);
  printf("before exit\n");
  Thread_Exit(0, 0, 0);
  printf("should not get here\n");
  return NULL;
}
static void *t1_proc(void *ctx) {
  int id = (int)pthread_self();
  printf("pthread_id=%d\n", id);
  printf("before exit\n");
  exit(0);
  printf("should not get here\n");
  return NULL;
}

static void *t2_proc(void *ctx) {
  printf("forked %d\n", (int)pthread_self());
  return NULL;
}

static void *t3_proc(void *ctx) {
  printf("forked %d\n", (int)pthread_self());
  printf("before sleep(100)\n");
  sleep(100);
  printf("woke up from sleep\n");
  return NULL;
}

Sema *t4_s;

static void *t4_proc(void *ctx) {
  printf("forked %d\n", (int)pthread_self());
  printf("before P()\n");
  P(t4_s);
  printf("after P()\n");
  return NULL;
}

//pthread_create(&t[0], NULL, t1_proc, NULL);

int main(int argc, char **argv) {
  int would_block = 0;
  if(argc < 2) {
    printf("syscall-tests needs at least one argument\n");
    exit(-1);
  }
  int test_num = atoi(argv[1]);
  switch(test_num) {
  case 0: {
    // GetID and exit (low level)
    int i;
    for(i=0; i < MAX_NUM_THREADS; i++) {
      pthread_create(&t[i], NULL, t0_proc, NULL);
    }
    break;
  }
  case 1: {
    int i;
    // GetID and exit, high level
    // via pthread_init, pthread_self 
    for(i=0; i < MAX_NUM_THREADS; i++) {
      pthread_create(&t[i], NULL, t1_proc, NULL);
    }
    break;
  }
  case 2: {
    int i;
    for(i=0; i < 2; i++) {
      pthread_create(&t[i], NULL, t2_proc, NULL);
    }
    printf("sleep 5\n");
    sleep(5);
    printf("after sleep 5\n");

    printf("usleep 10000000\n");
    usleep(10000000);
    printf("after usleep 10000000\n");

    struct timespec req = {
      .tv_sec = 15,
      .tv_nsec = 0,
    }, rem;
    printf("nanosleep 15000000\n");
    nanosleep(&req, &rem);
    printf("after nanosleep 15000000\n");
    break;
  }
  case 3: {
    printf("sleep cancellation\n");
    pthread_create(&t[0], NULL, t3_proc, NULL);
#if 1
    sleep(1);
    // cancel sleep
    Thread_CancelSleep((int)t[0]);
#else
    sleep(200);
#endif
    break;
  }
  case 4: {
    t4_s = sema_new();
    printf("sleep cancellation\n");
    pthread_create(&t[0], NULL, t4_proc, NULL);
    sleep(5);
    V_nexus(t4_s);
    break;
  }
  case 5: {
    printf("kill test\n");
    printf("Needs to be updated to new version of Recv()\n");
#if 0
    int done = 0;
    void *ctx = recv_block_fork(&done);
    recv_block_kill(ctx);
    break;
#endif
  }
 case 6: {
   extern unsigned int kbdhandle;
   char buf[80];
   printf("console test\n"); // this tests printchar
   // Blit_Init() is called from program initialization
   int i;
   int limit = 5;
   for(i=0; i < limit; i++) {
     printf("[%d/%d] waiting for input: > ", i, limit);
     struct VarLen desc = {
       .data = buf,
       .len = sizeof(buf),
     };
     int cnt = Console_GetData(kbdhandle, desc, sizeof(buf));
     printf("got %s (%d)\n", buf, cnt);
   }
   break;
 }
  case 7: {
    printf("blit test\n");
    extern unsigned int printhandle;
    char data[3*10*40];
    int i, c;
	for(c = 0; /*c < 0xff*/; c++) {
		int r,g,b;
		for(i=0; i < 10*40; i++) {
			r = (c+i)&0xff;
			g = (c+i+0x55)&0xff;
			b = (c+i+0xa5)&0xff;
		  data[3 * i + 0] = (r < 0x55 ? 0 : (r > 0xa5) ? r-0xa5 : r);
		  data[3 * i + 1] = (g < 0x55 ? 0 : (g > 0xa5) ? g-0xa5 : r);
		  data[3 * i + 2] = (b < 0x55 ? 0 : (b > 0xa5) ? b-0xa5 : r);
		}
		//printf("color %d : %d %d %d\n", c, r, g, b);
		Console_Blit_Frame(printhandle, data, 40, 10);
	}
    break;
  }
  case 8: {
    int j;
	int written = 0;
	//int real_rate = Audio_SetRate(8000);
	//printf("got %d for real_rate\n", real_rate);
	//Audio_ioctl();
	printf("opening /dev/dsp\n");
	int f = open("/dev/dsp", O_WRONLY);
	///printf("got fd=%d.  doing ioctl\n", f);
	//int rate = 11025;
	//ioctl(f, SNDCTL_DSP_SPEED, &rate);
	//printf("got %d for real_rate\n", rate);


	//int snd = open("/nfs/snd", O_RDONLY);
	//char *buf = (char *)malloc(4096 * 8);
	//int numread = read(snd, buf, 4096 * 8);

	/* XXX 
	 * DAN: this doesn't seem to make a sound so I just read a
	 * raw sound file from disk instead.  Fix this if you know what is
	 * going on here.*/
#if 1
	int extend;
	for(extend = 0; extend < 1; extend++){
	  for (j = 1; j < 30; j++) {
	    int seq[] = {6, 6, 9, 9, 10, 10, 9};
	    //char buf[7*3*1024];
	    short buf[7*3*1024];
	    int base = 120*9/3;

	    int s;
	    for (s = 0; s < 7; s++) {
	      short v = 0;
	      int a = base /seq[s];
	      int i;
	      for (i = 0; i < 3*1024; i++) {
		if (i % a == 0) v = (v ? 0:0x6fff);
		buf[s*3*1024+i] = (i > 3*1024-300 ? 0 : v);
	      }
	    }
	    //printf("writing %d to fd\n", sizeof(buf));
	    written = write(f, buf, sizeof(buf));
	    //printf("just wrote %d\n", written);
	  }
	}
#else
	written += write(f, buf, numread);
	printf("now have written %d\n", written);
	free(buf);
	close(snd);
#endif
	close(f);
	printf("done.");
   break;
  }
  case 9: {
    printf("Log tests\n");
    int x = 5;
    Log_PrintStandard("Log %d\n", x);
    Log_DumpStandard();
    break;
  }
  case 10: {
    printf("KernelFS (TFTP and file cache) tests\n");
    int fd = open("in_testfile", O_RDONLY);
    char buf[1024];
    int sum = 0;
    while(1) {
      int count = read(fd, buf, sizeof(buf));
      int i;
      for(i=0; i < count; i++) {
	sum += buf[i];
	printf("%c", buf[i]);
      }
      if(count != sizeof(buf)) break;
    }
    close(fd);
    char *test_string = "Subscribe signs you up to receive updates when changes are detected at a website. Unsubscribe stops notifications from the named website. List shows you what you have signed up for so far.  Try \"help examples\" to see some examples of how to get started using Corona.  Type \"help\" followed by a command above to find out more about it.";
    writefile("out_testfile", test_string, strlen(test_string));
    break;
  }
  case 11: {
    printf("Gettimeofday()\n");
    int i;
    for(i=0; i < 5; i++) {
      struct timeval tv;
      memset(&tv, 0, sizeof(tv));
      int rv = gettimeofday(&tv, NULL);
      printf("tv = { %d, %d } (%d)\n", (int)tv.tv_sec, (int)tv.tv_usec, rv);
      sleep(1);
    }
    break;
  }
  case 12: {
    printf("audio test\n");
    int sndfile = open("track.pcm", O_RDONLY);
    int dsp = open("/dev/dsp", O_RDWR);

    int i;
    for(i=0; i < 2; i++) {
      int speed;
      int real_speed;
      if(i==0) {
	speed = 44100;
      } else {
	speed = 44100 / 2;
      }
      real_speed = ioctl(dsp, SNDCTL_DSP_SPEED, &speed);
      printf("%d =? %d\n", speed, real_speed);
      while(1) {
	char buf[1024];
	int amt = read(sndfile, buf, sizeof(buf));
	write(dsp, buf, amt);
	if(amt != sizeof(buf)) break;
      }
    }
    break;
  }
  case 13: {
    struct sockaddr_in addr = {
      .sin_port = htons(1024),
      .sin_addr = { getmyinet_addr() },
    }, dest_addr = {
      .sin_port = htons(1024),
      .sin_addr = { htonl(DEST_ADDR) },
    };
    printf("UDP test\n");
    int s = socket(PF_INET, SOCK_DGRAM, 0);
    // printf("socket = %d\n", s);
    int bind_rval = bind(s, (struct sockaddr *) &addr, sizeof(addr));
    printf("bind(%d)=>%d\n", s, bind_rval);

    char data[] = "hello world";
    int i;
    for(i=0; i < 5; i++) {
      int send_rv = sendto(s,data,strlen(data),0,
			   (struct sockaddr *) &dest_addr, sizeof(dest_addr));
      printf("send(%d) => %d\n", i, send_rv);
    }
    // test poll
    printf("polling for events\n");
    int count = 0;
    struct pollfd fds = {
      .fd = s,
      .events = POLLIN,
      .revents = 0,
    };
    while(poll(&fds, 1, -1) == 0) {
      if(count++ > 100000) {
	printf(".");
	count = 0;
      }
    }
    printf("revents = %d\n", fds.revents);
    struct sockaddr_in r_addr;
    unsigned int len = sizeof(r_addr);
    char r_data[1600];
    int recv_rv = recvfrom(s, r_data, sizeof(r_data), 0,
			   (struct sockaddr *) &r_addr, &len);
    printf("recv_rv = %d\n", recv_rv);

    r_data[30] = '\0';
    printf("excerpt = %s\n", r_data + 15);
    break;
  }
  case 15: {
    
    printf("non-blocking udp recv\n");
    would_block = 0;
    goto generic_udp_block;
  }
  case  16: {
    would_block = 1;
    generic_udp_block: ; 
    struct sockaddr_in addr = {
      .sin_port = htons(1024),
      .sin_addr = { getmyinet_addr() },
    };
    int s = socket(PF_INET, SOCK_DGRAM, 0);
    int bind_rval = bind(s, (struct sockaddr *) &addr, sizeof(addr));
    printf("bind(%d)=>%d\n", s, bind_rval);
    if(!would_block) {
      fcntl(s, F_SETFL, O_NONBLOCK);
    }
    struct sockaddr_in r_addr;
    unsigned int len = sizeof(r_addr);
    char r_data[1600];
    printf("about to recv (block = %d)\n", would_block);
    int count = 0;
    while(1) {
      int recv_rv = recvfrom(s, r_data, sizeof(r_data), 0,
			     (struct sockaddr *) &r_addr, &len);
      count++;
      if(count > 10000 || recv_rv >= 0) {
	printf("after recv: %d\n", recv_rv);
	count = 0;
      }
      if(recv_rv != -1) {
	break;
      }
    }
    break;
  }
  case 17: {
    char *name = "testsvc", *name1 = "testsvc-alt";

    int err_count = 0;
#define SUCCEED(RV) do { printf("succeed? "); if((RV) < 0) err_count++; } while(0)
#define FAIL(RV) do { printf("fail? "); if((RV) >= 0) err_count++; } while(0)

    Port_Num channel_port_num;
    Port_Handle channel_port_handle = IPC_CreatePort(&channel_port_num);
    SUCCEED(channel_port_handle);
    printf("channel_port_handle = %d\n", channel_port_handle);
    int rv;
    struct NS_SimpleRegisterCtx *ctx = NS_SimpleRegister(name, channel_port_num);
    rv = (ctx != NULL) ? 0 : -1;
    SUCCEED(rv);
    printf("SimpleRegisterName()=>%d\n", rv);
    rv = NS_SimpleLookup(name);
    SUCCEED(rv);
    printf("SimpleLookup()=>%d\n", rv); // should succeed

    rv = NS_Unregister(ctx->service_description); // this one won't free the ctx
    SUCCEED(rv);

    rv = NS_SimpleLookup(name);
    FAIL(rv);
    printf("SimpleLookup()=>%d\n", rv);     // should fail

    rv = NS_SimpleUnregister(ctx); // this one will free the ctx
    FAIL(rv);
    printf("SimpleUnregisterName()=>%d\n", rv); // should fail

    rv = IPC_DestroyPort(channel_port_handle);
    SUCCEED(rv);
    printf("Unregister()=>%d\n", rv);     // should succeed

    rv = IPC_DestroyPort(channel_port_handle);
    FAIL(rv);
    printf("Unregister()=>%d\n", rv);     // should fail

    ctx = NS_SimpleRegister(name1, channel_port_handle);
    rv = (ctx != NULL) ? 0 : -1;
    FAIL(rv);
    printf("SimpleRegister()=>%d\n", rv);

    rv = NS_SimpleLookup(name1);
    FAIL(rv);
    printf("Lookup()=>%d\n", rv);     // should fail

    printf("err count = %d\n", err_count);
    return (err_count == 0) ? 0 : -1;
    break;
  }
  case 30: {
    char line[80];
    printf("Testing fgets(stdin)\n");
    printf("Type a line: \n");
    fgets(line, sizeof(line), stdin);
    printf("input was '%s'\n", line);
    break;
  }

  case 31: {
    // Reference count
    IPC_Counters counter0, counter1;
    int rv;

    rv = Debug_get_ipc_counters(&counter0);
    assert(rv == 0);
    printf("start: "); IPCCounters_print(&counter0);


#define NUM_PORTS (3)
    struct {
      Port_Handle handle;
      Port_Num port_num;
    } ports[NUM_PORTS];
    int i;
    for(i=0; i < NUM_PORTS; i++) {
      ports[i].handle = IPC_CreatePort(&ports[i].port_num);
      printf("created %d %d\n", ports[i].handle, ports[i].port_num);
      assert(ports[i].handle > 0);
    }

    rv = Debug_get_ipc_counters(&counter1);
    printf("After creation of %d: ", NUM_PORTS); IPCCounters_print(&counter0);

    for(i=0; i < NUM_PORTS; i++) {
      rv = IPC_DestroyPort(ports[i].handle);
      printf("destroyed %d %d\n", ports[i].handle, ports[i].port_num);
      assert(rv == 0);
    }

    printf("Destroyed ports\n");
    rv = Debug_get_ipc_counters(&counter1);
    IPC_Counters delta = IPCCounters_subtract(&counter1, &counter0);
    assert(rv == 0);
    printf("delta: "); IPCCounters_print(&delta);
    printf("end: "); IPCCounters_print(&counter1);
    if(delta.IPC_Port != 0) {
      printf("IPC port count mismatch!\n");
      return -1;
    }
    printf("Good IPC port count, test succeeded\n");
    break;
#undef NUM_PORTS
  }
  default:
    printf("Unknown test %d\n", test_num);
    break;
 }
  return 0;
}
