/** NexusOS: Audio driver main loop */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include <nexus/ipc.h>
#include <nexus/IPC.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/UserAudio.interface.h>

#include "longsound.h"
#include "testsound.h"

#define CHUNKSIZE 1024

extern int i810_init_module (void);
extern int init_es1370(void);

// copied from fs.h: must remain identical
struct file_operations {
	void *owner;
	loff_t (*llseek) (void*, loff_t, int);
	ssize_t (*read) (void*, char *, size_t, loff_t *);
	ssize_t (*write) (void*, const char *, size_t, loff_t *);
	int (*readdir) (void*, void *, int);
	unsigned int (*poll) (void*, void*);
	int (*ioctl) (void*, void*, unsigned int, unsigned long);
	int (*mmap) (void*, void*);
	int (*open) (void*, void*);
	int (*flush) (void*);
	int (*release) (void*, void*);
	int (*fsync) (void*, void*, int datasync);
	int (*fasync) (int, void*, int);
	int (*lock) (void*, int, void*);
	ssize_t (*readv) (void*, void*, unsigned long, loff_t *);
	ssize_t (*writev) (void*, void*, unsigned long, loff_t *);
	ssize_t (*sendpage) (void*, void*, int, size_t, loff_t *, int);
	unsigned long (*get_unmapped_area)(void*, unsigned long, unsigned long, unsigned long, unsigned long);
};

// the methods of the active audio device
// (must be set at end of driver's init, if successful)
struct file_operations *nexus_audio_fops;

int assert(int val)
{
#ifndef NDEBUG
	if (!val) {
		fprintf(stderr, "assertion failed at %s.%d\n", __FUNCTION__, __LINE__);
		abort();
	}
#endif
	return 0;
}

#ifndef NDEBUG

void testplay(void) 
{
  const unsigned int testsnd_pcm2_len = 30000;
  int i, ret;

  printk("[audio] playing short sound (%dB)\n", testsnd_pcm2_len);
  for(i = 0; i < testsnd_pcm2_len - CHUNKSIZE; i += ret){
    ret = nexus_audio_fops->write(NULL, testsnd_pcm2 + i, CHUNKSIZE & ~0x3, NULL);
    if (ret < 0) {
	    printf("        write failed\n");
	    break;
    }
  }
  printk("[audio] finished short test after %dB\n", i);

  /* the long sound */
  printk("playing long sound (%dB)\n", testsnd_pcm_len);
  for(i = 0; i < testsnd_pcm_len - CHUNKSIZE; i += ret){
    ret = nexus_audio_fops->write(NULL, testsnd_pcm + i, CHUNKSIZE & ~0x3, NULL);
    if (ret < 0) {
	    printf("        write failed\n");
	    break;
    }
  }

  printk("[audio] finished long test after %dB\n", i);
}

#endif /* not NDEBUG */

int main(int argc, char **argv) {
  void pci_enable_pfault_handler(void);
  int ret;

  // setup userlevel MMIO
  pci_enable_pfault_handler();

  // probe drivers
  if (i810_init_module() && init_es1370())
	  return 1;

  UserAudio_port_handle = IPC_CreatePort(0);

#ifndef NDEBUG
  printf("[audio] test\n");
  testplay();
#endif

  printf("[audio] up\n");
  while (1)
    UserAudio_processNextCommand();

  return 0;
}

