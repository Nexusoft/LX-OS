/*
 *  linux/init/main.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  GK 2/5/95  -  Changed to support mounting root fs via NFS
 *  Added initrd & change_root: Werner Almesberger & Hans Lermen, Feb '96
 *  Moan early if gcc is old, avoiding bogus kernels - Paul Gortmaker, May '96
 *  Simplified starting of init:  Michael A. Griffith <grif@acm.org>
 */

#include <nexus/defs.h>
#include <nexus/machineprimitives.h>
#include <asm/bitops.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>
#include <nexus/debug.h>

extern void setup_arch(char **);
extern void init_IRQ(void);
extern void time_init(void);
extern void nexus_init(void);

char * boot_command_line;
asmlinkage void start_kernel(void)
{
/*
 * Interrupts are still disabled. Do necessary setups, then
 * enable them
 */

	setup_arch(&boot_command_line);

/* disabled because adds dependency on strstr and is probably not used. */
#ifdef ENABLE_GDBEARLY
	/* enable_gdb_mode usually called later init.c
	 * but you can call it here (or even early) to debug stuff before init.c
	 */
	if (strstr(boot_command_line, "gdbearly"))
		enable_gdb_mode(NULL);
#endif

	init_IRQ();
	time_init();

	enable_intr();

	/* begin Nexus boot */
	nexus_init();
}

#ifndef __OPTIMIZE__
// Helper functions for -O0 build

unsigned int __find_first_bit(const unsigned long *bits, unsigned int nbits) {
  assert(nbits <= 32);
  return ffs(bits[0]);
}

void prefetch(const void *x) {
}

unsigned int ntohl(unsigned int val) {
  unsigned char *ptr = (unsigned char *)&val;
  return (unsigned int) (ptr[0]<<24) | (ptr[1]<<16) | (ptr[2]<<8) | ptr[3];
}
unsigned int htonl(unsigned int val) {
  unsigned int ret;
  unsigned char *ptr = (unsigned char *)&ret;

  ptr[0] = val>>24;
  ptr[1] = val>>16;
  ptr[2] = val>>8;
  ptr[3] = val;
  
  return ret;
} 

unsigned short ntohs(unsigned short val) {
  unsigned char *ptr = (unsigned char *)&val;
  return (unsigned short) (ptr[0]<<8) | ptr[1];
}

unsigned short htons(unsigned short val) {
  return ntohs(val);
}

int unregister_chrdev(unsigned int i, const char * c) {
  printk("unregister chrdev\n");
  assert(0);
  return -1;
}

#endif // __OPTIMIZE__

void skb_over_panic(struct sk_buff *skb, int len, void *here) {printk("DAN: skb_over_panic!!!\n");}

