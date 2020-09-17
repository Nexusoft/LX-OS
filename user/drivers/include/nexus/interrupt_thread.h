/** Nexus OS: pthreads related to userspace interrupt handling.
 
    Used to be part of drivers/include/interrupts.h, but the
    pthread_t caused problems when included in asm/system.h */

#ifndef NEXUS_UDRV_INTTHREAD_H
#define NEXUS_UDRV_INTTHREAD_H

int start_interrupt_thread(unsigned int irq, void (*handler)(int, void *, void *), void *dev_id);

#endif /* NEXUS_UDRV_INTTHREAD_H */

