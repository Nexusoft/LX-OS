#ifndef __DEVICELOG_H__
#define __DEVICELOG_H__

#include <nexus/x86_emulate.h>

/* dump all logs to disk */
void kernel_log_region_dump_logs(void);


/* add a logging region */
void kernel_log_region_add(unsigned int vaddr, int size);

/* add a logging ioport space */
void kernel_log_io_add(unsigned int vaddr, int size);



/* read and write conform to the xen dissasembler interface */
int kernel_log_region_read(enum x86_segment seg,
			   unsigned long vaddr,
			   unsigned long *val,
			   unsigned int bytes,
			   struct x86_emulate_ctxt *ctxt);
int kernel_log_region_write(enum x86_segment seg,
			    unsigned long vaddr,
			    unsigned long val,
			    unsigned int bytes,
			    struct x86_emulate_ctxt *ctxt);

void kernel_log_io_read(unsigned short port,
			unsigned char *val,
			unsigned int bytes);

void kernel_log_io_write(unsigned short port,
			 unsigned char *val,
			 unsigned int bytes);

#endif
