#ifndef _NEXUS_TFTP_H_
#define _NEXUS_TFTP_H_

#include "mem.h"

void tftp_init(void);

/* TFTP communication with the default server. Cache contents */

char *fetch_file(char *filepath, int *filesize);
int send_file(char *filepath, char *file, int filesize);
int queue_and_send_file(char *filepath, char *file, int filesize);

/* Combine TFTP I/O with user I/O */
int peeksend_file(char *filename, Map *m, unsigned int vaddr, unsigned int filesize);
int fetchpoke_file(char *filename, int *filesize, Map *m, unsigned int vaddr, 
                   unsigned int maxsize);

// Cache access functions

const char *cache_entry(int index, const char **name, int *size);
char *cache_find(char* filename, int *size);
void cache_add(char *filename, char *file, int size);
void cache_list(void);
void cache_remove(char *filename);
int cache_clear(void);

#endif // _NEXUS_TFTP_H_
