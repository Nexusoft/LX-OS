#ifndef _NEXUS_UTIL_H_
#define _NEXUS_UTIL_H_

#define isadigit(c) ((c) >= '0' && (c) <= '9')
#define isahexdigit(c) (((c) >= '0' && (c) <= '9') || ((c) >= 'a' && (c) <= 'f'))

#ifdef __NEXUSKERNEL__ 
// outside of kernel, this is prototyped in stdlib.h
int atoi(const char *s);
#else
void dump_stack_trace(unsigned int *ebp);
int dump_stack_trace_array(unsigned long *addrs, int numaddrs);
#endif // __NEXUSKERNEL__ 

int hexatoi(const char *s);

/*
 * min()/max() macros that also do
 * strict type-checking.. See the
 * "unnecessary" pointer comparison.
 */
#define min(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })

#define max(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })

/*
 * ..and if you can't take the strict
 * types, you can specify one yourself.
 *
 * Or not use min/max at all, of course.
 */
#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })



/* prepend or append a string to another string and get the result in
 * a malloced buffer */
char *get_string_ext(char *prefix, char *filename, char *suffix);
void put_string_ext(char *filenameext);


int find_badchar(char *name, int startpoint);


/* To avoid writing this loop for printing bytes over and over... */
#ifndef __NEXUSKERNEL__
#define PRINT_UTIL printf
#else
#define PRINT_UTIL printk_red
#endif
//#ifndef __NEXUSKERNEL__
#define PRINT_BYTES(x,l)  do{			\
    int i;					\
    for(i = 0; i < (l); i++)			\
      PRINT_UTIL("%02x", (x)[i]);			\
  }while(0);


#define PRINT_HASH(x)  do{			\
    PRINT_BYTES(x,TCPA_HASH_SIZE);		\
    PRINT_UTIL("\n");				\
  }while(0);
//#endif

#ifndef __NEXUSKERNEL__
/* These simple loops have been written too many times... */

/* Read a file (optionally, in a directory), returning data and length, or NULL
 * on error.  Data will be null terminated as well, which is only useful if the
 * file contains text. The terminating null does not count as part of the
 * length. */
unsigned char *read_file(char *fname, int *len);
unsigned char *read_file_dir(char *dirname, char *fname, int *len);

/* Write a file (optionally, in a directory), returning 0 on success. */
int write_file(char *fname, unsigned char *data, int len);
int write_file_dir(char *dirname, char *fname, unsigned char *data, int len);

int is_directory(char *dirname, char *fname);

char *file_hash(char *dirname, char *fname);

void hexdump(char *data, int len);
#endif // __NEXUSKERNEL__

#endif

