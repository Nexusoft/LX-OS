/** NexusOS: screen printing support */

#ifndef NEXUS_PRINTK_H
#define NEXUS_PRINTK_H

///// standard output 

int printk(const char *fmt, ...);
int printk_current(const char *fmt, ...);
void print_backspace(void);

///// class and level based selective output

/** List of accepted printkx classes. Extend as needed */
enum printkx_class {PK_PRINTK, PK_THREAD, PK_TFTP, PK_CACHE, PK_SYSCALL, 
		    PK_KERNELFS, PK_IPC, PK_TEST, PK_PROCESS, PK_SHELL,
		    PK_NET, PK_DRIVER, PK_PCI, PK_MEM, PK_GUARD, PK_XEN,
		    PK_DDRM};

/** List of message levels. 
    Levels are ordered and printed from 0 up to a threshold */
enum printkx_level {PK_ERR, PK_WARN, PK_INFO, PK_WARNLOW, PK_DEBUG, PK_ALL};
enum printkx_level printkx_max_level;

int printkx(enum printkx_class, enum printkx_level, const char *, ...);

///// explicitly colored output

/* colors can be any 24-bit r-g-b value, specified as 0xrrggbb00 */
/* we invert white and black, however, to make debugging easier */
#define WHITE 0x00000000
#define RED   0xFF000000
#define GREEN 0x00FF0000
#define BLUE  0x5555FF00

int printk_color(int color, const char *fmt, ...);
int printk_red(const char *fmt, ...);
int printk_green(const char *fmt, ...);

#endif /* NEXUS_PRINTK_H */

