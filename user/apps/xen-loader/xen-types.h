// Compatibility definitions

#ifndef _XEN_TYPES_H_
#define _XEN_TYPES_H_

#include <stdio.h>

#define XC_PAGE_SHIFT (12)
// #include "xc_private.h"

#define ERROR(STR, ...) fprintf(stderr, STR, ## __VA_ARGS__)
#define PERROR(STR, ...) ERROR(STR, ## __VA_ARGS__)
#define DPRINTF(STR, ...) ERROR(STR, ## __VA_ARGS__)
#define IPRINTF(STR, ...) ERROR(STR, ## __VA_ARGS__)

int xc_version(int xc_handle, int cmd, void *arg);

unsigned long xc_make_page_below_4G(int xc_handle, uint32_t domid,
                                    unsigned long mfn);

#endif // _XEN_TYPES_H_
