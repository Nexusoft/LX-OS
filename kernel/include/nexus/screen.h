#ifndef __NEXUS_SCREEN_H__
#define __NEXUS_SCREEN_H__

#include <nexus/defs.h>
#include <nexus/device.h>

struct NexusDevice;
struct NexusOpenDevice;

struct NexusOpenDevice *screen_init(struct NexusDevice *nd, IPD *ipd);

// Turn on or off printing
void screen_set_print_state(struct NexusOpenDevice *nod, int enable);

void screen_refresh(struct NexusOpenDevice *nod);

int screen_putc(struct NexusOpenDevice *nod, char c, unsigned int color);

int screen_print(NexusOpenDevice *nod, const char *string, int len);
int screen_printf(struct NexusOpenDevice *nod, const char *fmt, va_list args, unsigned int color);

int screen_blit(struct NexusOpenDevice *nod, unsigned int width, unsigned int height, unsigned char *data);
int screen_blit_native(struct NexusOpenDevice *nod,
		       unsigned int width, unsigned int height,
		       unsigned char *data);

int screen_get_geometry(struct NexusOpenDevice *nod, struct FB_Info *info);

void screen_backspace(struct NexusOpenDevice *nod);

/* dump screen contents to file */
void screen_dump(void *voidipd, void *ignore);

#endif
