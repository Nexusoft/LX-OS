#ifndef __NEXUS_SCREEN_H__
#define __NEXUS_SCREEN_H__

#include <nexus/defs.h>
#include <nexus/device.h>

struct nxconsole;

void *screen_init(int console_id, const char *name, const char *sha1);

int screen_print(struct nxconsole *console, const char *string, int len);
int screen_printf(struct nxconsole *console, const char *fmt, va_list args, unsigned int color);
int screen_blit(struct nxconsole *console, unsigned int width, unsigned int height, unsigned char *data);
void screen_backspace(struct nxconsole *console);

void screen_refresh(void);
void screen_redrawline(void);

#endif

