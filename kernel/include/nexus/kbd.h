#ifndef __NEXUS_KBD_H__
#define __NEXUS_KBD_H__

#include "defs.h"
#include "device.h"
#include "ipd.h"
#include "mem.h"

#include <nexus/keyboard.h>

void kbd_start(NexusDevice *nd);
NexusOpenDevice *kbd_new(NexusDevice *nd, IPD *ipd);

int kbd_setmode(NexusOpenDevice *nod, KbdMode mode);
struct BasicThread;
void kbd_set_xen_irq_thread(NexusOpenDevice *nod, struct BasicThread *t);

KbdMode kbd_getmode(NexusOpenDevice *nod);
// *size contains that max amount of data to return, and is set to the amount of data returned
void kbd_getdata(NexusOpenDevice *nod, int *size, char *dest);
int kbd_hasline(NexusOpenDevice *nod);
int kbd_hasdata(NexusOpenDevice *nod);

void nexus_kbd_focus(NexusOpenDevice *nod, int focus);

// Interface between low-level (Linux-derived drivers) and upper-level
// (Nexus API)
struct kbd_drv_context;

struct kbd_drv_context *kbd_drv_context_new(void);

void kbd_drv_context_save(struct kbd_drv_context *ctx);
void kbd_drv_context_restore(struct kbd_drv_context *ctx);

void kbd_drv_context_change_mode(struct kbd_drv_context *ctx, int focused, KbdMode mode);

int kbd_drv_keymap_get_entry(int table, int entry);

#endif
