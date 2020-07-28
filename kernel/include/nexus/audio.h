#ifndef __NEXUS_AUDIO_H__
#define __NEXUS_AUDIO_H__

#include "defs.h"
#include "device.h"
#include "ipd.h"

NexusOpenDevice *audio_init(NexusDevice *nd, IPD *ipd, int block);

int audio_setrate(NexusOpenDevice *nod, int hz);

int audio_write(NexusOpenDevice *nod, char *data, int len);

int audio_ioctl(NexusOpenDevice *nod, unsigned int cmd, unsigned long argvaddr, Map *m);

void i810_set_current_audio_buf(void *a);
void i810_unset_current_audio_buf(void);
#endif
