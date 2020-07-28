#ifndef __NEXUS_AUDIO_PRIVATE_H__
#define __NEXUS_AUDIO_PRIVATE_H__

#include <nexus/audio.h>

struct AudioBuf {
  int hz;
  Sema *block;
  int waiting;
	// we need to buffer writes in the background, instead of just blocking
	// char *backbuf;
	// int backpos;
};

#endif
