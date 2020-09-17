/** NexusOS:  reader-writer locks */

#ifndef NEXUS_COMMON_RWSEMA_H
#define NEXUS_COMMON_RWSEMA_H

/// reader-writer lock
typedef struct RWSema {
  struct Sema sema;
  struct Sema writer_mutex;
  int max_readers;		// same as the initial value of s
} RWSema;

RWSema * rwsema_new(int value);
void     rwsema_set(RWSema *s, int value);
void     rwsema_del(RWSema *s);

void P_writer(RWSema *s);
void V_writer(RWSema *s);
void P_reader(RWSema *s);
void V_reader(RWSema *s);

#endif

