#include <nexus/defs.h>
#include <libtcpa/identity_private.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>

#include <nexus/util.h>

#define SHA1(s,l,d) sha1(s,l,d)

#include <../code/libtcpa/identity-code.c>
