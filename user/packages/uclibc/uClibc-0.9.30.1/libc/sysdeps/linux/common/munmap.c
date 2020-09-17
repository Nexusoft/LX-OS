/* vi: set sw=4 ts=4: */
/*
 * munmap() for uClibc
 *
 * Copyright (C) 2000-2006 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>

#include "linuxcalls_io.h"

libc_hidden_proto(munmap)

int munmap(void *start, size_t length)
{
	return nxlibc_syscall_munmap(start, length);
}

libc_hidden_def(munmap)
