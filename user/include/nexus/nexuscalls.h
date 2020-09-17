/** NexusOS: library calls that are not derived from Posix */

#ifndef NEXUS_USER_CALLS_H
#define NEXUS_USER_CALLS_H

#include <nexus/fs.h>

long nxcall_exec(const char *command);
long nxcall_exec_ex(const char * filepath, 
                    char **argv, char **env, 
		    int interpose_port);

FSID nxcall_fsid_get(int fd);
FSID nxcall_fsid_byname(const char *name);


//////// file IO (extensions to Posix)

/// fcntl() option to enable/disable encryption
//  verified not to overlap with posix or GNU extensions
#define F_SETENC	0x2000	
#define F_SIGN		0x4000	///< track dirty bits and recalc sig on close
#define F_SIGNED	0x8000	///< verify signature with current file

int nxfile_port(int fd);

#endif /* NEXUS_USER_CALLS_H */

