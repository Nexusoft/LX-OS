/** NexusOS: standardized logging support. 
    Uses Nexus secure storage facilities when available */

#ifndef NEXUS_USER_LOG_H
#define NEXUS_USER_LOG_H

int nxlog_write(const char *fmt, ...);
int nxlog_write_ex(int level, const char *fmt, ...);
int nxlog_write_simple(const char *string);

int nxlog_open(const char *name);
int nxlog_close(void);

extern int nxlog_fd;
extern int nxlog_level;
extern int nxlog_disable;	// if set, all logging is disabled

#endif /* NEXUS_USER_LOG_H */

