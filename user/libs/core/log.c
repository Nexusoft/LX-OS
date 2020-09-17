/** NexusOS: standardized logging support. 
    Uses Nexus secure storage facilities when available */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <nexus/log.h>
#include <nexus/kshmem.h>

int nxlog_fd = -1;
int nxlog_level = 1;
int nxlog_disable;

/** The others crash for credential add, 
    probably because of interpretation by printf.
 
    You probaby do not need this. Use regulat write */
int
nxlog_write_simple(const char *string)
{
	char line[512];
	int len; 
	
	if (nxlog_disable)
		return 0;

	if (nxlog_fd < 0)
		return -1;

	len = sprintf(line, "[%8u] ", NEXUSTIME);
	write(nxlog_fd, line, len);
	
	len = strlen(string);
	write(nxlog_fd, string, len);

	if (string[len - 1] != '\n')
		write(nxlog_fd, "\n", 1);

	return 0;
}

static int
nxlog_vwrite(const char *fmt, va_list args)
{
	char line[512];
	int off;

	if (nxlog_disable)
		return 0;

	if (nxlog_fd < 0)
		return -1;

	off = sprintf(line, "[%8u] ", NEXUSTIME);
	off += vsnprintf(line + off, 512 - off - 2, fmt, args);
	line[off++] = '\n';
	line[off] = 0;

	write(nxlog_fd, line, off);
	// fsync(nxlog_fd)

	return 0;
}

/** Write a message with standard headers prepended.
    End of line character is automatically appended */
int
nxlog_write(const char *fmt, ...)
{
	va_list args;
	int ret;
	
	if (nxlog_disable)
		return 0;

	va_start(args, fmt);
	ret = nxlog_vwrite(fmt, args);
	va_end(args);

	return ret;
}

/** Log messages with level less than or equal to nxlog_level */
int
nxlog_write_ex(int level, const char *fmt, ...)
{
	va_list args;
	int ret;
	
	if (nxlog_disable)
		return 0;

	if (level > nxlog_level)
		return 0;

	va_start(args, fmt);
	ret = nxlog_vwrite(fmt, args);
	va_end(args);

	return ret;
}

/** Open a logfile /var/log/$name.log

    @param name is a name for the logfile, or NULL for stderr
    @return a standard filedescriptor or -1 on failure */
int 
nxlog_open(const char *name)
{
	char filepath[512];
	unsigned long flags;

	if (nxlog_disable)
		return 0;

	if (name == NULL) {
		nxlog_fd = 2;
		return 0;
	}

	if (nxlog_fd >= 0)
		return -1;

	if (snprintf(filepath, 511, "/var/log/%s.log", name) == 511)
		return -1;

	flags =  O_WRONLY | O_CREAT | O_APPEND;
	/* flags += O_ENCRYPT | O_SIGN; // XXX enable when this works */

	nxlog_fd = open(filepath, flags, 0644);
	if (nxlog_fd > 0) {
		nxlog_write("process: %d", getpid());
		nxlog_write("log opened: %s", name);
	}

	return nxlog_fd;
}

int 
nxlog_close(void)
{
	int ret;

	nxlog_write("log closed");
	ret = close(nxlog_fd);
	nxlog_fd = -1;

	return ret;
}

