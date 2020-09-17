/** NexusOS: demo the guard: allow writing to a file until 
             the first five characters read 'FINAL'.
 
    NB: to avoid infinite recursion, never call this authority
    on a file read operation, as it reads itself.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/defs.h>
#include <nexus/guard.h>
#include <nexus/test.h>

#include <nexus/FS.interface.h>
#include <nexus/Auth.interface.h>

int 
auth_answer(const char *req, int pid)
{
	FSID file;
	char head[5];
	unsigned long long upper;
	int ret, writable;

	// this example authority uses sscanf to parse the expression
	// understand that this is FRAGILE with regard to whitespace, etc.
	ret = sscanf(req, "pem (%%0) says ipc.%u.<<%llx>> = writable", 
		     &file.port, &upper);
	if (ret != 2)
		ReturnError(0, "parse");

	// read the first bytes of the file
	((struct FSID_pretty *) &file)->upper = upper;
	if (FS_Read(file, 0, VARLEN(head, 5), 5) != 5)
		ReturnError(0, "read");
	writable = memcmp(head, "FINAL", 5) ? 1 : 0;

	printf("[auth.ff] writable ? %s. first bytes are %c%c%c%c%c\n",
	       writable ? "yes" : "NO",
	       head[0], head[1], head[2], head[3], head[4]);

	return writable;
}


int
main(int argc, char **argv)
{
	return nxguard_auth(default_guard_port, "ff", NULL);
}

