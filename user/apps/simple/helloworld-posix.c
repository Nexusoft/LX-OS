/* Demonstrator application for Nexus. 
 * Depends only on Posix, not directly on libnexus */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include <nexus/linuxcalls.h>
#include <nexus/Debug.interface.h>
#include <nexus/Console.interface.h>

int main(int argc, char **argv)
{
	char *data;
	pid_t pid;

	brk((void *) 0x100);
	data = malloc(10);

	pid = getpid();
	printf("Hello World! I'm process %d\n", pid);

	sleep(3);
	return 0;
}

