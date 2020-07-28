/* Demonstrator application for Nexus. 
 * Depends only on libnexus, not on POSIX libc */

#include <nexus/Thread.interface.h>
#include <nexus/Console.interface.h>
#include <nexus/Mem.interface.h>
#include <nexus/init.h>

int main(int argc, char **argv)
{
	const unsigned char hw[] = "Hello World!";
	unsigned const char *cur;
	unsigned int pages;

	pages = Mem_GetPages(8, 0);

	for (cur = hw; *cur; cur++) {
		Console_PrintChar(printhandle, *cur);
  		Thread_USleep(1 * 1000000);
	}
  	Thread_USleep(60 * 1000000);

	return 0;
}

