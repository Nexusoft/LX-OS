/* Demonstrator application for Nexus. 
 * Depends only on libnexus, not on POSIX libc */

#include <nexus/Thread.interface.h>
#include <nexus/Console.interface.h>
#include <nexus/Mem.interface.h>
#include <nexus/init.h>

int main(int argc, char **argv)
{
	char hw[] = "Hello World!";
	unsigned const char *cur;
	unsigned int pages;

	pages = Mem_GetPages(8, 0);

	Console_PrintString(hw, 13);
  	Thread_USleep(60 * 1000000);

	return 0;
}

