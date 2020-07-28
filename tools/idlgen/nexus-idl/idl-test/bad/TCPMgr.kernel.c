//// DO NOT EDIT
//// INCLUDE FILES
#include "a.h"
#include <b.h>
static int TCPMgr_foo_Handler(int x, bool y, char z, int * px, int * py) /* INTERFACE */ 
{
	char *str = "in foo";
  }#include <nexus-user/syscall.h>
#include "machineprimitives.h"

/* The following ordinals must be defined in the syscall table
	TCPMgr_foo_CMD,
*/


void syscallProcessor(InterruptState *is) {
	int syscallno = is->eax;
	unsigned int arg1 = is->ecx;
	unsigned int arg2 = is->edx;
	unsigned int arg3 = is->ebx;

	switch(syscallno) {
case TCPMgr_foo_CMD: {
Some unmarshall code!
}

	}
}
