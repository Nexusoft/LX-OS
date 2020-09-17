/** NexusOS: dummy userspace driver (for testing and benchmarking) */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/sema.h>
#include <nexus/rdtsc.h>

#include <nexus/interrupt_thread.h>
#include <nexus/Debug.interface.h>
#include <nexus/Device.interface.h>

#define IRQ_OFFSET	0x20	/* PIC IRQs start at this interrupt vector offset */
#define IRQ_DUMMYDEV	3	/* COM port */

#define IRQ_MAX		10000

static Sema sema_int = SEMA_INIT;

static void
interrupt(int irq, void *device, void *unused)
{
	assert(irq == IRQ_DUMMYDEV);
	V_nexus(&sema_int);
}

static int
test_Device(void)
{
#define TEST_NUM_ULONG 2
	unsigned long data[TEST_NUM_ULONG];
	unsigned long ret;

	// aligned dword read
	memset(data, 0, TEST_NUM_ULONG * sizeof(unsigned long));
	ret = Device_mem_read((unsigned long) data, 4);
	if (ret)
		ReturnError(1, "mem #1");

	// aligned byte write and read
	Device_mem_write((unsigned long) data, 1, 'a');
	ret = Device_mem_read((unsigned long) data, 1);
	if (ret != 'a')
		ReturnError(1, "mem #2");
	
	// unaligned word write and read
	Device_mem_write((unsigned long) data + 1, 2, 0xabcd);
	ret = Device_mem_read((unsigned long) data + 1, 2);
	if (ret != 0xabcd)
		ReturnError(1, "mem #3");

	// aligned dword write, read direct
	Device_mem_write((unsigned long) data + 4, 4, 0xeeeeeeee);
	if (data[1] != 0xeeeeeeee)
		ReturnError(1, "mem #4");

	// aligned word write direct, read
	data[0] = 0xbbbbbbbb;
	ret = Device_mem_read((unsigned long) data, 2);
	if (ret != 0xbbbb)
		ReturnError(1, "mem #5");

	printf("[dummy] OK. mem test passed\n");
	return 0;
}

int
main(int argc, char **argv)
{
	uint64_t tdiff;
	int i;

	if (test_Device())
		return 1;

	start_interrupt_thread(IRQ_DUMMYDEV, interrupt, NULL);

	tdiff = rdtsc64();
	for (i = 0; i < IRQ_MAX; i++) {
		Debug_SoftInt(IRQ_OFFSET + IRQ_DUMMYDEV);
		P(&sema_int);
	}
	tdiff =  rdtsc64() - tdiff;
	tdiff /= IRQ_MAX;

	printf("[dummy] %d interrupts. %lld cycles/int\n", IRQ_MAX, tdiff);
	return 0;
}

