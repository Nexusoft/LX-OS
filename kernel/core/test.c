/** NexusOS: regression testing 
    see test.h for more information */

#include <nexus/printk.h>
#include <nexus/regression.h>
#include <nexus/hashtable.h>
#include <nexus/queue.h>
#include <nexus/ipc.h>
#include <nexus/net.h>
#include <nexus/elf.h>
#include <nexus/initrd.h>
#include <nexus/bitmap.h>
#include <nexus/guard.h>
#include <nexus/test.h>

#define TEST_EARLY 1
#define TEST_LATE 2

int unittest_active;
int unittest_active_early;

/** a unittest. 
    
    @param when describes when to run the test. 
           if TEST_EARLY is set, the test is run as soon as the screen is up
	   if TEST_LATE is set, the test is run as the shell initializes */
struct unittest {
	unittest_func func;
	unsigned int when;
	const char *name;
};

/* declare test functions here that go without a header file */
int test_memcpy(void);
int test_ipc(void);
int test_paged_ipc(void);

/** register a unittest by adding it to this list.
    the last element of the list MUST be empty */
#ifndef NDEBUG
static struct unittest unittests[] = {
	{ .func = run_thread_test, 		.when = TEST_LATE,	.name = "thread" },
	{ .func = run_thread_spawn_test, 	.when = TEST_LATE,	.name = "spawn" },
	{ .func = run_sema_pingpong_test, 	.when = TEST_LATE,	.name = "semaphore" },
	{ .func = uqueue_unittest, 		.when = TEST_LATE,	.name = "queue" },
	{ .func = hash_test, 			.when = TEST_LATE,	.name = "hash" },
	{ .func = hash_var_test, 		.when = TEST_LATE,	.name = "hash (var)" },
	{ .func = test_memcpy, 			.when = 0,		.name = "memcpy" },
	{ .func = test_ipc, 			.when = TEST_LATE,	.name = "ipc" },
	{ .func = test_paged_ipc, 		.when = TEST_LATE,	.name = "ipc (paged)" },
	{ .func = nxnet_filter_test, 		.when = TEST_LATE,	.name = "net (filter)" },
	{ .func = nxtwobit_selftest,		.when = TEST_EARLY,	.name = "twobit"},
	{ .func = nxnibble_selftest,		.when = TEST_EARLY,	.name = "nibble"},
	{ .func = nxkguard_unittest,		.when = TEST_LATE,	.name = "guard"},
	{ .func = IPCPort_unittest, 		.when = TEST_EARLY | TEST_LATE,	.name = "ipc (port)" },
	{ .func = ipcpoll_unittest, 		.when = TEST_LATE,	.name = "ipc (poll)" },
	{}
};
#endif

static void __unittest_runall(unsigned int when)
{
#ifndef NDEBUG
	enum printkx_level pksave;
	struct unittest *cur;
	int total, failed, ret;

	// set global environment flags
	unittest_active = 1;
	if (when == TEST_EARLY)
		unittest_active_early = 1;

	// temporarily disable warnings 
	pksave = printkx_max_level;
	printkx_max_level = PK_ERR;

	// run all tests that match 'when'
	total = 0;
	failed = 0;
	for (cur = unittests; cur->func; cur++) {
		if (cur->when & when) {
			//printk_current("[unittest] k:%s\n", cur->name);
			if (cur->func()) {
				printkx(PK_TEST, PK_WARN, "[unittest] k:%s FAILED\n", cur->name);
				failed++;
			}
            else
				printkx(PK_TEST, PK_DEBUG, "[unittest] k:%s passed\n", cur->name);

			total++;
		}
	}

	// reset output 
	printkx_max_level = pksave;

	// reset flags
	unittest_active_early = 0;
	unittest_active = 0;

	assert(!failed);
	printkx(PK_TEST, PK_INFO, "[unittest] Ok. passed %d kernel tests\n", total);
#endif
}

void unittest_runall_early(void)
{
	return __unittest_runall(TEST_EARLY);
}

void unittest_runall_late(void)
{
	return __unittest_runall(TEST_LATE);
}

void unittest_runall_user(void)
{
#ifndef NDEBUG
  	struct InitRD_File *te;
	int i, ret, total, nlen;
	
	unittest_active = 1;
	total = 0;
	for (te = initrd_first(); te ; te = te->next) {
		nlen = strlen(te->name);
		if (nlen < 5 || memcmp(te->name + strlen(te->name) - 5, ".test", 5))
			continue;
		
		//printk_current("[unittest] %s\n", te->name);
		ret = elf_exec(te->name, PROCESS_QUIET | PROCESS_WAIT, 2, 
			       (char *[]) { (char *) te->name, "auto", NULL });
		if (ret)
			printkx(PK_TEST, PK_WARN, "[unittest] %s (user) FAILED\n", te->name);
		else
			printkx(PK_TEST, PK_DEBUG, "[unittest] %s (user) passed\n", te->name);

		total++;
	}
	unittest_active = 0;
	printkx(PK_TEST, PK_INFO, "[unittest] OK. passed %d user tests\n", total);
#endif
}

