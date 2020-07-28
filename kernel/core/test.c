/** NexusOS: regression testing 
    see test.h for more information */

#include <nexus/printk.h>
#include <nexus/regression.h>
#include <nexus/hashtable.h>
#include <nexus/queue.h>
#include <nexus/tftp.h>
#include <nexus/ipc.h>
#include <nexus/net.h>
#include <nexus/elf.h>
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
};

/* declare test functions here that go without a header file */
int test_memcpy(void);
int test_ipc(void);

/** register a unittest by adding it to this list.
    the last element of the list MUST be empty */
#ifndef NDEBUG
static struct unittest unittests[] = {
	{ .func = run_preemption_test, 		.when = TEST_LATE },
	{ .func = run_thread_test, 		.when = TEST_LATE },
	{ .func = run_sema_pingpong_test, 	.when = TEST_LATE },
	{ .func = uqueue_unittest, 		.when = TEST_LATE },
	{ .func = hash_test, 			.when = TEST_LATE },
	{ .func = hash_var_test, 		.when = TEST_LATE },
	{ .func = test_memcpy, 			.when = 0 },
	{ .func = test_ipc, 			.when = TEST_LATE },
//	{ .func = nxnet_test, 			.when = TEST_LATE },
	{ .func = nxnet_filter_test, 		.when = TEST_LATE },
	{ .func = IPCPort_unittest, 		.when = TEST_EARLY | TEST_LATE },
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
			if (cur->func()) {
				printkx(PK_TEST, PK_WARN, "[unittest] failed #%d\n", total);
				failed++;
			}
			total++;
		}
	}

	// reset output 
	printkx_max_level = pksave;

	// reset flags
	unittest_active_early = 0;
	unittest_active = 0;

	assert(!failed);
	printkx(PK_TEST, PK_INFO, "[unittest] Ok. passed %d tests\n", total);
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
	const char *name, *file;
	int size, i, pid, total, nlen;

	total = 0;
	for (i = 0; ; i++) {
		file = cache_entry(i, &name, &size);
		if (file == (void *) -1)
			break;
		if (!file)
			continue;

		nlen = strlen(name);
		if (nlen < 5 || memcmp(name + strlen(name) - 5, ".test", 5))
			continue;

		pid = elf_exec(name, PROCESS_QUIET, 2, (char *[]) { (char *) name, "auto", NULL });
		printkx(PK_TEST, PK_INFO, "[unittest] %s (user) %d\n", name, size, pid);
		total++;
	}

	printkx(PK_TEST, PK_INFO, "[unittest] Started %d user tests\n", total);
#endif
}

