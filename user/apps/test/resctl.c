/** NexusOS: resource control selftest */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <nexus/test.h>
#include <nexus/syscall-defs.h>
#include <nexus/Resource.interface.h>

static int account;
static int do_output;

static int
test_attest(int account)
{
	char filepath[] = "/tmp/cpucert.pem";
	char buf[80];
	int fd, len;

	if (Resource_Account_Attest_ext(resctl_cpu_port, account, 
					(struct VarLen) { .data = filepath, 
							  .len  = sizeof(filepath) } ))
		return 1;	

	if (do_output) {
		fd = open(filepath, O_RDONLY);
		if (fd < 0)
			ReturnError(1, "open");

		do {
			len = read(fd, buf, 80);
			if (len <= 0)
				break;
			write(1, buf, len);
		} while (1);
		close(fd);
		write(1, "\n", 1);
	}

	if (unlink(filepath))
		ReturnError(1, "unlink");

	return 0;
}

int
main(int argc, char **argv)
{
	// cannot run before resource controller is started
	test_skip_auto();

	if (!nxtest_isauto(argc, argv))
		do_output = 1;

    if (Resource_Info_SizeTotal_ext(resctl_cpu_port) != 10)
        ReturnError(1, "InfoTotal");

	account = Resource_Account_New_ext(resctl_cpu_port, 0);
	if (account < 0)
		ReturnError(1, "New");

	if (!test_attest(666))
		ReturnError(1, "Attest to nonexistent account");

	if (test_attest(account))
		ReturnError(1, "Attest");

	if (Resource_Account_AddResource_ext(resctl_cpu_port, account, 2))
		ReturnError(1, "AddResource");

    if (Resource_Info_SizeAccount_ext(resctl_cpu_port, account) != 2)
        ReturnError(1, "InfoAccount");

#if 0
	if (Resource_Account_AddProcess_ext(resctl_cpu_port, account, getpid()))
		ReturnError(1, "AddProcess");
fprintf(stderr, "%s.%d\n", __FUNCTION__, __LINE__);

	if (Resource_Account_ByProcess_ext(resctl_cpu_port, getpid()) != account)
		ReturnError(1, "ByProcess");
fprintf(stderr, "%s.%d\n", __FUNCTION__, __LINE__);
#endif

	if (test_attest(account))
		ReturnError(1, "Attest #2");

	return 0;
}

