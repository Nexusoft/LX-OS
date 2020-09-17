/** NexusOS : test propery handling of posix time functions */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

#include <nexus/test.h>

int
main(int argc, char **argv)
{
	struct tm *tm;
	struct timeval tv1, tv2;
	char *strtime;
	time_t time1, time2, time3;
	uint64_t tdiff;

	//// set timezone
	setenv("TZ", "America/New_York", 1);

	//// part 1: gettimeofday

	if (gettimeofday(&tv1, NULL))
		ReturnError(1, "gettimeofday #1");

	usleep(1000);

	if (gettimeofday(&tv2, NULL))
		ReturnError(1, "gettimeofday #2");

	tdiff = (tv2.tv_sec + tv2.tv_usec * 1000000)
		- (tv1.tv_sec + tv1.tv_usec * 1000000);
	if (tdiff < 1000)
		ReturnError(1, "sleep");


	//// part 2: time

	time1 = time(NULL);
	if (time1 == (time_t) -1)
		ReturnError(1, "time #1");

	time2 = time(&time3);
	if (time2 < time1 || time2 != time3)
		ReturnError(1, "time #2");


	//// part 3: localtime
	tm = localtime(&time1);
	if (!tm)
		ReturnError(1, "localtime #1");
	if (tm->tm_year < 70)	// years since 1900, unixtime at least 1970
		ReturnError(1, "localtime #2");

	strtime = asctime(tm);
	if (!strtime)
		ReturnError(1, "asctime");

	if (argc == 1) // not 'auto' call at boot
		printf("[%s] OK. Current time is %s\n", argv[0], strtime);
	return 0;
}

