/** NexusOS: TRIVIAL python code analyzer 
 
    This tool will analyze a python sourcefile and insert a credential
    iff it deems the code safe. Actual safeguarding of Python is a known
    hard problem. This is not a true solution, just a proof-of-concept.

    On Linux, performs identical check, but does not insert credential.

    XXX move to shedskin (code.google.com/p/shedskin)
 
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef __NEXUS__
#include <nexus/fs.h>
#include <nexus/guard.h>
#include <nexus/nexuscalls.h>
#include <nexus/Thread.interface.h>
#endif

#define PYFILE_MAX	(1 << 16)

static inline int
my_isalnum(char c)
{
	if ((c >= 'a' && c <= 'z') ||
	    (c >= 'A' && c <= 'Z') ||
	    (c >= '0' && c <= '9'))
		return 1;
	else
		return 0;
}

static char *
file_import(int fd, int *len)
{
	struct stat statinfo;
	char *contents;
	int off, cur;

	if (fstat(fd, &statinfo)) {
		fprintf(stderr, "fstat()\n");
		return NULL;
	}

	if (statinfo.st_size > PYFILE_MAX) {
		fprintf(stderr, "file too large\n");
		return NULL;
	}
	
	// copy contents (XXX could've used mmap)
	contents = malloc(statinfo.st_size);
	off = 0;
	while (off < statinfo.st_size) {
		cur = read(fd, contents + off, statinfo.st_size - off);
		if (cur < 0 || (cur == 0 && off != statinfo.st_size)) {
			fprintf(stderr, "read()\n");
			return NULL;
		}
		off += cur;
	}
	
	*len = statinfo.st_size;
	return contents;
}

/** Check for safety (however that may be defined)
    @return 0 if deemed safe, 1 if not */
static int 
data_parse(const char *data, int len)
{
	const char * whitelist[] = { " time", NULL };
	const char **wcur;
	int unused;

	// trivial test: only allow import from a whitelist of modules
	while ((data = strstr(data, "import"))) {
		data = strchr(data, ' ');
		if (!data)
			break;

		// next token after import: find match in whitelist
		wcur = whitelist;
		while (*wcur) {
			if (!memcmp(data, *wcur, sizeof(*wcur) - 1))
				break;
			wcur++;
		}

		// not in list: error
		if (!*wcur) {
			fprintf(stderr, "failed at [");
			data++;
			while (my_isalnum(*data))
				unused = write(2, data++, 1);
			unused = write(2, "]\n", 2);
			return 1;
		}
	}

	return 0;
}

static int
cred_insert(int fd)
{
	const char header[] = "sha1.<<";
	const char footer[] = ">> says ipc.%u.%llu = \"safe\"";
	char buf[512], sha1[20];	
	int i, off;

#ifdef __NEXUS__
	FSID id;

	// get file id: resource control works on ids, not names
	id = nxcall_fsid_get(fd);
	if (!FSID_isFile(id)) {
		fprintf(stderr, "fsid error\n");
		return 1;
	}

	// kernel needs to say that we speak for hash
	Thread_Sha1_AddCred();	
	
	// get process hash
	Thread_Sha1_Get(getpid(), sha1);
#else
	// fake process hash
	memset(sha1, 'a', sizeof(sha1) - 1);
#endif
	// create cred "sha.<<process.SHA1>> says file = 'safe'"
	off = sizeof(header) - 1;
	memcpy(buf, header, off);
	for (i = 0; i < 20; i++)
		sprintf(buf + off + (i << 2), "%02x%02x", (sha1[i] >> 4) & 0xff, sha1[i] & 0xff);
	off += 80;

#ifdef __NEXUS__
	sprintf(buf + off, footer, id.port, fsid_upper(&id));
	nxguard_cred_add_raw(buf);
	printf("[pysafe] safe. inserted credential\n");
#else
	sprintf(buf + off, footer, 0, 0ULL);
	printf("[pysafe] safe. not inserting credential on linux\n");
#endif
	return 0;
}

int
main(int argc, char **argv)
{	
	char *data;
	int len, fd;

	// validate input
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <filepath>\n", argv[0]);
		return 1;
	}
	
	// open file
	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "file not found\n");
		return 1;
	}

	
	// read file
	data = file_import(fd, &len);
	if (!data)
		return 1;

	// pattern match
	if (!data_parse(data, len)) {
		if (cred_insert(fd))
			return 1;
	}
	else {
		printf("[pysafe] not safe.\n");
	}

	// cleanup
	if (close(fd)) {
		fprintf(stderr, "close()");
		return 1;
	}
	free(data);
	
	return 0;
}

