/** NexusOS: webserver benchmark setup:
             creates files /bin/bench.$SIZE.html and
 	     optionally installs access control goals */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/rand.h>

#include <nexus/test.h>

#ifdef __NEXUS__
#include <nexus/fs.h>
#include <nexus/guard.h>
#include <nexus/guard-impl.h>
#include <nexus/nexuscalls.h>

#include <nexus/FS.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Auth.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/LockBox.interface.h>
#endif

#define FILESZ_MIN	100
#define FILESZ_MAX	1000000
#define FILESZ_MULTIPLY	10

#define FILE_BLUEPRINT	"/bin/bench.%d.html"
#define LOCKBOX_PORT	(primary_lockbox_port)
#define LOCKBOX_INDEX	(1)

static int  do_hashing, do_encryption;
static long flags = (LOCKBOX_PORT << 16) | LOCKBOX_INDEX;

/** Create a single file */
static int
file_create(const char *filepath, const char *contents, int clen)
{
	int fd, index;

	fd = open(filepath, O_CREAT | O_WRONLY, 0644);
	if (fd < 0) 
		ReturnError(1, "open()\n");
	
#ifdef __NEXUS__
	if (do_encryption) {
		if (fcntl(fd, F_SETENC, flags))
			ReturnError(1, "error at set encryption");
	}
#endif

	if (write(fd, contents, clen) != clen)
		ReturnError(1, "write()\n");

#ifdef __NEXUS__
	if (do_hashing) {
		// WARNING: index MUST correspond with indices in httpd.app/file.py
		switch (clen) {
			case 100:	index = 2; break;
			case 1000:	index = 3; break;
			case 10000:	index = 4; break;
			case 100000:	index = 5; break;
			case 1000000:	index = 6; break;
			default:	index = 1;
		}
		printf("    set signature %s at index %d\n", filepath, index);
		if (fcntl(fd, F_SIGN, ((LOCKBOX_PORT << 16) | index)))
			ReturnError(1, "error at set hashing");
	}
#endif
	if (close(fd))
		ReturnError(1, "close()\n");

	return 0;
}

/** Create benchmarking files: webpages of increasing size
    format (in pseudogrep): "[::header]:: a+ [::footer::]" */
static int
files_add(void)
{
	const char header[] = "<html><body><p>";
	const char footer[] = "</p></body></html>";

	char *buffer, filename[20];
	int i, pad, off;

	buffer = malloc(FILESZ_MAX);
	for (i = FILESZ_MIN; i <= FILESZ_MAX; i *= FILESZ_MULTIPLY) {
		pad = i - sizeof(header) - sizeof(footer) + 1;

		// fill file
		memcpy(buffer, header, sizeof(header) - 1 /* skip \0 */);
		off = sizeof(header) - 1;
		memset(buffer + off, 'a', pad);
		off += pad;
		memcpy(buffer + off, footer, sizeof(footer));
		off += sizeof(footer);

		// create inode
		sprintf(filename, FILE_BLUEPRINT, i);
		if (file_create(filename, buffer, off))
			break;
	}
	free(buffer);
	return 0;
}

/** Create standard files for Lighttpd: config and home */
static int
files_add_static(void)
{
	const char index[] = "<html><body><p>test</p></body></html>";
	if (file_create("/tmp/index.html", index, sizeof(index)))
		return 1;
	return 0;
}


#ifdef __NEXUS__
static Sema authsema = SEMA_INIT;

/** Authority callback */
int
auth_answer(const char *req, int pid)
{
	{
		static int count;
		if (!((++count) % 1000))
			fprintf(stderr, "[count] %d\n", count);
	}
	// trivial authority: always answer true
	return AC_ALLOW_NOCACHE;
}

/** Authority thread */
static void *
auth_thread(void *unused)
{
	// initialize
	Auth_serverInit();
	if (nxguard_auth_register(default_guard_port, Auth_port_handle, "bench"))
		ReturnError((void *) 1, "[auth] registration failed");
	V_nexus(&authsema);

	// run
	while (1)
		Auth_processNextCommand();

	return NULL;
}

/** Authority initialization */
static void
auth_start(void)
{
	pthread_t t;
	pthread_create(&t, NULL, auth_thread, NULL);
	P(&authsema);
}

static int
files_set_accesscontrol(int option)
{
	struct nxguard_object ob;
	char buf[512], goal[512];
	pid_t pid;
	int i, ret;

	if (option < 1 || option > 2) {
		fprintf(stderr, "illegal access control option\n");
		return 1;
	}

//#define EMBEDDED_AUTH
#ifndef EMBEDDED_AUTH
	if (option == 2)
		auth_start();
#endif

	for (i = FILESZ_MIN; i <= FILESZ_MAX; i *= FILESZ_MULTIPLY) { 
		snprintf(buf, 511, FILE_BLUEPRINT, i);

		// resolve filepath
		ob.upper = ob.lower = 0;
		ob.fsid = nxcall_fsid_byname(buf);
		if (!FSID_isValid(ob.fsid)) 
			ReturnError(1, "unknown file\n");

		if (option == 1) {
			snprintf(goal, 511, "ipc.%u.%llu.1 says a=b", ob.fsid.port, fsid_upper(&ob.fsid));

			// set a goal that is cachabe: has a label
			nxguard_cred_add_raw(goal);
			nxguard_goal_set_str(SYS_FS_Read_CMD, &ob, goal);
		}
		else {
			// set an uncachable goal: call an authority
#ifdef EMBEDDED_AUTH
			nxguard_goal_set_str(SYS_FS_Read_CMD, &ob, "name.guard says me = ok");
#else
			nxguard_goal_set_str(SYS_FS_Read_CMD, &ob, "name.bench says me = ok");
#endif
		}
	} 

	if (option == 1)
		printf("    set access control policy OWNERSHIP\n");
	else
		printf("    set access control policy ASKGUARD\n");
	
	return 0;
}
#endif

static int
do_accesscontrol(int option)
{

		// select 1: static checks or
		//        2: dynamic (authority-based) checks
		if (files_set_accesscontrol(option))
			return 1;

		printf("OK. File access control updated\n");
		if (option == 2) {
			printf("Authority staying active\n");
			while (1) 
				sleep(3600);
		}

		return 0;
}

static int
do_usage(const char *filepath)
{
	fprintf(stderr, "Usage: %s [1|2|3|4]\n"
			"where      1 installs static ac\n"
			"           2 installs authority-based ac\n"
			"           3 enables hash verification\n"
			"           4 enables encyption\n\n"
			"NB: when run with (2): keep active in background (as authority)",
			filepath);
	return 1;
}

int
main(int argc, char **argv)
{
	char aeskey[16];
	int option = 0, ret = 0;
	
	if (argc > 2)
		do_usage(argv[0]);

#ifdef __NEXUS__
	if (argc == 2) {
		option = strtol(argv[1], NULL, 10);
		if (option == 3) {
			fprintf(stderr, "    enabled HASHING\n");
			do_hashing = 1;
		}
		else if (option == 4) {
			fprintf(stderr, "    enabled ENCRYPTION\n");
			do_encryption = 1;

            // See BUGS: this is a know issue with OpenSSL on nexus
            fprintf(stderr, "WARNING: unsafe key: PRNG disabled due to bug\n");
//    		RAND_seed(files_add, 100); // very 'random'
//			RAND_bytes(aeskey, 16);
            memset(aeskey, 1, 16);
			LockBox_Insert_ext(LOCKBOX_PORT, LOCKBOX_INDEX, 
					   VARLEN(aeskey, 16), 16);
		}
	}
#endif

	// default: create files
	if (files_add_static())
		return 1;

	if (files_add())
		return 1;

	printf("OK. Files created\n");

#ifdef __NEXUS__
	if (argc == 2) {
	
		switch (option) {
			case 1 : 
			case 2 : ret = do_accesscontrol(option); break;
			case 3 : 
			case 4 : break;
			default: return do_usage(argv[0]);
		}
	}
#endif

	return ret;
}

