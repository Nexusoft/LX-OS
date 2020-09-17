/** NexusOS: test filesystem encryption and signing using lockboxes */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/sha.h>
#include <openssl/aes.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/nexuscalls.h>

#include <nexus/LockBox.interface.h>

#define LOCKBOXFS_PORT	(5000)

/** stop listening for LockBox requests if set */
static int stop = 0;
static char table_index0[20];


////////  LockBox interface implementation  ////////
// trivial test implementation

int
nxkey_shutdown(void)
{
	stop = 1;
	fprintf(stderr, "shutdown called!\n");
	return 0;
}

/** NB: this test expects data to be 10B long */
int 
nxkey_save_app(const char *filepath, const char *data, int dlen)
{
	if (dlen != 10)
		return -1;

	return 0;
}

char *
nxkey_restore_app(const char *filepath)
{
	return calloc(1, 10);
}

int 
nxkey_create(void)
{
	return 0; // key created at index 0
}

int 
nxkey_insert(int index, char* key, int klen)
{
	assert(index == 0 && klen == 20);
	memcpy(table_index0, key, 20);

	return 0;
}

int 
nxkey_delete(int key_id)
{
	return 0; // key deleted from index 0
}

/** Ceasar cipher: nothing but top technology in Nexus. */
char* 
nxkey_encrypt(int key_id, const char *data, 
	      char ivec_start[AES_BLOCK_SIZE])
{
        const unsigned char *plain;
	unsigned char *enc;
	int i;

	plain = data;
	enc = malloc(512);
	for (i = 0; i < 512; i++)
		enc[i] = plain[i] + 128;

	printf("NXDEBUG: encrypt\n");
	return enc;
}

char * 
nxkey_decrypt(int key_id, const char *ciphertext, 
	      char ivec[AES_BLOCK_SIZE])
{
	printf("NXDEBUG: decrypt\n");
	return nxkey_encrypt(key_id, ciphertext, ivec);
}

int 
nxkey_sign(const char *data, int dlen, char *digest)
{
	SHA1(data, dlen, (unsigned char *) digest);
	return 0;
}

int 
nxkey_verify(int index, const char *digest)
{
	assert(index == 0);
	return memcmp(table_index0, digest, 20);
}


////////  test application  ////////

#define FILEPATH "/tmp/crypto.txt"

static int
child_shutdown(const char *errormsg, int error)
{
	// shutdown
	if (LockBox_Shutdown())
		ReturnError(1, "shutdown failed\n");

	printf("child returning %d:%s\n", error, errormsg);
	return error;
}

#define MSGLEN 640	/* 640: multiblock with partial fragment */
static char message[MSGLEN];

/** Test encryption 
 
    XXX test overwriting a partial segment */
static int
child_test_encrypt(void)
{
	unsigned char buf[1024];
	unsigned long flags;
	int fd, i, len;

	len = sizeof(message) - 1;
	memset(message, 'c', MSGLEN);

	// open
	fd = open(FILEPATH, O_RDWR | O_CREAT, 0644);
	if (fd < 0)
		return child_shutdown("open", 1);

	// enable encryption
	flags = (LOCKBOXFS_PORT << 16) | 1; // ipcport=LOCKBOXFS, key_index=1
	if (fcntl(fd, F_SETENC, flags))
		return child_shutdown("fcntl #1", 1);
	
	// write
	if (write(fd, message, len) != len)
		return child_shutdown("write", 1);
	if (fsync(fd))
		return child_shutdown("sync", 1);

	// read back
	if (lseek(fd, 0, SEEK_SET))
		return child_shutdown("lseek", 1);
	if (read(fd, buf, 1024) != len)
		return child_shutdown("read", 1);
	if (memcmp(buf, message, len))
		return child_shutdown("read data", 1);
		
	// disable encryption
	flags = 0;
	if (fcntl(fd, F_SETENC, flags))
		return child_shutdown("fcntl #2", 1);
	
	// read back: should be ciphertext
	if (lseek(fd, 0, SEEK_SET))
		return child_shutdown("lseek", 1);
	if (read(fd, buf, 1024) != len)
		return child_shutdown("read", 1);
	for (i = 0; i < len; i++) {
		if (buf[i] != message[i] + 128) {
			printf("corrupt data %d: %hhu != %hhu + 128\n", i, buf[i], message[i]);
			return child_shutdown("read data #2", 1);
		}
	}

	// close
	if (close(fd))
		return child_shutdown("close", 1);

	if (unlink(FILEPATH))
		return child_shutdown("unlink", 1);

	return 0;
}

static int
child_test_sign(void)
{
	unsigned long flags;
	int fd, len;

	len = sizeof(message) - 1;

	// open with signature generation
	fd = open(FILEPATH, O_RDWR | O_CREAT, 0644);
	if (fd < 0)
		return child_shutdown("open #2", 1);

	// write
	if (write(fd, message, len) != len)
		return child_shutdown("write #2", 1);

	// set to sign on close
	flags = (LOCKBOXFS_PORT << 16); // ipcport=LOCKBOXFS, key_index=0
	if (fcntl(fd, F_SIGN, flags))
		return child_shutdown("fcntl #3", 1);

	// close
	if (close(fd))
		return child_shutdown("close #2", 1);

	// reopen with signature verification
	fd = open(FILEPATH, O_RDWR, 0644);
	if (fd < 0)
		return child_shutdown("open #3", 1);

	if (fcntl(fd, F_SIGNED, flags))
		return child_shutdown("fcntl #4: verify", 1);

	// mess with contents. 
	// note that without O_SIGN, signature is NOT regenerated
	if (write(fd, "xxx", 3) != 3)
		return child_shutdown("write #3", 1);

	if (!fcntl(fd, F_SIGNED, flags))
		return child_shutdown("fcntl #5: verify #2", 1);

	if (close(fd))
		return child_shutdown("close #3", 1);

	if (unlink(FILEPATH))
		return child_shutdown("unlink #2", 1);

	return 0;
}

static int
do_child(void)
{
	printf("Running encryption test\n");
	if (child_test_encrypt())
		return 1;

	printf("Running signature test\n");
	if (child_test_sign())
		return 1;

	return child_shutdown("ok", 0);
}

////////  server  ////////

/** run as actual 'production' server */
static int
do_continuous(void)
{
	LockBoxSvc_Init(primary_lockbox_port);
	printf("[lockbox] up at port %d\n", LockBox_server_port_num);
	
	while (!stop)
		LockBox_processNextCommand();

	LockBoxSvc_Exit();
	return 0;
}


////////  main loop (shared)  ////////

int
main(int argc, char **argv)
{
	char *childv[3];
	int pid, ret, silent;
	
	// skip auto test at boot until all tests pass
	if (argc == 2 && !strcmp(argv[1], "auto"))
		return 0;
	else
		silent = 0; //1;

	// run as continuous server
	if (argc == 2 && !strcmp(argv[1], "--server"))
		return do_continuous();

	if (argc == 2 && !strcmp(argv[1], "--child"))
		return do_child();

	// initialize server
	LockBoxSvc_Init(LOCKBOXFS_PORT);
	if (!silent)
		printf("[lockbox] up at port %d\n", LockBox_server_port_num);

	// start child
	childv[0] = argv[0];
	childv[1] = "--child";
	childv[2] = NULL;
	pid = nxcall_exec_ex(argv[0], childv, NULL, 0);

	while (!stop)
		LockBox_processNextCommand();

	LockBoxSvc_Exit();

	// wait for child
	waitpid(pid, &ret, 0);
	if (ret && ret != -1)
		ReturnError(1, "child exited with error\n");

	if (!silent)
		printf("[lockbox] OK\n");

	return 0;
}

