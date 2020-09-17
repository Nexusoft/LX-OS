/** NexusOS: Lockbox.svc selftest */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include <openssl/aes.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/nexuscalls.h>

#include <nexus/LockBox.interface.h>

/** stop listening for LockBox requests if set */
static int stop = 0;


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
	return 0; // key inserted at index 0
}

int 
nxkey_delete(int key_id)
{
	return 0; // key deleted from index 0
}

/** fake enc/dec/sign/verify: accept all data with an a as first character */
static int 
fake_edsv(int key, const char *data)
{
	if (key != 0)
		return -1;

	if (data[0] != 'a')
		return -1;

	return 0;
}

char* 
nxkey_encrypt(int key_id, const char *data, 
	      char ivec_start[AES_BLOCK_SIZE])
{
	char *encrypted;

	if (fake_edsv(key_id, data))
		ReturnError(NULL, "Enc");

	if (ivec_start[0] != 'c')
		ReturnError(NULL, "Enc: iv");

	encrypted = malloc(512);
	memset(encrypted, 'b', 512);
	return encrypted;
}

char * 
nxkey_decrypt(int key_id, const char *ciphertext, 
	      char ivec[AES_BLOCK_SIZE])
{
	if (fake_edsv(key_id, ciphertext))
		return NULL;

	return calloc(1, 512);
}

int 
nxkey_sign(const char *data, int dlen, const char *digest)
{
	// XXX not tested
	return 0;
}

int 
nxkey_verify(int index, const char *digest)
{
	// XXX not tested
	return 0;
}


////////  Processes  ////////

/** The child instance connects to the parent and tests interfaces */

static int
do_child(void)
{
	char pblock[512], cblock[512];
	char ivec[AES_BLOCK_SIZE];

	// 'encrypt'
	memset(pblock, 'a', 512);
	memset(ivec, 'c', AES_BLOCK_SIZE);
	if (LockBox_Encrypt(0, (struct VarLen) {.data = pblock, .len = 512},
				(struct VarLen) {.data = cblock, .len = 512},
				(struct VarLen) {.data = ivec, .len = AES_BLOCK_SIZE},
				512, 0))
		ReturnError(1, "encrypt failed\n");
	if (cblock[0] != 'b')
		ReturnError(1, "encrypt data corruption\n");

	// shutdown
	if (LockBox_Shutdown())
		ReturnError(1, "shutdown failed");

	return 0;
}

int
main(int argc, char **argv)
{
	char *childv[3];
	int pid, ret, silent;
	
	// skip auto test at boot: waitpid hangs
	test_skip_auto();
	
	if (argc == 2 && !strcmp(argv[1], "auto"))
		silent = 1;

	if (argc == 2 && !strcmp(argv[1], "--child"))
		return do_child();

	// initialize server
	LockBoxSvc_Init(primary_lockbox_port);
	if (!silent)
		printf("[lockbox] up at port %d\n", LockBox_server_port_num);

	// start child
	childv[0] = argv[0];
	childv[1] = "--child";
	childv[2] = NULL;
	pid = nxcall_exec_ex(argv[0], childv, NULL, 0);

	// process child requests
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

