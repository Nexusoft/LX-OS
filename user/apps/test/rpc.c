/** NexusOS: stresstest RPC 
 
    Implement an arbitrary RPC interface and test request handling,
    especially with concurrent clients and servers */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <nexus/test.h>
#include <nexus/sema.h>
#include <nexus/machine-structs.h>

#include <nexus/Thread.interface.h>
#include <nexus/LockBox.interface.h>

static int stop;
static Sema stopped = SEMA_INIT;
static int index_max;
static int total;

//// trivial test RPC server
// 
// we have to implement all calls, but only exercise the first

int 
nxkey_insert(int index, char* key, int klen) 
{ 
	return index; 
}

int nxkey_shutdown(void) { return 0; }
int nxkey_save_app(const char *filepath, const char *data, int dlen) { return 0; }
char * nxkey_restore_app(const char *filepath) { return NULL; }
int nxkey_create(void) { return 0; }
int nxkey_delete(int key_id) { return 0; }
char* nxkey_encrypt(int key_id, const char *data, char ivec_start[16]) { return NULL; }
char * nxkey_decrypt(int key_id, const char *ciphertext, char ivec[16]) { return NULL; }
int nxkey_sign(const char *data, int dlen, const char *digest) { return 0; }
int nxkey_verify(int index, const char *digest) { return 0; }

static void *
server_thread(void *unused)
{
	// process child requests
	printf("[svc] up\n");
	while (stop != 2)
		LockBox_processNextCommand();
	printf("[svc] done\n");

	V_nexus(&stopped);
	return NULL;
}

static void *
client_thread(void *unused)
{
	unsigned long long count = 0;
	int index, ret;
       
	while (stop == 0) {
		index = atomic_get_and_addto(&index_max, 1);
		ret = LockBox_Insert_ext(primary_lockbox_port, index, NULL, 0);

		if (ret != index) {
			fprintf(stderr, "ERROR: at %llu: expected=%d received=%d\n", count, index, ret);
			return NULL;
		}

		count++;
	}

	atomic_addto(&total, count);
	V_nexus(&stopped);
	return NULL;
}

/** Start a number of instances of either the server or the client */
static int
start_type(int count, int do_client)
{
	pthread_t t;
	int i;

	for (i = 0; i < count; i++)
		pthread_create(&t, NULL, do_client ? client_thread : server_thread, NULL);

	return 0;
}

static int
do_test(int count_client, int count_server)
{
	int i;

	printf("[test] %d clients, %d servers\n", count_client, count_server);

	total = 0;
	stop = 0;
	start_type(count_server, 0);
	start_type(count_client, 1);
	
	sleep(20);

	printf("[test] done ..\n");
	
	// stop and wait on all clients
	stop = 1;
	for (i = 0; i < count_client; i++) {
		P(&stopped);
		fprintf(stderr, "%d of %d clients. total %d\n", 
			i + 1, count_client, atomic_get(&total));
	}

	// stop and wait on all servers 
	stop = 2;
	for (i = 0; i < count_server; i++) {
		LockBox_Insert_ext(primary_lockbox_port, 1, NULL, 0);
		P(&stopped);
		fprintf(stderr, "%d of %d servers. total %d\n", 
			i + 1, count_server, atomic_get(&total));
	}
	
	printf("[test] done\n\n\n");
	return 0;
}

int
main(int argc, char **argv)
{
	test_skip_auto();

	// initialize server
	LockBoxSvc_Init(primary_lockbox_port);

	// test single pair
	if (do_test(1, 1))
		return 1;
	
	// test server parallelism
	if (do_test(1, 20))
		return 1;
	
	// test client parallelism
	if (do_test(20, 1))
		return 1;
	
	// all out
	if (do_test(25, 30))
		return 1;

	if (!nxtest_isauto(argc, argv))
		printf("[test] OK\n");

	LockBoxSvc_Exit();
	return 0;
}

