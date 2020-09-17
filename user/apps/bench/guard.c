/** NexusOS: benchmark guard calls from an external application 
 
    XXX measure overhead of cred_add for credentials of varying complexity */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/sema.h>
#include <nexus/guard.h>
#include <nexus/formula.h>
#include <nexus/profiler.h>

#include <nexus/IPC.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>

#define NUMRUNS_CTRL   101
#define NUMRUNS_INVOK  1001

// An RSA key we will use, in PEM format
const char rsakey_pem[] = 	
"-----BEGIN RSA PRIVATE KEY-----\n"	
"MIIEpAIBAAKCAQEAm2uWG3ToBvPsieNkmiISLnz4bkRNNzMan2L2qEaNpVJikyOD\n"
"uy4a+7obbd7teaX3EP2usXRV9DMe0z5cpgqZIkDpR5y2aqwC3OgmK8Z5+0kKiBIg\n"
"6O5mH2ygPwD72FAJSiRpgFuwH5vrgam8zj6lLbLOZq2vK1DeaaJSK9/HCuxDWbUg\n"
"0BfLjHBnn25n8MqHue4nJLQoyyAFc06f6CeWHmHna1BNxZc1e+j25ZXCZoe8jvnj\n"
"ZapT87jm1Ikl1syVQTMKqeZ7dD1WCaaQsamVGVJc9mxB5IfJeQcd8s9taAqAxWzA\n"
"/6JvD4rF817lWBV+cslH2sYZiz0l7d1i0QL9OQIDAQABAoIBAQCEuQWBAP68IUXY\n"
"IuXgckQQiwwkLhO6ldugTQTSgx2nFomzmVp/WEoWucF+vCcUAVTRn7G1POHCHn2u\n"
"a8z2xoorJD+SthNZWPdA6sbeDypQGvnxZXnRMPTo1PyrkQ2Alii4tguaX7Ix7Bbb\n"
"rbXccsbgFZgJOz0hwneMwd9mND1n5zJfTV1AzDeJulSlu33ANTh4EVsg2aHR9Pnf\n"
"/qi+9UNjGVFUXkXKxbewOC+s5wmnsGJpE1ByaeH2GAmtG02zI06EBjFM+qcz9Kn1\n"
"wlPr0KuCbm4RDy5ALews6TQfJDd8+khtTnYlkbYBF4zA3ovN2eXhjTzhYUxnWJFP\n"
"5SZB3jCZAoGBAM6vPLJ8pstXTT/SCype7EDRseP4zuu3+SFFjyxIzCZA/GviCkIZ\n"
"bfxdAHMAuSki3qy5wuhYXG/GzMQTN9qWRRHUJMNPfD4PhtGwKmPCOBjwceQrpAY9\n"
"+KH0YSO5aBvpUA0dk3xPRWepWIEXKnRgVegMx7bLKYC6thL+1xUAnEBXAoGBAMCB\n"
"AtNZ4mJ65QIzuJ2oLULil3UaQPwkKhEMFqHzqOUeTRmfSVjxwVc/KofXU/SZRWOy\n"
"5nxpaLHG6JGlnu7OK2r8CHaizny+TdBVliY6mESpDjYs/BIxZQroQlQGAZp5wKzo\n"
"hh7zmti/bpglOLXj3HFb62E4mtwWysmZEGTasPTvAoGASlbVKg2ToIeiDVZrFa5W\n"
"o2nI5gpTwozFWqY+PNtiMlAlelgvAF9NI/v/cV3NO3KDTPTzmcZOWRXUCKIw8Loj\n"
"1anMH0OzmE7VWw5V8NOmgbHaBQt9T5FyoC3Z0pOZUpC0bkM5DPkmKYbLgoLmjj0o\n"
"KPKP0rt4DgkZ+/MVQUSa7rkCgYEAnN/FjLTADt71hxDdDuWBVPNQ1+Y4NQHHojLG\n"
"st3csjI6RHoRDMGefFoGb8LjMP5ClNeyiopf/hgJaL+eQB+VNE8FGqDcQr3WrcNB\n"
"ZA/2DGX0JeQM20qTfAsAGnb2kYtMn9uxiMGeW6nNF4GlsFxrRZnRvF2jnV2ZjiYF\n"
"PRsWf9MCgYBjtgAAm62VUnM/glQ07eH1S4pIrDW0NixJrcLq/X1kOO8qeQdTuLGm\n"
"JAxufc06p7UT6ajnbBrTfMetbWsLaPE+ZhlzSQAGBUKA0/er3xCigX3BM09sD1Nh\n"
"cJ2lETVXeZ5Zg2nBiwX6SFbwuzZFZw7eTiGHUHQ1V+BFZ6gga+ezBA==\n"
"-----END RSA PRIVATE KEY-----\n";

static struct nxmedian_data *mediandata;
static RSA *rsakey;
static char buf[100];
static char *bench_form;
static struct nxguard_object ob;
static Sema authsema = SEMA_INIT;

/** Blueprint for benchmarking a single function call
    The name of the bench routine will be bench_<name>
   
    @param data: 	a struct mediandata for profiling
    @param name: 	a moniker for the specific test
    @param call: 	the function to call
 
    @return 0 on success, -1 on error		     */
#define nxmedian_single(runs, data, name, call, ...)		\
static int							\
bench_##name(void)						\
{								\
	int i, ret;						\
								\
	nxmedian_reset(data);					\
								\
	for (i = 0; i < runs; i++) {				\
		nxmedian_begin(data);				\
		ret = call(__VA_ARGS__);			\
		nxmedian_end(data);				\
	}							\
								\
	nxmedian_show(#name, data);				\
	return ret;						\
}

nxmedian_single(NUMRUNS_CTRL,  mediandata, cred_pid, nxguard_cred_add, "test=1", NULL);
nxmedian_single(NUMRUNS_CTRL,  mediandata, cred_shrt, nxguard_cred_addshort, "test=1");
nxmedian_single(NUMRUNS_CTRL,  mediandata, cred_key, nxguard_cred_add, "test=1", rsakey);
nxmedian_single(NUMRUNS_CTRL,  mediandata, goal_clr, nxguard_goal_set_str, SYS_Debug_Null2_CMD, &ob, NULL);
nxmedian_single(NUMRUNS_CTRL,  mediandata, goal_set, nxguard_goal_set_str, SYS_Debug_Null2_CMD, &ob, bench_form);
nxmedian_single(NUMRUNS_CTRL,  mediandata, proof_clr, nxguard_proof_set, SYS_Debug_Null2_CMD, &ob, NULL);
nxmedian_single(NUMRUNS_CTRL,  mediandata, proof_set, nxguard_proof_set, SYS_Debug_Null2_CMD, &ob, buf);
nxmedian_single(NUMRUNS_INVOK, mediandata, invoke, Debug_Null3, 10);

/** Test authority registration. 
    Similar to the nxmedian_single() tests above, 
    but this case needs a prologue and epilogue */
static int				
bench_auth_register(void)			
{		
	char filepath[255];
	char name[10];
	int i, ret, port;			
	
	nxmedian_reset(mediandata);		

	port = IPC_CreatePort(0);

	// Acquire ipc port and register with guard
	for (i = 0; i < NUMRUNS_CTRL; i++) {	

		// for security reasons, names cannot be released
		// so we must generate a new name and port for each authority
		snprintf(name, 9, "bench%d", i);

		nxmedian_begin(mediandata);	
		ret = nxguard_auth_register(default_guard_port, port, name);
		nxmedian_end(mediandata);
	}		
	
	nxmedian_show("auth", mediandata);	
	return ret >= 0 /* valid port */ ? 0 : 1;			
}

/** Benchmark cred_add, auth_add and other state changing calls */
static int
test_controlcalls(void)
{
	// add credentials
	if (bench_cred_pid())
		ReturnError(1, "cred pid");
	
	// add credentials
	if (bench_cred_shrt())
		ReturnError(1, "cred pid (short)");
	
	if (bench_cred_key())
		ReturnError(1, "cred key");

	snprintf(buf, 99, "process.%d says test=1", Thread_GetProcessID());

	// clear a goal (NB: clears an empty goal, slightly cheaper than if set)
	if (bench_goal_clr())
		ReturnError(1, "goal clear");

	// set a goal
	nxguard_object_clear(&ob);	// this call has no object. set to NULL
	bench_form = "false";
	if (bench_goal_set())
		ReturnError(1, "goal set");

	// clear a proof (NB: clears an empty proof, slightly cheaper than if set)
	// set a proof
	snprintf(buf, 99, "assume process.%d says test=1;", Thread_GetProcessID());
	if (bench_proof_clr())
		ReturnError(1, "proof clear");

	if (bench_proof_set())
		ReturnError(1, "proof set");

	if (bench_auth_register())
		ReturnError(1, "auth register");

	return 0;
}

/** Benchmark invocation for varying states of the guard */
static int
test_invocation(void)
{
	printf("invocation tests\n");
	// clear goal
	if (nxguard_goal_set_str(SYS_Debug_Null3_CMD, &ob, NULL)) {
		fprintf(stderr, "[guard bench] goal clear failed\n");
		return 1;
	}
	
	printf("invoke pass:       ");
	if (bench_invoke() != 10) {
		fprintf(stderr, "[guard bench] invoke failed #1\n");
		return 1;
	}

	// set goal and clear proof
	snprintf(buf, 99, "process.%d says 1=1" , Thread_GetProcessID());
	bench_form = buf;
	if (nxguard_goal_set_str(SYS_Debug_Null3_CMD, &ob, bench_form))
		ReturnError(1, "[guard bench] goal set failed");
	if (nxguard_proof_set(SYS_Debug_Null3_CMD, &ob, NULL))
		ReturnError(1, "[guard bench] proof clear failed");
	
	printf("invoke no proof:   ");
	if (bench_invoke() >= 0) {
		fprintf(stderr, "[guard bench] invoke failed #2\n");
		return 1;
	}

	// make evaluation fail on unsound deduction (cacheable) 
	snprintf(buf, 99, "assume a says b;"); // incorrect syntax -> fail
	if (nxguard_proof_set(SYS_Debug_Null3_CMD, &ob, buf))
		ReturnError(1, "[guard bench] set proof failed");
	printf("invoke bad proof:  ");
	if (bench_invoke() >= 0) {
		fprintf(stderr, "[guard bench] invoke failed #3a\n");
		return 1;
	}

	// make evaluation fail on missing credential (not cacheable)
	snprintf(buf, 99, "assume process.%d says 1=1;\n", getpid());
	if (nxguard_proof_set(SYS_Debug_Null3_CMD, &ob, buf))
		ReturnError(1, "[guard bench] set proof failed");
	printf("invoke fail cred:  ");
	if (bench_invoke() >= 0) {
		fprintf(stderr, "[guard bench] invoke failed #3b\n");
		return 1;
	}

	// make evaluation succeed: 
	// result is now not cached even though cachable
	// (implementation artifact of nxguard_auth_check, see XXX there)
	// NB: for authorization overhead graph, use microbench for the cached result
	nxguard_cred_add("1=1", NULL);
	printf("invoke pass !cache:");
	if (bench_invoke() != 10) {
		fprintf(stderr, "[guard bench] invoke failed (pass)\n");
		return 1;
	}

	// set goal and proof to ask (embedded) guard authority 
	bench_form = "name.guard says mcycles < 0xffffff";
	if (nxguard_goal_set_str(SYS_Debug_Null3_CMD, &ob, bench_form))
		ReturnError(1, "[guard bench] goal set failed");
	if (nxguard_proof_set(SYS_Debug_Null3_CMD, &ob, "assume name.guard says mcycles < 0xffffff"))
		ReturnError(1, "[guard bench] set proof failed");
	
	printf("invoke embed auth: ");
	if (bench_invoke() != 10) {
		fprintf(stderr, "[guard bench] invoke failed #4\n");
		return 1;
	}

	// set goal and proof to ask (ipc) authority
	bench_form = "name.bench says test=1";
	if (nxguard_goal_set_str(SYS_Debug_Null3_CMD, &ob, bench_form))
		ReturnError(1, "[guard bench] goal set failed");
	if (nxguard_proof_set(SYS_Debug_Null3_CMD, &ob, "assume name.bench says test=1"))
		ReturnError(1, "[guard bench] set proof failed");
	
	printf("invoke ipc auth:   ");
	if (bench_invoke() != 10) {
		fprintf(stderr, "[guard bench] invoke failed #5\n");
		return 1;
	}

	// XXX invoke authority over network
	return 0;
}

int
auth_answer(const char *formula, int pid)
{
	return 1;
}
	
/** Run an authority for the invoke test.
    NB: running in the same process could give a slight advantage over an 
    independent process (but I doubt it, given Nexus's thread scheduler) */
static void *
thread_auth(void *mutex)
{
	if (nxguard_auth(default_guard_port, "bench", &authsema)) {
		fprintf(stderr, "authority registration failed\n");
		exit(1);
	}

	// normally not reached 
	return NULL;
}

int
main(int argc, char **argv)
{
	pthread_t thread;

	printf("Nexus guard benchmark\n");

	//XXX fix: allow import of precreated key
	//rsakey = rsakey_private_import(rsakey_pem);
	rsakey = rsakey_create();
	if (!rsakey) {
		fprintf(stderr, "[guard bench] rsa import failed\n");
		return 1;
	}

	// run control tests
	printf("\n[guard bench] control tests\n");
	mediandata = nxmedian_alloc(NUMRUNS_CTRL);
	if (test_controlcalls())
		return 1;
	nxmedian_free(mediandata);
	
	// start an authority
	pthread_create(&thread, NULL, thread_auth, NULL);
	P(&authsema);

	// run invocation tests
	printf("\n[guard bench] invocation tests\n");
	mediandata = nxmedian_alloc(NUMRUNS_INVOK);
	if (test_invocation())
		return 1;
	nxmedian_free(mediandata);

	rsakey_destroy(rsakey);
	printf("[guard bench] done\n");
	return 0;
}

