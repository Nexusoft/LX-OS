/** NexusOS: selftest for the guard: test the auth channel */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/defs.h>
#include <nexus/ipc.h>
#include <nexus/guard.h>
#include <nexus/test.h>

#include <nexus/IPC.interface.h>

/** authenticated channel */
static int lport, rport;

static RSA *rsakey;

/** Open an authenticated channel to the guard */
static int
chan_open(void)
{
	struct guard_auth_challenge chal;
	struct guard_auth_response msg;
	char *pubkey;
	int ret;

	lport = guard_authtest_port;
	lport = IPC_CreatePort(&lport);
	if (lport != guard_authtest_port)
		ReturnError(-1, "chan open\n");

	// send lportber
	if (IPC_Send(guard_authority_port, &lport, sizeof(lport)))
		ReturnError(-1, "chan open send\n");

	// receive challenge
	if (IPC_Recv(lport, &chal, sizeof(chal)) != sizeof(chal))
		ReturnError(-1, "chan open recv\n");

	
	// sign challenge
	msg.slen = nxguard_sdigest_create(chal.challenge, CHALLENGE_LEN,
			                   msg.sdigest, rsakey);
	if (msg.slen <= 0)
		ReturnError(-1, "chan open sign error\n");

#ifndef NDEBUG
	// verify sdigest
	if (nxguard_sdigest_verify(chal.challenge, CHALLENGE_LEN, 
				   rsakey, msg.sdigest, msg.slen))
		ReturnError(-1, "chan open sig error\n");
#endif

	// copy public key
	pubkey = rsakey_public_export(rsakey);
	memcpy(msg.pubkey, pubkey, PUBKEY_LEN);
	free(pubkey);

	// send response (to private port)
	if (IPC_Send(chal.port, &msg, sizeof(msg)))
		ReturnError(-1, "chan open response error");

	// wait for final reply
	if (IPC_Recv(lport, &ret, sizeof(ret)) != sizeof(ret) || ret)
		ReturnError(-1, "chan open ack error");

	rport = chal.port;

	return 0;
}

/** Handle a single request */
static int
chan_answer(void)
{
	char req[AUTHREQ_LEN];
	int rlen, arg, ret;

	rlen = IPC_Recv(lport, &req, AUTHREQ_LEN);
	if (rlen <= 0)
		ReturnError(-1, "chan answer recv error\n");

	// this example authority uses sscanf to parse the expression
	// understand that this is WEAK with regard to whitespace, etc.
	if (sscanf(req, "authport = %d", &arg) != 1)
		ReturnError(-1, "chan answer parse error\n");

	ret = (arg == rport) ? 1 : 0;
	IPC_Send(rport, &ret, sizeof(ret));

	return 0;
}

int
main(int argc, char **argv)
{
	test_skip_auto();

	rsakey = rsakey_create();
	if (chan_open())
		return 1;

	if (chan_answer())
		return 1;

	RSA_free(rsakey);

	printf("[authtest] OK.\n");
	return 0;
}

