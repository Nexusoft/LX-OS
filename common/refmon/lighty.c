
#include <nexus/guard.h>
#include <nexus/guard-impl.h>
#include <nexus/syscall-defs.h>
#include <nexus/IPC.interface.h>

#define TEST_SIMPLE	0x0		//< only restrict type of calls
#define TEST_CONTROL	0x1		//< limit #ipc contacts
#define TEST_DEEP	0x2		//< correlate ipc endpoint and URL

#define TESTTYPE	TEST_SIMPLE

//int refmon_lighty_val = AC_ALLOW_NOCACHE;
int refmon_lighty_val = AC_ALLOW_CACHE;

// Once lighttpd has initialized, tighten the allowed calls
static int initialized;

static inline int
check_ipc_send(struct nxguard_tuple tuple)
{
#if TESTTYPE == TEST_CONTROL
	// allow only IPC to network (vswitch) and a single python instance
	#define MAX_IPC 2

	static int ipc[MAX_IPC];
	int i;

	for (i = 0; i < MAX_IPC; i++) {
		if (ipc[i] == tuple.dest)
			return AC_ALLOW_CACHE;
		else if (!ipc[i]) {
			ipc[i] = tuple.dest;
			return AC_ALLOW_CACHE;
		}
	}
		
	printf("@BLOCK (ipc) %d\n", tuple.operation);
	return AC_BLOCK_NOCACHE;
#elif TESTTYPE == TEST_DEEP
	// XXX check destination to expected destination (from recv)
	return AC_ALLOW_NOCACHE;
#else
	printf("@BLOCK (ipc) %d\n", tuple.operation);
	return AC_BLOCK_NOCACHE;
#endif
}

static int 
nxrefmon_lighty_in(struct nxguard_tuple tuple)
{
// benchmarking
return refmon_lighty_val;

	switch (tuple.operation) {

	//// calls that require extra processing

	// end of initialization
	case SYS_IPC_Wait_CMD:
	case SYS_IPC_Available_CMD:
	case SYS_IPC_Poll_CMD: 
		initialized = 1;
		return refmon_lighty_val;

	// network I/O
  	case SYS_IPC_Send_CMD:
  	case SYS_IPC_SendPage_CMD:
#if TESTTYPE == TEST_SIMPLE
		return 1;
#else
		return check_ipc_send(tuple);
#endif
  	case SYS_IPC_Recv_CMD:
  	case SYS_IPC_RecvFrom_CMD:
  	case SYS_IPC_RecvPage_CMD:
		return refmon_lighty_val;

	// file I/O: correlate with network I/O
  	case SYS_FS_Lookup_CMD:
	case SYS_FS_Read_CMD:
  	case SYS_FS_ReadDir_CMD:
#if TESTTYPE == TEST_DEEP
		// XXX enable tracing of HTTP request mapping to IPC port
		// XXX restrict directory access to within /var/www
		return AC_ALLOW_NOCACHE;
#else
		return refmon_lighty_val;
#endif

	//// calls only allowed during initialization
	case SYS_Net_get_mac_CMD:
	case SYS_Net_get_ip_CMD:
	case SYS_Net_filter_ipport_CMD:
	case SYS_Net_filter_arp_CMD:
	case SYS_Net_port_get_CMD:
		if (initialized) { 
			printf("@BLOCK %d\n", tuple.operation);
			return AC_BLOCK_CACHE;
		}
		else
			return AC_ALLOW_NOCACHE;

	//// calls that are always allowed
	case SYS_Thread_Fork_CMD:
	case SYS_Thread_SetMyTCB_CMD:
	case SYS_Thread_Yield_CMD:
	case SYS_Thread_Exit_CMD:
	case SYS_Thread_ExitThread_CMD:
	case SYS_Thread_CondVar_Wait_CMD:
	case SYS_Thread_CondVar_Signal_CMD:
	case SYS_Thread_CondVar_Broadcast_CMD:
	case SYS_Thread_CondVar_Free_CMD:
	case SYS_Thread_GetID_CMD:
	case SYS_Thread_GetProcessID_CMD:
	case SYS_Mem_Brk_CMD:
	case SYS_Mem_GetPages_CMD:
	case SYS_Mem_FreePages_CMD:
	case SYS_Net_GetMyIP_CMD:
	case SYS_IPC_Wake_CMD:
	case SYS_IPC_CreatePort_CMD:
	case SYS_IPC_DestroyPort_CMD:
	case SYS_Time_gettimeofday_CMD:
	case SYS_Console_PrintString_CMD:
	case SYS_Console_GetData_CMD:
  	case SYS_Console_HasLine_CMD:
  	case SYS_FS_Sync_CMD:
  	case SYS_FS_Size_CMD:
  	case SYS_FS_Pin_CMD:
  	case SYS_FS_Unpin_CMD:
		return refmon_lighty_val;

	// all other calls are always blocked
	default:
		printf("BLOCKED opcode=%d\n", tuple.operation);
		return AC_BLOCK_CACHE;
	}

	return refmon_lighty_val;
}

static int 
nxrefmon_lighty_out(struct nxguard_tuple tuple)
{
#if TESTTYPE == TEST_DEEP
	switch (operation) {
	case IPC_RecvPage:
	{
		char msg[sizeof(int) + sizeof(struct IPC_RecvPage_Args)];
		struct IPC_RecvPage_Args *args;

		args = msg + sizeof(int);
		if (IPC_TransferParam(msg, 0, sizeof(msg))) {
			fprintf(stderr, "[refmon] Error at recvpage\n");
			return AC_BLOCK_NOCACHE;
		}

		// only interested in network traffic
		if (args->port_num != XXX-networkport)
			return AC_ALLOW_NOCACHE;

		
		// only look for HTTP request that start at packet boundary
		// (the common case, but not dictated by standard)
		if (strcmp(msg.data + 54, "GET") &&
		    strcmp(msg.data + 54, "POST")) 
			// allow other packets, e.g., SSL or POSTDATA
			return AC_ALLOW_NOCACHE;
	
		fprintf(stderr, "HTTP Request %c%c%c%c%c%c..\n",
			msg.data[54], msg.data[55], msg.data[56]
			msg.data[57], msg.data[58], msg.data[59]);

		// XXX fix next allowed IPC_Send destination based on URL
		return AC_ALLOW_NOCACHE
	}
	break;
	}
#endif
	return 0;
}

