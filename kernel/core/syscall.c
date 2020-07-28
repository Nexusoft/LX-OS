/** Nexus OS: kernelside system call handlers 

    For interpositioning, nearly all system calls (functions from .sc files)
    are marshalled and sent as messages through the IPC system calls */

#include <asm/msr.h>
#include <asm/processor.h>

#include <nexus/defs.h>
#include <nexus/machineprimitives.h>
#include <nexus/kshmem.h>
#include <nexus/clock.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/thread.h>
#include <nexus/device.h>
#include <nexus/queue.h>
#include <nexus/log.h>
#include <nexus/service.h>
#include <nexus/net.h>
#include <nexus/ipd.h>
#include <nexus/ipc.h>
#include <nexus/thread-private.h>
#include <nexus/thread-struct.h>
#include <nexus/syscall-defs.h>
#include <nexus/syscall-private.h>
#include <nexus/syscall-asm.h>
#include <nexus/ipc_private.h>

#include <nexus/IPC.interface.h>
#include <nexus/pci.interface.h>
#include <nexus/Profile.interface.h>
#include <nexus/Mem.interface.h>
#include <nexus/Net.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/Console.interface.h>
#include <nexus/Log.interface.h>
//#include <nexus/KernelFS.interface.h>
#include <nexus/Time.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/VKey.interface.h>
#include "Crypto.interface.h"
#include "VDIR.interface.h"
#include "SMR.interface.h"
#include "Audio.interface.h"
#ifdef __NEXUSXEN__
#include "Xen.interface.h"
#endif
#include "Attestation.interface.h"
#include "nsk.interface.h"
#include "nrk.interface.h"
#include "ddrm.interface.h"

typedef int (*syscall_ipc_handler)(InterruptState *);
uint64_t syscall_event_num;	///< a simple counter to give unique ids

#define SYSCALL_TYPES_1(H)			\
  H(Attestation);				\
  H(Audio);					\
  H(Console);					\
  H(Crypto);					\
  H(Debug);					\
  H(IPC);					\
  H(Log);					\
  H(Mem);					\
  H(Net);					\
  H(nsk);					\
  H(nrk);					\
  H(pci);					\
  H(Profile);					\
  H(SMR);					\
  H(Thread);					\
  H(Time);					\
  H(VDIR);					\
  H(VKey);					\
  H(ddrm);					
  
//H(Syscall);					
//H(Tap);					
//H(KernelFS);					
//H(LabelStore);				

#ifdef __NEXUSXEN__
#define ALL_SYSCALL_TYPES(call) SYSCALL_TYPES_1(call) call(Xen);
#else
#define ALL_SYSCALL_TYPES(call) SYSCALL_TYPES_1(call)
#endif

/** Create a port for a .sc class and set its call handler 
    to the function specified in the .sc file 
 
    the second part is handled by code in the .sc file

    XXX remove need of these macros by removing use of 
        variables with 'magical' class names 		   */
#define KERNEL_INIT(SCCLASS) \
	do {								\
		int num = SYSCALL_IPCPORT_##SCCLASS;			\
									\
		IPC_CreatePort(&num);					\
		assert(num == SYSCALL_IPCPORT_##SCCLASS);		\
		SCCLASS##_kernelInit();					\
	} while (0);

/** verify that all system calls have been registered and have handlers */
static void 
__syscall_verify_scports(void)
{
#ifndef NDEBUG
	IPC_Port *port;
	int i;

	for (i = FIRST_SYSCALL_IPCPORT; i <= LAST_SYSCALL_IPCPORT; i++) {
		port = IPCPort_find(i);
		if (!port || !port->kernel_call_handler) {
			printkx(PK_SYSCALL, PK_DEBUG, "no syscall port %d\n",
				i - FIRST_SYSCALL_IPCPORT);
		}
		else
			IPCPort_put(port);
	}
#endif
}

/** Initialize all system calls.

    Since most are encapsulated and sent as IPC, set up IPC ports
    that listen on incoming calls and execute the right callback handlers */
void 
syscall_init(void) 
{

  // set the callback of each 'syscall type' port to a system call handler
  ALL_SYSCALL_TYPES(KERNEL_INIT);
  __syscall_verify_scports();

  // detect and initialize sysenter MSRs
  printkx(PK_SYSCALL, PK_DEBUG, "x86=%d model=%d mask=%d sep = %d\n", 
	     boot_cpu_data.x86, boot_cpu_data.x86_model,
	     boot_cpu_data.x86_mask, cpu_has_sep);

  // disable sysenter on older machines 
  if (boot_cpu_data.x86 == 6 && boot_cpu_data.x86_model < 3 && 
      boot_cpu_data.x86_mask < 3)
    clear_bit(X86_FEATURE_SEP, boot_cpu_data.x86_capability);
  
  // sysenter/sysexit type fast kernel mode (system call) switching
  if (cpu_has_sep) {
    void *sep_base;
    uint32_t sep_top;

    wrmsr(MSR_IA32_SYSENTER_CS, KNEXUSCS, 0);

    sep_base = getKernelPages(1);
    assert(sep_base);
    sep_top = (uint32_t)((char *) sep_base + PAGESIZE - sizeof(int));

    // Allocate a tiny initial sysenter stack
    wrmsr(MSR_IA32_SYSENTER_ESP, sep_top, 0);
    wrmsr(MSR_IA32_SYSENTER_EIP, sysenter_call, 0);
  }
}

#define FASTPATH_HANDLER(N)					\
  N##_syscallProcessorCases(dataBuf, dataLen, result);

static int 
syscall_fastpath(int syscall_num,  char *dataBuf, int dataLen, char *result) 
{

  nexusuthread_current()->fast_syscall_result_dest = result;

  switch (syscall_num) {
    ALL_SYSCALL_TYPES(FASTPATH_HANDLER);
      break;
    default:
      nexusthread_dump_regs_stack(nexusthread_self());
      return -SC_INVALID;
  };

  nexusuthread_current()->fast_syscall_result_dest = NULL;

  return 0;
}

#undef FASTPATH_HANDLER

int setup_syscall_stub(Map *m) {
  char *entry_stub;
  int entry_stub_len;
  char *exit_stub;
  int exit_stub_len;
  if (cpu_has_sep) {
    extern char sysenter_stub_template[], sysenter_stub_template_end[];
    extern char sysexit_stub_template[], sysexit_stub_template_end[];
    entry_stub = sysenter_stub_template;
    entry_stub_len = sysenter_stub_template_end - sysenter_stub_template;
    exit_stub = sysexit_stub_template;
    exit_stub_len = sysexit_stub_template_end - sysexit_stub_template;
  } else {
    printk_red("int 82h init\n");
    extern char int82_stub_template[], int82_stub_template_end[];
    entry_stub = int82_stub_template;
    entry_stub_len = int82_stub_template_end - int82_stub_template;
    exit_stub = NULL;
    exit_stub_len = 0;
  }

  assert(SYSENTER_STUB_ADDR == SYSENTER_STUB_C);
  assert(SYSEXIT_STUB_ADDR == SYSEXIT_STUB_C);

  assert(entry_stub_len < sizeof(((KShMem *)0)->sysenter_stub));
  assert(exit_stub_len < sizeof(((KShMem *)0)->sysexit_stub));

  if(entry_stub_len > 0) {
    if(poke_user(m, SYSENTER_STUB_ADDR, entry_stub, entry_stub_len) != 0) {
      return -1;
    }
  }
  if(exit_stub_len > 0) {
    if(poke_user(m, SYSEXIT_STUB_ADDR, exit_stub, exit_stub_len) != 0) {
      return -1;
    }
  }
  return 0;
}

/** create a connection from this ipd to all syscall ports
    XXX why? */
static void
__syscall_connect(IPD *ipd, Port_Num port_num)
{
	IPC_Connection *connection;
	IPC_Port *port;
	Connection_Handle handle, wanted_handle;

	assert(IS_SYSCALL_IPCPORT(port_num));
	port = IPCPort_find(port_num);
	assert(port && port->port_num == port_num); // overly paranoid
	
	connection = IPCConnection_new(ipd, port, 0);
	wanted_handle = port_num - FIRST_SYSCALL_IPCPORT + 1;

	handle = ipd_addConnection(ipd, connection, wanted_handle); 
  	assert(handle == wanted_handle);
  	IPCConnection_put(connection);
	IPCPort_put(port);
}

#define POPULATE_TABLE(class) __syscall_connect(ipd, SYSCALL_IPCPORT_##class);

/** Open IPC connections to all system call kernel handlers 
    XXX is this M:N match between processes and calls really necessary? */
void 
populate_syscall_conn_table(IPD *ipd) 
{
  IPC_Connection *connection;
  ALL_SYSCALL_TYPES(POPULATE_TABLE);
}

// deprecated XXX: remove and check against syscalling from kernel (should be an oxymoron) at IPC-Callee..:Invoke
void 
populate_kernelIPD_syscall_conn_table(IPD *ipd) 
{
  int i;
  for(i = 0; i <= LAST_SYSCALL_IPCPORT  - FIRST_SYSCALL_IPCPORT; i++) {
      ipd_addConnection(ipd, RESERVED_CONNECTION, i);
  }
}


/**** Handlers for IPC calls (which are syscalls) ********/

// Special cases for system call handling that bypasses the indirection through IPC layer.
// We could auto-generate these, but I expect there to be only a handful
#define GET_ARG(T)							\
  struct IPC_##T##_Args __args;						\
  if (unlikely(peek_user(nexusthread_current_map(), is->ecx + sizeof(int), &__args, sizeof(__args)) != 0)) \
    return -SC_ACCESSERROR;				 \

#define CALL_AND_PUT_RESULT(T, ...) struct IPC_##T##_Result __rval = {	\
    .resultCode = 0,							\
    .rv = IPC_##T##_Handler(-1, -1, NULL, 0, ##__VA_ARGS__), \
  };									\
  if(unlikely(poke_user(nexusthread_current_map(), is->edx, &__rval, sizeof(__rval)) != 0)) \
    return -SC_ACCESSERROR;						\
  return 0;

/** Contrary to the other calls, handle system calls immediately */
int IPC_InvokeSys_fromIS(InterruptState *is) {
    struct IPC_InvokeSys_Result rval;
    struct TransferDesc result_descriptor;
    int opcode;

    GET_ARG(InvokeSys);

    // safely aquire the system call opcode
    if(unlikely(peek_user(nexusthread_current_map(), 
			       (unsigned int) __args.message, 
			       &opcode, sizeof(opcode)) != 0)) {
      printk_red("could not copy message opcode\n");
      return -SC_ACCESSERROR;
    }

    // safely acquire the result descriptor (only used in async mode)
    if(unlikely(peek_user(nexusthread_current_map(),
			       (unsigned int)__args.user_descs, 
			       &result_descriptor, 
			       sizeof(struct TransferDesc)) != 0)) {
      printk_red("could not copy result descriptor\n");
      return -SC_ACCESSERROR;
    }

    // find and invoke the actual system call handler
    rval.resultCode = 0;
    rval.rv = syscall_fastpath(opcode, __args.message,
			       __args.message_len - sizeof(int),	// XXX why -sizeof int?
			       (void *)result_descriptor.u.direct.base);

    // safely write the return value
    if(unlikely(poke_user(nexusthread_current_map(), 
			  is->edx, &rval, sizeof(rval)) != 0))
      return -SC_ACCESSERROR;

    return 0;
}

int IPC_Invoke_fromIS(InterruptState *is) {
  GET_ARG(Invoke);
  CALL_AND_PUT_RESULT(Invoke,
			__args.conn_handle,
			__args.message,
			__args.message_len,
			__args.user_descs,
			__args.num_transfer_descs);
}

int IPC_TransferFrom_fromIS(InterruptState *is) {
  GET_ARG(TransferFrom);
  CALL_AND_PUT_RESULT(TransferFrom,
		      __args.call_handle0,
		      __args.desc_num,
		      __args.local,
		      __args.remote,
		      __args.len);
}
int IPC_TransferTo_fromIS(InterruptState *is) {
  GET_ARG(TransferTo);
  CALL_AND_PUT_RESULT(TransferTo,
		      __args.call_handle0,
		      __args.desc_num,
		      __args.remote,
		      __args.local,
		      __args.len);
}
int IPC_RecvCall_fromIS(InterruptState *is) {
  GET_ARG(RecvCall);
  CALL_AND_PUT_RESULT(RecvCall,
		      __args.port_handle,
		      __args.message_dest,
		      __args.message_len_p,
		      __args.call_descriptor);
}
int IPC_CallReturn_fromIS(InterruptState *is) {
  GET_ARG(CallReturn);
  CALL_AND_PUT_RESULT(CallReturn,
		      __args.call_handle0);
}

int IPC_AsyncReceive_fromIS(InterruptState *is) {
  GET_ARG(AsyncReceive);
  CALL_AND_PUT_RESULT(AsyncReceive,
		      __args.port_handle,
		      __args.user_message,
		      __args.max_message_len,
		      __args.user_transfer_descs);
}

int IPC_AsyncDone_sys_fromIS(InterruptState *is) {
  GET_ARG(AsyncDone_sys);
  CALL_AND_PUT_RESULT(AsyncDone_sys,
		      __args.call_handle0, __args.done_type);
}

int IPC_AsyncSend_fromIS(InterruptState *is) {
  GET_ARG(AsyncSend);
  CALL_AND_PUT_RESULT(AsyncSend,
		      __args.conn_handle,
		      __args.user_message, __args.message_len,
		      __args.user_descs, __args.num_transfer_descs);
}


/**** System call handling ********/

/** syscall handling preamble */
static inline void 
__syscall_enter(BasicThread *t, InterruptState *is) 
{
  __asm__ ( "movl $1, %0" :
	    "=r" (t->in_syscall) : : "memory" );

  t->trap_is = is;
  t->syscall_is = is;
}

/* syscall handle postscript */
static inline void 
__syscall_exit_finish(BasicThread *t) 
{
  __asm__ __volatile__ ( "movl $0, %0" 		:
	                 "=r" (t->in_syscall) 	: 
			 			:
			 "memory" );  
  // thread is now killable
}

static void 
__syscall_exit(BasicThread *t, InterruptState *is) 
{
  t->trap_is = NULL;
  t->syscall_is = NULL;

  if(unlikely(t->pending_kill))
    nexusthread_check_and_do_pending_kill(t);

#ifdef __NEXUSXEN__
  if(nexusthread_isXen(t)) {
    // Might not return, depending on Xen event mask 

    // We split __syscall_exit_finish(t) into two paths for performance

    // In non-Xen case, we don't need to bother to disable interrupts,
    // since nothing critical happens after in_syscall is cleared

    // In Xen case, we want to make sure that this thread is not
    // killed during dispatchPendingEvent.

    // We could eliminate this disable_intr() by clearing the
    // in_syscall flag in dispatchPendingEvent, but this code is
    // cleaner, and as of 12/14, dispatchPendingEvent() already
    // disables interrupts
    int intlevel = disable_intr();
    __syscall_exit_finish(t);
    nexusthread_Xen_dispatchPendingEvent(t, is);
    restore_intr(intlevel);
  } else 
#endif
  {
    __syscall_exit_finish(t);
    // Do not do anything after thread becomes killable
  }
}

/** secondary system call demultiplexer. 
    handles calls that are not marshalled into an IPC request */
static void
__syscall_nointerpose(InterruptState *is)
{
    switch (is->eax) {

#ifdef __NEXUSXEN__
	case SYS_Xen_PreInit_CMD:
      		is->eax = Xen_PreInit_handler(is);
      		break;
#endif
	case SYS_Attestation_TakeOwnership_CMD:
      		is->eax = Attestation_TakeOwnership_Handler(-1, -1, NULL, 0, 
						            (unsigned char *) is->ecx,
							    (unsigned char *)is->edx);
		break;
    	case SYS_BIRTH:
      		nexusthread_birth();
      		break;
    	case SYS_NPANIC:
      		disable_intr();
      		nexuspanic();
      		break;
	default:
      		printk("Error: unknown system call %d in process %x\n", 
	     	       is->eax, nexusthread_current_ipd()->id);
     		 is->eax = -SC_INVALID;
	}
}

/** main system call demultiplexer. 
    aex register holds system call number: switch based on its value */
void 
nexus_syscall(InterruptState *is) 
{
  syscall_ipc_handler handler;

  // Nothing exotic should happen before enter_syscall is called,
  // since the thread is considered killable before this point
  __syscall_enter(curt, is);

  // AFAIK gcc generates a jump table from this
  switch (is->eax) {
	case SYS_IPC_Invoke_CMD:	is->eax = IPC_Invoke_fromIS(is);	break;
	case SYS_IPC_InvokeSys_CMD:	is->eax = IPC_InvokeSys_fromIS(is);	break;
	case SYS_IPC_RecvCall_CMD:	is->eax = IPC_RecvCall_fromIS(is); 	break;
	case SYS_IPC_CallReturn_CMD:	is->eax = IPC_CallReturn_fromIS(is);	break;
	case SYS_IPC_TransferFrom_CMD:	is->eax = IPC_TransferFrom_fromIS(is);	break;
	case SYS_IPC_TransferTo_CMD:	is->eax = IPC_TransferTo_fromIS(is);	break;
	case SYS_IPC_AsyncReceive_CMD:	is->eax = IPC_AsyncReceive_fromIS(is);	break;
	case SYS_IPC_AsyncDone_sys_CMD:	is->eax = IPC_AsyncDone_sys_fromIS(is);	break;
	case SYS_IPC_AsyncSend_CMD:	is->eax = IPC_AsyncSend_fromIS(is);	break;

	// most system calls are marshalled. this is not one of them, call directly
	default: __syscall_nointerpose(is);
		 return;
  }

  // cleanup after syscall
  __syscall_exit(curt, is);
}

