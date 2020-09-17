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
#include <nexus/guard.h>
#include <nexus/ipc.h>
#include <nexus/thread-private.h>
#include <nexus/thread-struct.h>
#include <nexus/syscall-defs.h>
#include <nexus/syscall-private.h>
#include <nexus/syscall-asm.h>
#include <nexus/ipc_private.h>

#include <nexus/IPC.interface.h>
#include <nexus/Mem.interface.h>
#include <nexus/Net.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/Console.interface.h>
#include <nexus/Time.interface.h>
#include <nexus/Debug.interface.h>
#ifdef __NEXUSXEN__
#include "Xen.interface.h"
#endif
#include "Device.interface.h"

/** Initialize all system calls.

    Since most are encapsulated and sent as IPC, set up IPC ports
    that listen on incoming calls and execute the right callback handlers */
void 
syscall_init(void) 
{
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

/** Sysenter requires shared memory. Int82 is used by Xen */
int 
setup_syscall_stub(Map *m) 
{
  extern char sysenter_stub_template[], sysenter_stub_template_end[];
  extern char sysexit_stub_template[], sysexit_stub_template_end[];
  extern char int82_stub_template[], int82_stub_template_end[];
  
  char *entry_stub;
  int entry_stub_len;
  char *exit_stub;
  int exit_stub_len;

  if (cpu_has_sep) {
    entry_stub = sysenter_stub_template;
    entry_stub_len = sysenter_stub_template_end - sysenter_stub_template;
    exit_stub = sysexit_stub_template;
    exit_stub_len = sysexit_stub_template_end - sysexit_stub_template;
  } else {
    entry_stub = int82_stub_template;
    entry_stub_len = int82_stub_template_end - int82_stub_template;
    exit_stub = NULL;
    exit_stub_len = 0;
  }

  assert(SYSENTER_STUB_ADDR == SYSENTER_STUB_C);
  assert(SYSEXIT_STUB_ADDR == SYSEXIT_STUB_C);
  assert(entry_stub_len < sizeof(((KShMem *)0)->sysenter_stub));
  assert(exit_stub_len < sizeof(((KShMem *)0)->sysexit_stub));

  if (entry_stub_len > 0) {
    if (poke_user(m, SYSENTER_STUB_ADDR, entry_stub, entry_stub_len) != 0) {
      return -1;
    }
  }
  if (exit_stub_len > 0) {
    if (poke_user(m, SYSEXIT_STUB_ADDR, exit_stub, exit_stub_len) != 0) {
      return -1;
    }
  }
  return 0;
}


/**** Handlers for IPC calls (which are syscalls) ********/

/** system calls take a fast (?) path: skip RecvCall and most of CallReturn */
static inline int
rpc_invoke_syscall(struct IPC_Invoke_Args *args)
{
  void (*callback)(char *, int , char *);
  
  // system calls use IPC_TransferTo fastpath hack for returncode
  curt->syscall_result = (void *) args->descs->u.direct.base;
  
  // demultiplex message
  switch (args->portnum) {
    case SYSCALL_IPCPORT_IPC:	 	callback = IPC_syscallProcessor; break;
    case SYSCALL_IPCPORT_Thread: 	callback = Thread_syscallProcessor; break;
    case SYSCALL_IPCPORT_Mem:	 	callback = Mem_syscallProcessor; break;
    case SYSCALL_IPCPORT_Net:	 	callback = Net_syscallProcessor; break;
    case SYSCALL_IPCPORT_Debug:	 	callback = Debug_syscallProcessor; break;
    case SYSCALL_IPCPORT_Console:	callback = Console_syscallProcessor; break;
    case SYSCALL_IPCPORT_Time:		callback = Time_syscallProcessor; break; 
    case SYSCALL_IPCPORT_Device:	callback = Device_syscallProcessor; break;
#ifdef __NEXUSXEN__
    case SYSCALL_IPCPORT_Xen:		callback = Xen_syscallProcessor; break;
#endif
    default: 
	printk_red("[%d.%d] ILLEGAL SYSCALL %d\n", curt->ipd->id, curt->id, args->portnum);
	if (curt->name) printk_red("     (thread %s)\n", curt->name);
	ipd_kill(curt->ipd);
  };

  callback(args->msg /* include opcode */, args->mlen - sizeof(int), NULL);
  return 0;
}
#undef FASTPATH_HANDLER

/** Handle a wrapped system or RPC call */
static int 
nexus_invoke(InterruptState *is) 
{
  struct IPC_Invoke_Args *args;
  struct IPC_Invoke_Result *rv;
  struct nxguard_tuple tuple;
  int ret = 0;

  rv = ((void *) is->edx);
  
  // create local copy of arguments (that the process cannot modify)
#ifdef SAFE_COPY
  args = gcalloc(1, sizeof(*args));
  memcpy(args, ((void *) is->ecx) + sizeof(int), sizeof(*args));
#else
  args = ((void *) is->ecx) + sizeof(int);
  // XXX make sure caller cannot modify arguments after the check:
  //     block task switch into other caller thread 
  //     or lazily copy before switch
#endif

  // push onto thread stack for services to find
  assert(curt->callstack_len + 1 < MAX_CALLSTACK);
  curt->callstack[curt->callstack_len++] = args;
  
  // interposition on call and access control
  tuple.subject = curt->ipd->id;
  if (curt->ipd->id > 1 &&
      nxkguard_in(args->portnum, args->msg, args->mlen, &tuple)) {
	  ret = -SC_ACCESSERROR;
	  goto cleanup;
  }

  // call 
  if (likely(args->portnum <= LAST_SYSCALL_IPCPORT))
	  rv->rv = rpc_invoke_syscall(args);
  else
	  rv->rv = rpc_invoke(args->portnum);
  
  // interposition on return path:
  // only called if was interposed on incoming path
  if (unlikely(curt->ipd->refmon_port >= 1))
	  nxkguard_out(&tuple);

cleanup:
  curt->callstack_len--;
  rv->resultCode = ret; 
#ifdef SAFE_COPY
  gfree(args);
#endif
  return ret;
}

/**** System call handling ********/

static inline unsigned long
nexus_syscall_demux(InterruptState *is)
{
  // Ordered list of integers
  // AFAIK gcc generates a jump table from this
  switch (is->eax) {
	case SYS_IPC_Invoke_CMD:			
	case SYS_IPC_InvokeSys_CMD:		return nexus_invoke(is);	
	case SYS_RAW_CondVar_Wait_CMD:		return nxcondvar_wait((int*) is->ecx, (unsigned int*) is->edx, 
								      (int) is->ebx, (int*) is->esi, 
								      (unsigned int *) is->edi);
  	case SYS_RAW_CondVar_Signal_CMD:	return nxcondvar_signal((int*) is->ecx, (unsigned int*) is->edx);
  	case SYS_RAW_Process_Fork_CMD:		return ipd_fork();		///< fork() CANNOT be interposed
	case SYS_RAW_Thread_Yield_CMD:		nexusthread_yield(); return 0;
	case SYS_RAW_Thread_GetParentID_CMD:	return curt->ipd->parent ? curt->ipd->parent->id : 0;	///< benchmarking
#if NXCONFIG_FAST_IPC
	case SYS_RAW_Send_CMD:			return ipc_send(curr_map, (long) is->ecx, (void *) is->edx, (long) is->ebx);
	case SYS_RAW_Recv_CMD:			return ipc_recv(curr_map, (long) is->ecx, (void *) is->edx, (long) is->ebx, NULL);
	case SYS_RAW_SendPage_CMD:		return ipc_sendpage_impl(curr_map, (long) is->ecx, (void *) is->edx);
	case SYS_RAW_RecvPage_CMD:		return ipc_recvpage_impl(curr_map, (long) is->ecx, (void *) is->edx, NULL);
#endif
#ifdef __NEXUSXEN__
	case SYS_RAW_Xen_PreInit_CMD:		return Xen_PreInit_handler(is);
#else
	case SYS_RAW_Xen_PreInit_CMD:		return 0;
#endif
  	case SYS_RAW_Debug_Null_CMD:		return 0; // for benchmarking only
	case SYS_RAW_Time_gettimeofday_CMD:	return gettimeofday_posix((void *) is->ecx);
	case SYS_BIRTH:				return 0;
  }

#ifndef NDEBUG
  printkx(PK_SYSCALL, PK_WARN, "unhandled system call %d\n", is->eax);
#endif
  return -1;
}

/** main system call demultiplexer. 
    aex register holds system call number: switch based on its value */
void 
nexus_syscall(InterruptState *is) 
{
  if (unlikely(is->eax < SYSCALL_TBL_START ||is->eax > SYSCALL_TBL_STOP)) {
	printk_current("Illegal system call %d\n", is->eax);
	ipd_kill(curt->ipd);
  }

  // if dead, allow thread to be reaped
  if (unlikely(curt && curt->schedstate == DEAD))
    nexusthread_yield();

  // thread is considered killable before this point
  curt->syscall_is = is;

#if NXCONFIG_CYCLECOUNT_USER
  if (curt->cycles_ustart) {
	  unsigned long long cdiff = rdtsc64() - curt->cycles_ustart;
	  curt->cycles_ustart = 0;	// small race with accounting in thread.c:switch
	  curt->cycles_user += cdiff;
	  curt->cycles_utotal += cdiff;
  }
#endif
  
  // handle request
  is->eax = nexus_syscall_demux(is);
	
  // cleanup after syscall
  curt->syscall_is = NULL;

#ifdef __NEXUSXEN__
  // see commit f69a245ae9e479f7c or older for old code
#endif
  
#if !NXCONFIG_PREEMPT_KERNEL
  // check if the process was preempted (optionally delayed if in kernel)
  if (unlikely(swap(&curt->pending_preempt, 0))) 
    nexusthread_yield();
#endif
  
  // if dead, allow thread to be reaped
  if (unlikely(curt->schedstate == DEAD))
    nexusthread_yield();

#if NXCONFIG_CYCLECOUNT_USER
  curt->cycles_ustart = rdtsc64();
#endif
}

