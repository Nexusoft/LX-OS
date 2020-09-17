
#include <nexus/guard.h>
#include <nexus/guard-impl.h>
#include <nexus/syscall-defs.h>

static int 
nxrefmon_vlance_in(struct nxguard_tuple tuple)
{
	static int callcount, _phys, _read, _write, _in, _out, _irq, _pcir, _pciw, _sendp, _recvp;
	static int _yield, _usleep, _unblock, _getid, _getpid, _brk, _getpage, _freepage, _timeofday;

	return AC_ALLOW_NOCACHE;
	//return AC_ALLOW_CACHE;
#if 0
	if (!(++callcount % 10000)) {
		printf("dev[phys=%d read=%d write=%d in=%d out=%d irq=%d pcir=%d pciw=%d] ipc[sendp=%d recvp=%d]\n",
			_phys, _read, _write, _in, _out, _irq, _pcir, _pciw,  _sendp, _recvp);
		_phys = _read = _write = _in = _out = _irq = _sendp = _recvp = 0;
		printf("   [yield=%d, sleep=%d, unblock=%d id=%d pid=%d, brk=%d, getpg=%d, free=%d, tod=%d\n",
			_yield, _usleep, _unblock, _getid, _getpid, _brk, _getpage, _freepage, _timeofday);
		_yield= _usleep= _unblock= _getid= _getpid= _brk= _getpage= _freepage= _timeofday = 0;

	}
#endif

	// XXX copy parameters and/or VarLen data to perform necessary checks
	// e.g., read configspace to extract safe IRQ and ioport+mem ranges
	//       read probe IDlist to verify that the driver only tries vlance 
	
	switch (tuple.operation) {

	// calls that require extra checks
	case SYS_Mem_GetPhysicalAddress_CMD:	_phys++; break; //printf("devmem lookup physical\n"); break;
	case SYS_Device_mem_read_CMD:		_read++; break;//printf("devmem read\n"); break;
	case SYS_Device_mem_write_CMD:		_write++; break;//printf("devmem write\n"); break;
	case SYS_Device_mem_map_CMD:		break;//printf("devmem map\n"); break;
	case SYS_Device_inb_CMD:		
	case SYS_Device_inw_CMD:
	case SYS_Device_inl_CMD:		_in++; break;//printf("ioport in\n"); break;
	case SYS_Device_outb_CMD:
	case SYS_Device_outw_CMD:
	case SYS_Device_outl_CMD:		_out++; break;//printf("ioport out\n"); break;
	case SYS_Device_irq_get_CMD:		break;//printf("irq get\n"); break;
	case SYS_Device_irq_wait_CMD:		_irq++; break;//printf("irq wait\n"); break;
	case SYS_Device_irq_put_CMD:		break;//printf("irq put\n"); break;
	case SYS_Device_pciconfig_read_CMD:	_pcir++; break;//printf("pciconfig read\n"); break; // XXX block
	case SYS_Device_pciconfig_write_CMD:	_pciw++; break;//printf("pciconfig write\n"); break; // XXX block
	case SYS_Pci_Probe_CMD:			//printf("pci probe\n"); break;
	case SYS_Pci_ConfigSpace_CMD:		//printf("pci configspace\n"); break;
	case SYS_Pci_ConfigSpace_BarLength_CMD:	break;//printf("pci barlength\n"); break;
	case SYS_IPC_SendPage_CMD:		_sendp++; break;
	case SYS_IPC_RecvPage_CMD:		_recvp++; break;
						break;

	case SYS_Thread_Fork_CMD:
	{
		static int forkcount;

		if (forkcount) {
			printf("BLOCKED thread create\n");
			return AC_BLOCK_CACHE;
		}

		// allow a single thread creation: for the interrupt handler
		forkcount = 1;
		return AC_ALLOW_CACHE;
	}

	// calls that are always allowed
	case SYS_Thread_Yield_CMD:		_yield++; return AC_ALLOW_CACHE;
	case SYS_Thread_ExitThread_CMD:		return AC_ALLOW_CACHE;
	case SYS_Thread_USleep_CMD:		_usleep++; return AC_ALLOW_CACHE;
	case SYS_Thread_CondVar_Wait_CMD:	return AC_ALLOW_CACHE;
	case SYS_Thread_CondVar_Signal_CMD:	_unblock++; return AC_ALLOW_CACHE;
	case SYS_Thread_CondVar_Broadcast_CMD:	_unblock++; return AC_ALLOW_CACHE;
	case SYS_Thread_CondVar_Free_CMD:	return AC_ALLOW_CACHE;
	case SYS_Thread_GetID_CMD:		_getid++; return AC_ALLOW_CACHE;
	case SYS_Thread_GetProcessID_CMD:	_getpid++; return AC_ALLOW_CACHE;
	case SYS_Mem_Brk_CMD:			_brk++; return AC_ALLOW_CACHE;
	case SYS_Mem_GetPages_CMD:		_getpage++; return AC_ALLOW_CACHE;
	case SYS_Mem_FreePages_CMD:		_freepage++; return AC_ALLOW_CACHE;
	case SYS_Time_gettimeofday_CMD:		_timeofday++; return AC_ALLOW_CACHE;

	case SYS_Thread_SetMyTCB_CMD:
	case SYS_Thread_Exit_CMD:
	case SYS_Thread_RegisterTrap_CMD:
	case SYS_Net_GetMyIP_CMD:
	case SYS_Net_add_mac_CMD:
	case SYS_IPC_CreatePort_CMD:
	case SYS_IPC_DestroyPort_CMD:
	case SYS_Console_PrintString_CMD:
	case SYS_Console_GetData_CMD:
		return AC_ALLOW_CACHE;

	// all other calls are always blocked
	default:
		printf("BLOCKED opcode=%d\n", tuple.operation);
		return AC_BLOCK_CACHE;
	};

	return AC_ALLOW_NOCACHE;
}

static int 
nxrefmon_vlance_out(struct nxguard_tuple tuple)
{
	return 0;
}

