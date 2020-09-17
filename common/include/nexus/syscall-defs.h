/** NexusOS: main naming of system calls and IPC ports */

#ifndef _SYSCALLS_H_
#define _SYSCALLS_H_

#include <nexus/config.h>

// Result codes

#define SC_NOERROR (0)
#define SC_ACCESSERROR (1)
#define SC_INVALID (2)
#define SC_KERNELERROR (3)
#define SC_NOMEM (4)
#define SC_NORESULTMEM (5)
#define SC_TRUNCATED (6)
#define SC_REPEATED (7)
#define SC_NOPERM (8)
#define SC_NOTFOUND (9)
#define SC_LABELERROR (10)
#define SC_INTERPOSE_ERROR 	(11)
#define SC_INTERPOSE_DROPPED 	(12)
#define SC_NOTASSIGNED (13)
#define SC_INTERRUPTED (14)
#define SC_PEERKILLED (15)
#define SC_FORKED (16)
#define SC_NOTCONNECTED (17)
#define SC_PORTDESTROYED (18)
#define SC_BADPOLICY (19)

// IPC ports are the routing end points of connections and messages
// (incl. syscalls). As such, they are important identifiers. 
//
// Below we first list all the reserved ports that have a specific use, such 
// as system calls, and then define the start of the dynamic port range.

#define FIRST_IPCPORT (1)

/// Reserved system call identifiers

#define FIRST_SYSCALL_IPCPORT		FIRST_IPCPORT
#define SYSCALL_IPCPORT_IPC	 	FIRST_IPCPORT
#define SYSCALL_IPCPORT_Thread	 	FIRST_IPCPORT + 1
#define SYSCALL_IPCPORT_Mem	 	FIRST_IPCPORT + 2
#define SYSCALL_IPCPORT_Net	 	FIRST_IPCPORT + 3
#define SYSCALL_IPCPORT_pci	 	FIRST_IPCPORT + 4
#define SYSCALL_IPCPORT_Debug	 	FIRST_IPCPORT + 5
#define SYSCALL_IPCPORT_Console	 	FIRST_IPCPORT + 6
#define SYSCALL_IPCPORT_Time	 	FIRST_IPCPORT + 7
#define SYSCALL_IPCPORT_Device	 	FIRST_IPCPORT + 8
#define SYSCALL_IPCPORT_Xen	 	FIRST_IPCPORT + 9
#define LAST_SYSCALL_IPCPORT		FIRST_IPCPORT + 9

#define SYSCALL_CONN_HANDLE(S) (SYSCALL_IPCPORT_##S - FIRST_SYSCALL_IPCPORT + 1)

/// More reserved ports

#define RamFS_reserved_port	LAST_SYSCALL_IPCPORT + 1
#define default_mouse_port	LAST_SYSCALL_IPCPORT + 2
#define guard_upcall_port	LAST_SYSCALL_IPCPORT + 3
#define guard_init_port		LAST_SYSCALL_IPCPORT + 4
#define keyboard_ctrl_port	LAST_SYSCALL_IPCPORT + 5
#define guard_authority_port	LAST_SYSCALL_IPCPORT + 6
#define memtest_reserved_port 	LAST_SYSCALL_IPCPORT + 7
#define ipctest_reserved_port 	LAST_SYSCALL_IPCPORT + 8
#define default_switch_port	LAST_SYSCALL_IPCPORT + 9
#define default_keyboard_port	LAST_SYSCALL_IPCPORT + 10
#define primary_lockbox_port	LAST_SYSCALL_IPCPORT + 11
#define resctl_cpu_port		LAST_SYSCALL_IPCPORT + 12
#define default_guard_port	LAST_SYSCALL_IPCPORT + 13
#define KERNELFS_PORT		LAST_SYSCALL_IPCPORT + 14
#define FATFS_PORT		LAST_SYSCALL_IPCPORT + 15
#define blockdev_port		LAST_SYSCALL_IPCPORT + 16
#define quota_ctrl_port         LAST_SYSCALL_IPCPORT + 17
#define default_pci_port	LAST_SYSCALL_IPCPORT + 18
#define FIRST_DYNAMIC_IPCPORT	LAST_SYSCALL_IPCPORT + 19

/// The end of the range of valid port numbers, to catch bugs
#define LAST_IPCPORT FIRST_DYNAMIC_IPCPORT + 1024

enum NexusSyscalls {

// within this table are the real system calls, 
// which are demultiplexed in one switch. 
// we want it to be an O(1) lookup structure (jump table)
#define SYSCALL_TBL_START (SYS_IPC_Invoke_CMD)
  SYS_IPC_Invoke_CMD = 11000,
  SYS_IPC_InvokeSys_CMD, // syscall variant. Identical to IPC_Call, except does not set IPC_errno on exit.
  SYS_RAW_CondVar_Wait_CMD,
  SYS_RAW_CondVar_Signal_CMD,
  SYS_RAW_Process_Fork_CMD,
  SYS_RAW_Thread_Yield_CMD,
  SYS_RAW_Thread_GetParentID_CMD,
#if NXCONFIG_FAST_IPC
  SYS_RAW_Send_CMD,
  SYS_RAW_Recv_CMD,
  SYS_RAW_SendPage_CMD,
  SYS_RAW_RecvPage_CMD,
#endif
  SYS_RAW_Xen_PreInit_CMD,
  SYS_RAW_Debug_Null_CMD,
  SYS_RAW_Time_gettimeofday_CMD, 
  SYS_BIRTH, /* should never be called from user: magic init 'call' */
#define SYSCALL_TBL_STOP (SYS_BIRTH)

  SYS_IPC_TransferFrom_CMD,
  SYS_IPC_TransferTo_CMD,
  SYS_IPC_Wait_CMD,

  SYS_IPC_AsyncReceive_CMD,
  SYS_IPC_AsyncSend_CMD,
  
  SYS_IPC_CreatePort_CMD,
  SYS_IPC_DestroyPort_CMD,
  SYS_IPC_Caller_CMD,
  SYS_IPC_Server_CMD,
  SYS_IPC_RecvCall_CMD,
  SYS_IPC_CallReturn_CMD,
  SYS_IPC_TransferInterpose_CMD,
  
  SYS_IPC_FromElf_CMD, 			// XXX This should be in Process.sc
  SYS_IPC_Exec_CMD, 			// XXX This should be in Process.sc
  SYS_IPC_ExecInterposed_CMD, 		// XXX This should be in Process.sc
  SYS_IPC_WaitPid_CMD, 			// XXX This should be in Process.sc
  SYS_IPC_Interpose_CMD,		// XXX This should be in Process.sc
  SYS_IPC_Refmon_Start_CMD,

  SYS_IPC_Send_CMD,
  SYS_IPC_Recv_CMD,
  SYS_IPC_RecvFrom_CMD,
  SYS_IPC_SendPage_CMD,
  SYS_IPC_RecvPage_CMD,
  
  SYS_IPC_Poll_CMD,
  SYS_IPC_Available_CMD,
  SYS_IPC_Wake_CMD,
  SYS_IPC_TransferParam_CMD,

  /* Thread */
  SYS_Thread_Yield_CMD = 12000,
  SYS_Thread_Exit_CMD,
  SYS_Thread_ExitThread_CMD,
  SYS_Thread_Fork_CMD,
  SYS_Thread_USleep_CMD,
  SYS_Thread_ForkReserve_CMD,
  SYS_Thread_SetInterrupt_CMD,
  SYS_Thread_GetProcessID_CMD,
  SYS_Thread_GetParentID_CMD,
  SYS_Thread_GetID_CMD,
  SYS_Thread_Times_CMD,
  SYS_Thread_SetMyTCB_CMD,
  SYS_Thread_RegisterTrap_CMD,
  SYS_Thread_GetCycles_CMD,
  SYS_Thread_GetIPDIdentity_CMD,
  SYS_Thread_Notify_CMD,
  SYS_Thread_Reboot_CMD,
  SYS_Thread_SetSchedPolicy_CMD,
  SYS_Thread_Sha1_AddCred_CMD,
  SYS_Thread_Sha1_Get_CMD,
  SYS_Thread_Sha1_GetCert_CMD,
  SYS_Thread_Sha1_Says_CMD,
  SYS_Thread_Sha1_SaysCert_CMD,
  SYS_Thread_Sched_SetProcessAccount_CMD,
  SYS_Thread_Sched_GetProcessAccount_CMD,
  SYS_Thread_Sched_SetQuantumAccount_CMD,
  SYS_Thread_SetName_CMD,
  SYS_Thread_CondVar_Wait_CMD,
  SYS_Thread_CondVar_Signal_CMD,
  SYS_Thread_CondVar_Broadcast_CMD,
  SYS_Thread_CondVar_Free_CMD,
  SYS_Thread_DropPrivilege_CMD,
  SYS_Thread_SetPrivileges_Start_CMD,
  SYS_Thread_SetPrivilege_CMD,
  SYS_Thread_SetPrivileges_Stop_CMD,

  SYS_Mem_GetPages_CMD = 13000,
  SYS_Mem_GetPhysicalAddress_CMD,
  SYS_Mem_MProtect_CMD,
  SYS_Mem_FreePages_CMD,
  SYS_Mem_Brk_CMD,
  SYS_Mem_UnBrk_CMD,
  SYS_Mem_Set_GrantPages_CMD,
  SYS_Mem_Share_Pages_CMD,

  SYS_Net_GetMyIP_CMD = 14000,
  SYS_Net_add_mac_CMD,
  SYS_Net_get_mac_CMD,
  SYS_Net_get_ip_CMD,
  SYS_Net_set_ip_CMD,
  SYS_Net_filter_ipport_CMD,
  SYS_Net_filter_arp_CMD,
  SYS_Net_filter_ipproto_CMD,
  SYS_Net_port_get_CMD,
  SYS_Net_vrouter_to_CMD,
  SYS_Net_vrouter_from_CMD,
  SYS_Net_vrouter_from_blind_CMD,

  SYS_Debug_Null_CMD = 15000,
  SYS_Debug_Null2_CMD,
  SYS_Debug_Null3_CMD,

  SYS_Debug_Abort_CMD,
  SYS_Debug_LinuxCall_CMD,
  SYS_Debug_SoftInt_CMD,
  SYS_Debug_printk_msg_CMD,
  SYS_Debug_Trace_CMD,
  SYS_Debug_KCommand_CMD,

  /* Console */
  SYS_Console_Init_CMD = 16000,
  SYS_Console_Blit_Frame_CMD,
  SYS_Console_GetLine_CMD_deprecated, // Renamed to Console_GetData
  SYS_Console_HasLine_CMD,

  SYS_Console_GetData_CMD,
  SYS_Console_SetInputMode_CMD,

  SYS_Console_MapFrameBuffer_CMD,
  SYS_Console_Blit_Frame_Native_CMD,

  SYS_Console_GetKeymapEntry_CMD,

  SYS_Console_Mouse_Read_CMD,

  SYS_Console_UnmapFrameBuffer_CMD,
  SYS_Console_PrintString_CMD,
  SYS_Console_Switch_CMD,

  /* Time */
  SYS_Time_gettimeofday_CMD = 17000,
  SYS_Time_set_ntp_offset_CMD,
  SYS_Time_GetTicks_CMD,

  SYS_Device_mem_alloc_CMD = 18000,
  SYS_Device_mem_read_CMD,
  SYS_Device_mem_write_CMD,
  SYS_Device_mem_map_CMD,
  SYS_Device_inb_CMD,
  SYS_Device_inw_CMD,
  SYS_Device_inl_CMD,
  SYS_Device_outb_CMD,
  SYS_Device_outw_CMD,
  SYS_Device_outl_CMD,
  SYS_Device_irq_get_CMD,
  SYS_Device_irq_wait_CMD,
  SYS_Device_irq_put_CMD,
  SYS_Device_pciconfig_read_CMD,
  SYS_Device_pciconfig_write_CMD,

#ifdef __NEXUSXEN__
  /* Xen */
  SYS_Xen_AllocPages_CMD = 20000,
  SYS_Xen_FreePages_CMD,
  SYS_Xen_GetPDBR_CMD,
  SYS_Xen_ReadPDBR_CMD,
  SYS_Xen_GetMach2Phys_CMD,
  SYS_Xen_RegisterSharedMFN_CMD,
  SYS_Xen_Set_VMM_PDIR_CMD,
  SYS_Xen_VNet_Init_CMD,
  SYS_Xen_VNet_Send_CMD,
  SYS_Xen_VNet_Recv_CMD,
  SYS_Xen_VNet_HasPendingRecv_CMD,
  SYS_Xen_DeliverVIRQ_CMD,

  /* Xen Hypercalls */
  SYS_Xen_H_mmuext_op_CMD = 21000,
  SYS_Xen_H_mmu_update_CMD,
  SYS_Xen_H_set_callbacks_CMD,
  SYS_Xen_H_set_trap_table_CMD,
  SYS_Xen_H_stack_switch_CMD,
  SYS_Xen_H_event_channel_op_CMD,
  SYS_Xen_H_set_timer_op_CMD,
  SYS_Xen_H_arch_sched_op_CMD,
  SYS_Xen_H_callback_op_CMD,
  SYS_Xen_H_vm_assist_CMD,
  SYS_Xen_H_set_gdt_CMD,
  SYS_Xen_H_multicall_CMD,
  SYS_Xen_H_fpu_taskswitch_CMD,
  SYS_Xen_H_update_descriptor_CMD,
  SYS_Xen_H_physdev_op_CMD,
#endif

  /* Services. first entry MUST correspond with SYSNUM_SVC_START */
#define SYSNUM_SVC_START (SYS_FS_Pin_CMD)
  SYS_FS_Pin_CMD = 22000,
  SYS_FS_Unpin_CMD,
  SYS_FS_Create_CMD,
  SYS_FS_Read_CMD,
  SYS_FS_ReadDir_CMD,
  SYS_FS_Write_CMD,
  SYS_FS_Truncate_CMD,
  SYS_FS_Sync_CMD,
  SYS_FS_Size_CMD,
  SYS_FS_Lookup_CMD,
  SYS_FS_Rename_CMD,
  SYS_FS_Unlink_CMD,
  SYS_FS_Mount_CMD,
  SYS_FS_Unmount_CMD,
  SYS_FS_Setup_Quota_CMD,
  SYS_FS_Link_CMD,
  SYS_FS_Register_Account_CMD,
  SYS_FS_Partition_Size_CMD,
  
  SYS_UserAudio_Init_CMD = 23000,
  SYS_UserAudio_SetRate_CMD,
  SYS_UserAudio_Ioctl_CMD,
  SYS_UserAudio_Write_CMD,

  SYS_LockBox_Shutdown_CMD = 24000,
  SYS_LockBox_Create_CMD,
  SYS_LockBox_Insert_CMD,
  SYS_LockBox_Delete_CMD,
  SYS_LockBox_Encrypt_CMD,
  SYS_LockBox_Decrypt_CMD,
  SYS_LockBox_Sign_CMD,
  SYS_LockBox_Verify_CMD,
  SYS_LockBox_Save_CMD,
  SYS_LockBox_Restore_CMD,

  SYS_Resource_Account_New_CMD = 25000,
  SYS_Resource_Account_AddProcess_CMD,
  SYS_Resource_Account_ByProcess_CMD, 
  SYS_Resource_Account_AddResource_CMD, 
  SYS_Resource_Account_AddInfo_CMD, 
  SYS_Resource_Account_CheckInfo_CMD, 
  SYS_Resource_Account_Attest_CMD,
  SYS_Resource_Info_SizeTotal_CMD,
  SYS_Resource_Info_SizeAccount_CMD,
  
  SYS_Guard_GetGoal_CMD = 26000,
  SYS_Guard_SetGoal_CMD,
  SYS_Guard_SetProof_CMD,
  SYS_Guard_SetAuth_CMD,
  SYS_Guard_TestAuth_CMD,
  SYS_Guard_AddCred_CMD,
  SYS_Guard_AddCredShort_CMD,
  SYS_Guard_AddCredKey_CMD,
  SYS_Guard_InterposeIn_CMD,
  SYS_Guard_InterposeOut_CMD,

  SYS_Auth_Answer_CMD = 27000,

  SYS_Pci_Probe_CMD = 28000,
  SYS_Pci_ConfigSpace_CMD,
  SYS_Pci_ConfigSpace_BarLength_CMD,

};

#endif // _SYSCALLS_H_

