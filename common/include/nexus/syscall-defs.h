#ifndef _SYSCALLS_H_
#define _SYSCALLS_H_

#include <nexus/kshmem.h>	// for MAX_IPD_ID

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

#define FIRST_IPCPORT (MAX_IPD_ID + 1)
#define KERNELFS_PORT			(MAX_IPD_ID + 2)
#define VETO_TEST_PORT			(MAX_IPD_ID + 3)
#define NO_VETO_TEST_PORT		(MAX_IPD_ID + 4)
#define LAST_KERNEL_BOOT_PORT 		(NO_VETO_TEST_PORT)

/// Reserved system call ports

#define SYSCALL_IPCPORT(X) (LAST_KERNEL_BOOT_PORT + 1 + (X))
// CAUTION: the syscall ipc ports must be consecutive
// #define SYSCALL_IPCPORT(X) (MAX_IPD_ID + 1024 + (X))
#define FIRST_SYSCALL_IPCPORT		SYSCALL_IPCPORT(0)
#define SYSCALL_IPCPORT_Attestation	SYSCALL_IPCPORT(0)
#define SYSCALL_IPCPORT_Audio	 	SYSCALL_IPCPORT(1)
#define SYSCALL_IPCPORT_Console	 	SYSCALL_IPCPORT(2)
#define SYSCALL_IPCPORT_Crypto	 	SYSCALL_IPCPORT(3)
#define SYSCALL_IPCPORT_Debug	 	SYSCALL_IPCPORT(4)
#define SYSCALL_IPCPORT_IPC	 	SYSCALL_IPCPORT(5)
#define SYSCALL_IPCPORT_nsk	 	SYSCALL_IPCPORT(6)
#define SYSCALL_IPCPORT_Log	 	SYSCALL_IPCPORT(7)
#define SYSCALL_IPCPORT_Mem	 	SYSCALL_IPCPORT(8)
#define SYSCALL_IPCPORT_Net	 	SYSCALL_IPCPORT(9)
#define SYSCALL_IPCPORT_pci	 	SYSCALL_IPCPORT(10)
#define SYSCALL_IPCPORT_Profile	 	SYSCALL_IPCPORT(11)
#define SYSCALL_IPCPORT_SMR	 	SYSCALL_IPCPORT(12)
#define SYSCALL_IPCPORT_nrk	 	SYSCALL_IPCPORT(13)
#define SYSCALL_IPCPORT_Thread	 	SYSCALL_IPCPORT(14)
#define SYSCALL_IPCPORT_Time	 	SYSCALL_IPCPORT(15)
#define SYSCALL_IPCPORT_VDIR	 	SYSCALL_IPCPORT(16)
#define SYSCALL_IPCPORT_VKey	 	SYSCALL_IPCPORT(17)
#define SYSCALL_IPCPORT_ddrm	 	SYSCALL_IPCPORT(18)
#define SYSCALL_IPCPORT_LabelStore 	SYSCALL_IPCPORT(19)
#define SYSCALL_IPCPORT_Xen	 	SYSCALL_IPCPORT(20)
#define LAST_SYSCALL_IPCPORT		SYSCALL_IPCPORT(20) // this must match previous line

#define SYSCALL_CONN_HANDLE(S) (SYSCALL_IPCPORT_##S - FIRST_SYSCALL_IPCPORT + 1)

#define NUM_SYSCALL_IPCPORTS					\
  (LAST_SYSCALL_IPCPORT - FIRST_SYSCALL_IPCPORT + 1)

/// Other reserved ports

#define RamFS_reserved_port	LAST_SYSCALL_IPCPORT + 1
#define guard_authtest_port	LAST_SYSCALL_IPCPORT + 2
#define guard_upcall_port	LAST_SYSCALL_IPCPORT + 3
#define guard_upreply_port	LAST_SYSCALL_IPCPORT + 4
#define guard_credential_port	LAST_SYSCALL_IPCPORT + 5
#define guard_authority_port	LAST_SYSCALL_IPCPORT + 6
#define SpamFree_reserved_port 	LAST_SYSCALL_IPCPORT + 7
#define ipctest_reserved_port 	LAST_SYSCALL_IPCPORT + 8
#define default_switch_port	LAST_SYSCALL_IPCPORT + 9

/// The number to start using for dynamically assigned ports
//  (MUST be higher than all of the reserved ports, of course)
#define FIRST_DYNAMIC_IPCPORT LAST_SYSCALL_IPCPORT + 10

/// The end of the range of valid port numbers, to catch bugs
#define LAST_IPCPORT FIRST_DYNAMIC_IPCPORT + 1024

enum NexusSyscalls {
  SYS_NPANIC,

#define FIRST_IPC_TABLE_SYSCALL (SYS_IPC_Invoke_CMD)
  SYS_IPC_Invoke_CMD = 11000,
  SYS_IPC_InvokeSys_CMD, // syscall variant. Identical to IPC_Call, except does not set IPC_errno on exit.
  SYS_IPC_RecvCall_CMD,
  SYS_IPC_RecvCallAndFork_CMD,
  SYS_IPC_CallReturn_CMD,
  SYS_IPC_TransferFrom_CMD,
  SYS_IPC_TransferTo_CMD,
  SYS_IPC_AsyncReceive_CMD,
  SYS_IPC_AsyncDone_sys_CMD,
  SYS_IPC_AsyncSend_CMD,
#define LAST_IPC_TABLE_SYSCALL (SYS_IPC_AsyncSend_CMD)

  SYS_IPC_BindRequest_CMD,
  SYS_IPC_CloseConnection_CMD,
  SYS_IPC_CheckCap_CMD,

  // Interposition agent system calls
  SYS_IPC_Wrap_CMD,

  /* Begin place holders for removed syscalls */
  SYS_IPC_Null_CMD_PH,

  SYS_IPC_TimeInterrupt_CMD_PH,

  SYS_IPC_PeekUser_CMD_PH,
  SYS_IPC_PokeUser_CMD_PH,
  SYS_IPC_PServer_CMD_PH,
  SYS_IPC_PClient_CMD_PH,
  /* End placeholders for removed syscalls */

  SYS_IPC_GetMyIPD_ID_CMD,
  SYS_IPC_CreatePort_CMD,
  SYS_IPC_DestroyPort_CMD,
  
  SYS_IPC_UnregisterName_CMD_deprecated,
  SYS_IPC_RegisterName_CMD_deprecated,
  SYS_IPC_Lookup_CMD_deprecated,

  SYS_IPC_IDL_Test0_CMD_deprecated,
  SYS_IPC_IDL_Test1_CMD_deprecated,
  SYS_IPC_IDL_Test2_CMD_deprecated,

  SYS_IPC_FromElf_CMD, // XXX This should be in IPD.sc
  SYS_IPC_Exec_CMD, // XXX This should be in IPD.sc

  SYS_IPC_SetFirstUserIPCPort_CMD,
  SYS_IPC_GetFirstUserIPCPort_CMD,

  SYS_IPC_PortHandle_to_PortNum_CMD,
  SYS_IPC_IPD_GetName_CMD,
  SYS_IPC_Send_CMD,
  SYS_IPC_Recv_CMD,
  SYS_IPC_RecvFrom_CMD,

  SYS_LabelStore_Store_Create_CMD = 12000,
  SYS_LabelStore_Store_Delete_CMD,
  SYS_LabelStore_Store_Set_Policy_CMD,
  SYS_LabelStore_Label_Create_CMD,
  SYS_LabelStore_Label_Copy_CMD,
  SYS_LabelStore_Label_Delete_CMD,
  SYS_LabelStore_Label_Externalize_CMD,
  SYS_LabelStore_Label_Internalize_CMD,
  SYS_LabelStore_Label_GetName_CMD,
  SYS_LabelStore_Label_Read_CMD,
  SYS_LabelStore_Nexus_Label_CMD,
  SYS_LabelStore_Nexus_Get_Label_CMD,
  SYS_LabelStore_Get_IPD_Name_CMD,
  SYS_LabelStore_Sign_CMD,

  SYS_pci_enable_device_internal_CMD = 17000, 
  SYS_pci_disable_device_internal_CMD,
  SYS_pci_set_dma_mask_internal_CMD,
  SYS_pci_set_drvdata_internal_CMD,
  
  SYS_pci_request_regions_internal_CMD,
  SYS_pci_release_regions_internal_CMD,

  SYS_pci_write_config_dword_internal_CMD,
  SYS_pci_write_config_word_internal_CMD,
  SYS_pci_write_config_byte_internal_CMD,
  SYS_pci_read_config_dword_internal_CMD,
  SYS_pci_read_config_word_internal_CMD,
  SYS_pci_read_config_byte_internal_CMD,

  SYS_pci_Probe_CMD,
  SYS_pci_CopyFromHandle_CMD,

  SYS_Profile_Enable_CMD = 19000,
  SYS_Profile_ReadSamples_CMD,
  SYS_Profile_Dump_CMD,

  SYS_Mem_GetPages_CMD = 20000,
  SYS_Mem_GetPhysicalAddress_CMD,
  SYS_Mem_MProtect_CMD,
  SYS_Mem_FreePages_CMD,
  SYS_Mem_Brk_CMD,

  SYS_Net_GetMyIP_CMD = 21000,
  SYS_Net_GetServerIP_CMD,
  SYS_Net_GetServerPort_CMD,
  SYS_Net_set_l2sec_key_CMD,
  SYS_Net_add_mac_CMD,
  SYS_Net_get_mac_CMD,
  SYS_Net_get_ip_CMD,
  SYS_Net_set_ip_CMD,
  SYS_Net_filter_ipport_CMD,
  SYS_Net_filter_arp_CMD,
  SYS_Net_filter_ipproto_CMD,

#if 0
  SYS_VKey_Create_CMD = 22000,
  SYS_VKey_Delete_CMD,
  SYS_VKey_Seal_CMD,
  SYS_VKey_Unseal_CMD,
#endif

  SYS_VKey_Create_CMD = 23000,
  SYS_VKey_Lookup_CMD,
  SYS_VKey_Destroy_CMD,
  SYS_VKey_Rebind_CMD,
  SYS_VKey_Read_CMD,
  SYS_VKey_Write_CMD,

  SYS_Debug_CheckDups_CMD = 100000,
  SYS_Debug_KillCache_CMD,
  SYS_Debug_Null_CMD,

  SYS_Debug_TimeInterrupt_CMD,

  SYS_Debug_PeekUser_CMD,
  SYS_Debug_PokeUser_CMD,
  SYS_Debug_PServer_CMD,
  SYS_Debug_PClient_CMD,
  SYS_Debug_FPUDebug_CMD,
  SYS_Debug_PagesUsed_CMD,

  SYS_Debug_ForkDelay_CMD,
  SYS_Debug_RecvCallDelay_CMD,

  SYS_Debug_BindSerializeOrder_CMD,

  SYS_Debug_ThreadCheck_CMD,
  SYS_Debug_printk_red_CMD,
  SYS_Debug_printk_msg_CMD,

  SYS_Debug_RegressionLog_append_CMD_deprecated,
  SYS_Debug_RegressionLog_getDataLen_CMD_deprecated,
  SYS_Debug_RegressionLog_getData_CMD_deprecated,
  SYS_Debug_RegressionLog_clear_CMD_deprecated,

  SYS_Debug_CleanCount_get_CMD,
  SYS_Debug_CleanCount_clear_CMD,

  SYS_Debug_KillLog_getLen_CMD,
  SYS_Debug_KillLog_getEntry_CMD,
  SYS_Debug_KillLog_clear_CMD,

  SYS_Debug_GetTiming_CMD,
  SYS_Debug_KernelTftp_CMD,
  SYS_Debug_DumpPageUtilization_CMD,

  SYS_Debug_get_ipc_counters_CMD,
  SYS_Debug_cancel_shell_wait_CMD,

  SYS_Debug_TransferUser_CMD,
  SYS_Debug_SchedRecord_CMD,
  SYS_Debug_guard_chgoal_CMD,
  SYS_Debug_guard_chproof_CMD,

  /* Thread */
  SYS_Thread_Yield_CMD = 32000,
  SYS_Thread_Exit_CMD,
  SYS_Thread_Fork_CMD,
  SYS_Thread_USleep_CMD,
  SYS_Thread_ForkReserve_CMD,
  SYS_Thread_Block_CMD,
  SYS_Thread_SetInterrupt_CMD,
  SYS_Thread_Unblock_CMD,
  SYS_Thread_GetProcessID_CMD,
  SYS_Thread_GetID_CMD,
  SYS_Thread_CancelSleep_CMD,
  SYS_Thread_Kill_CMD,
  SYS_Thread_KillAll_CMD,
  // Nexus support for glibc-style fast access to TLS state
  SYS_Thread_SetMyTCB_CMD,
  SYS_Thread_UnlockAndUSleep_CMD,
  SYS_Thread_RegisterTrap_CMD,
  SYS_Thread_RegisterWatchpoint_CMD,
  SYS_Thread_UnRegisterWatchpoint_CMD,
  SYS_Thread_GetCycles_CMD,
  SYS_Thread_GetIPDIdentity_CMD,
  SYS_Thread_Notify_CMD,
  SYS_Thread_Reboot_CMD,
  SYS_Thread_SetSchedPolicy_CMD,
  SYS_Thread_ForkProcess_CMD,

  /* Console */
  SYS_Console_PrintChar_CMD = 33000,
  SYS_Console_Blit_Init_CMD,
  SYS_Console_Blit_Frame_CMD,
  SYS_Console_Kbd_Init_CMD,
  SYS_Console_GetLine_CMD_deprecated, // Renamed to Console_GetData
  SYS_Console_HasLine_CMD,

  SYS_Console_GetData_CMD,
  SYS_Console_SetInputMode_CMD,

  SYS_Console_MapFrameBuffer_CMD,
  SYS_Console_Blit_Frame_Native_CMD,

  SYS_Console_GetKeymapEntry_CMD,

  SYS_Console_Mouse_Init_CMD,
  SYS_Console_Mouse_Poll_CMD,
  SYS_Console_Mouse_Read_CMD,
  SYS_Console_Mouse_SetProtocol_CMD,

  SYS_Console_SetPrintState_CMD,

  SYS_Console_UnmapFrameBuffer_CMD,
  SYS_Console_PrintString_CMD,

  /* Audio */
  SYS_Audio_Init_CMD = 34000,
  SYS_Audio_SetRate_CMD,
  SYS_Audio_Write_CMD,
  SYS_Audio_Ioctl_CMD,

  /* Log */
  SYS_Log_PrintChar_CMD = 35000,
  SYS_Log_Dump_CMD,

  SYS_Log_Create_CMD,
  SYS_Log_GetLen_CMD,
  SYS_Log_GetData_CMD,
  SYS_Log_GetClear_CMD,
  SYS_Log_GetCreate_CMD,
  SYS_Log_Clear_CMD,


  /* KernelFS */
  SYS_KernelFS_TFTP_Get_CMD = 36000,
  SYS_KernelFS_TFTP_Put_CMD,
  SYS_KernelFS_Cache_Add_CMD,
  SYS_KernelFS_GetFileLen_CMD,
  SYS_KernelFS_SetRoot_CMD,
  SYS_KernelFS_SetEnv_CMD,

  /* Time */
  SYS_Time_gettimeofday_CMD = 37000,
  SYS_Time_set_ntp_offset_CMD,
  SYS_Time_GetUSECPERTICK_CMD,
  SYS_Time_GetTSCCONST_CMD,

  /* Crypto */
  SYS_Crypto_GetRandBytes_CMD = 40000,

  /* VDIR */
  SYS_VDIR_Create_CMD = 41000,
  SYS_VDIR_Lookup_CMD,
  SYS_VDIR_Destroy_CMD,
  SYS_VDIR_Rebind_CMD,
  SYS_VDIR_Write_CMD,
  SYS_VDIR_Read_CMD,

  /* Syscalls */
  SYS_Syscall_Wrap_CMD = 42000,

  /* SMR */
  SYS_SMR_Get_Bitmap_CMD = 43000,
  SYS_SMR_Remap_RO_CMD,
  SYS_SMR_Unmap_RO_CMD,
  SYS_SMR_RegisterTrap_CMD,

  /* Attestation */
  SYS_Attestation_GetPubek_CMD = 44000,
  SYS_Attestation_TakeOwnership_CMD,

  /* Tap-based interposition */
  SYS_Tap_SetIPDNotificationPort_CMD = 45000,
  SYS_Tap_AddPattern_CMD,
  SYS_Tap_DeletePattern_CMD,

  SYS_IPD_FromElf_CMD = 46000,

  /* sealing / unsealing */
  SYS_nrk_create_CMD = 47000,
  SYS_nrk_seal_CMD,
  SYS_nrk_unseal_CMD,
  SYS_nrk_reseal_CMD,

  SYS_nsk_create_CMD,
  SYS_nsk_certify_x509_CMD,
  SYS_nsk_request_tpm_certification_CMD,
  SYS_nsk_unlock_tpm_certification_CMD,
  SYS_nsk_or_nrk_request_nexus_certification_CMD,
  SYS_nsk_set_local_CMD,

  SYS_ddrm_sys_read_CMD = 48000,
  SYS_ddrm_sys_write_CMD,
  SYS_ddrm_sys_wait_for_intr_CMD,
  SYS_ddrm_sys_allocate_memory_CMD,
  SYS_ddrm_sys_setup_interrupts_CMD,
  SYS_ddrm_sys_hint_intr_done_CMD,

#ifdef __NEXUSXEN__

  /* Xen */
  SYS_Xen_PreInit_CMD = 49000,
  SYS_Xen_AllocPages_CMD,
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
  SYS_Xen_H_mmuext_op_CMD = 49500,
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

  SYS_BIRTH, /* should not be called from user */
};

struct NexusCallArgs {
  unsigned int arg2;
  unsigned int arg3;
};
struct NexusCall3Args {
  unsigned int arg2;
  unsigned int arg3;
  unsigned int arg4;
};

struct UserNetdev {
  char name[64];
  char mac[6];
} __attribute__((packed));

#ifndef TCPA_HASH_SIZE
#define TCPA_HASH_SIZE (20)
#endif

struct Vkeyargs{
  unsigned int handle;
  unsigned char *udata;
  int datalen;
  unsigned char *dest;
  int destlen;
  char *lfbuf;
  int lflen;
} __attribute__((packed));
struct VDIRargs{
  unsigned int handle;
  unsigned char *data;
  int datalen;
  char *lfbuf;
  int lflen;
} __attribute__((packed));

struct VDIRcargs{
  char *name;
  int namelen;
  unsigned int labels[3];
  int labelsizes[3];
} __attribute__((packed));

struct Remapargs{
  unsigned int rwvaddr;
  int size;
  int suboffset;
  int sublen;
} __attribute__((packed));


#define OID_UNREGISTER (0)

struct VKeyOp{
  unsigned int data;
  int len;
  unsigned int ac; /* or LF_OID, for *_lf functions */
  unsigned int pw;
  unsigned int output;
} __attribute__((packed));

// Nexus IOCTL interface, for use in XenLinux

#define NIOC_NEXUSCALL (1)
struct NIOC_Args {
  int syscallno;
  unsigned long arg1,arg2,arg3, arg4, arg5;
};


enum SchedTypes {
  SCHEDTYPE_ROUNDROBIN = 1,
  SCHEDTYPE_INTERVAL = 2,
};

struct SchedTypeInfo_Interval {
  int numerator; // ratio, unit of 1/1000
};

#endif // _SYSCALLS_H_
