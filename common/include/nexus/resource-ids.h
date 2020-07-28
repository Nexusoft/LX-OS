#ifndef _RESOURCE_IDS_H_
#define _RESOURCE_IDS_H_

#define LABELID_DATALEN (16)
#define LABELID_KEYLEN (16)

typedef int KernelResourceType;
typedef int KernelInterfaceType;
typedef int KernelResourceID;

#define KRESOURCE_TEST (0)
#define KIF_TEST_TEST (1)

#define KRESOURCE_IPD 	(1)
	#define KIF_IPD_WRAP 	(0)
	#define KIF_IPD_FGETS 	(1)
	#define KIF_IPD_NULL 	(2)
	#define KIF_IPD_NUM 	(3)

#define KRESOURCE_IPC 	(2)
	#define KIF_IPC_SEND 	(0)
	#define KIF_IPC_NUM 	(1)


#ifdef __NEXUSKERNEL__
// CheckModify hook is called when kernel wants to check whether
// ACL on a particular resource is allowed to be modified.

struct IPD;

enum AddDelOperation {
  ACL_OP_ADD_NOBACKINVALIDATE,
  ACL_OP_ADD_BACKINVALIDATE,
  ACL_OP_DEL,
};

typedef int (*CheckModify)(KernelResourceType res, 
			   KernelInterfaceType iftype,
			   void *res_ctx,
			   KernelResourceID resID, struct IPD *ipd,
			   enum AddDelOperation op);
typedef int (*AddResourceAccess)(KernelResourceType res, 
				 KernelInterfaceType iftype,
				 void *res_ctx,
				 KernelResourceID resID, struct IPD *ipd);
typedef int (*RevokeResourceAccess)(KernelResourceType res, 
				    KernelInterfaceType iftype,
				    void *res_ctx,
				    KernelResourceID resID, struct IPD *ipd);

// used by other modules to register an OpCap-protected interface
void Register_LabelACL_Interface(KernelResourceType res, 
				 KernelInterfaceType iftype,
				 void *res_type_check_ctx,
				 CheckModify check_func,
				 AddResourceAccess add_func,
				 RevokeResourceAccess revoke_func);
#endif

#endif // _RESOURCE_IDS_H_
