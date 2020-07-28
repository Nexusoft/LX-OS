/****************************************************************************/
/*                                                                          */
/*  TPM.H  03 Apr 2003                                                     */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/
#ifndef TPM_H
#define TPM_H

#define TCPA_MAX_BUFF_SIZE              4096

extern unsigned char tcpa_version_buf_g[];
#define TCPA_VERSION_SIZE (4)
#define TCPA_VERSION (tcpa_version_buf_g)

//XXX move to kvkey.h
#define RSA_NUMPRIMES                   (2)
#define RSA_MAX_MODULUS_BYTE_SIZE       (256)
#define RSA_MODULUS_BYTE_SIZE           (256)
#define RSA_MODULUS_BIT_SIZE  ( RSA_MODULUS_BYTE_SIZE * 8 )
#define RSA_PRIVEXP_BYTE_SIZE           (256)
#define RSA_DEFAULT_EXPONENT_LONG       (65537)
extern unsigned char rsa_default_exponent_array_g[];
#define RSA_EXPONENT_BYTE_SIZE          (3)
#define RSA_DEFAULT_EXPONENT_ARRAY       (rsa_default_exponent_array_g)
#define RSA_MAX_CLEAR_SIZE              (214)
#define RSA_ENC_SIZE RSA_MODULUS_BYTE_SIZE

#define TCPA_HASH_SIZE                  (20)
#define TCPA_NONCE_SIZE                 TCPA_HASH_SIZE
#define TCPA_SIG_SIZE                   RSA_MODULUS_BYTE_SIZE
#define TCPA_ENC_SIZE                   (312)

/*XXX specify PCR registers 0-6 but not 1*/
#define TCPA_DEFAULT_PCRS               0x007d
#define TCPA_MAX_PCRINFO_SIZE           (256)

#define TCPA_PARAMSIZE_OFFSET           2
#define TCPA_ORDINAL_OFFSET             6
#define TCPA_RETURN_OFFSET		6
#define TCPA_DATA_OFFSET                10
#define TCPA_SRK_PARAM_BUFF_SIZE        256

/* algorithms that may be supported by TPM */
#define TCPA_ALG_RSA  0x00000001
#define TCPA_ALG_DES  0x00000002
#define TCPA_ALG_3DES 0X00000003
#define TCPA_ALG_SHA  0x00000004
#define TCPA_ALG_HMAC 0x00000005
#define TCPA_ALG_AES  0x00000006

/* encryption schemes for RSA */
#define TCPA_ES_NONE                0x0001
#define TCPA_ES_RSAESPKCSv15        0x0002
#define TCPA_ES_RSAESOAEP_SHA1_MGF1 0x0003

/* signature schemes for RSA */
#define TCPA_SS_NONE                0x0001
#define TCPA_SS_RSASSAPKCS1v15_SHA1 0x0002
#define TCPA_SS_RSASSAPKCS1v15_DER  0x0003

#define MAXPCRINFOLEN ( (TCPA_HASH_SIZE * 2) + 2 + TCPA_PCR_MASK_SIZE )

/* Command Tags */
#define TPM_TAG_RQU_COMMAND             0x00C1
#define TPM_TAG_RQU_AUTH1_COMMAND       0x00C2
#define TPM_TAG_RQU_AUTH2_COMMAND       0x00C3
#define TPM_TAG_RSP_COMMAND             0x00C4
#define TPM_TAG_RSP_AUTH1_COMMAND       0x00C5
#define TPM_TAG_RSP_AUTH2_COMMAND       0x00C6

/* Entity type values */
#define TPM_ET_KEYHANDLE 0x0001      
#define TPM_ET_OWNER 0x0002      
#define TPM_ET_DATA 0x0003      
#define TPM_ET_SRK 0x0004      
#define TPM_ET_KEY 0x0005     
#define TPM_ET_REVOKE 0x0006      
#define TPM_ET_DEL_BLOB 0x0007      
#define TPM_ET_DEL_ROW 0x0008      
#define TPM_ET_DEL_KEY 0x0009     
#define TPM_ET_COUNTER 0x000A      
#define TPM_ET_NV 0x000B      

/* Key types */
#define TPM_KEY_STORAGE 0x0011
#define TPM_KEY_SIGNING 0x0010
#define TPM_KEY_BIND 0x0014

/* reserved key handles */
#define TPM_KH_SRK 0x40000000         // The handle points to the SRK
#define TPM_KH_OWNER 0x40000001       // The handle points to the TPM Owner
#define TPM_KH_REVOKE 0x40000002      // The handle points to the RevokeTrust value
#define TPM_KH_TRANSPORT 0x40000003   // The handle points to the EstablishTransport static authorization
#define TPM_KH_OPERATOR 0x40000004    // The handle points to the Operator auth
#define TPM_KH_ADMIN 0x40000005       // The handle points to the delegation administration auth
#define TPM_KH_EK 0x40000006          // The handle points to the PUBEK, only usable with TPM_OwnerReadInternalPub

/* payload types */
#define TCPA_PT_ASYM    0x01 // The entity is an asymmetric key
#define TCPA_PT_BIND    0x02 // The entity is bound data
#define TCPA_PT_MIGRATE 0x03 // The entity is a migration blob
#define TCPA_PT_MAINT   0x04 // The entity is a maintenance blob
#define TCPA_PT_SEAL    0x05 // The entity is sealed data



/* Ordinal values */
#define TPM_ORD_ActivateIdentity        0x0000007A
#define TPM_ORD_AuthorizeMigrationKey   0x0000002B
#define TPM_ORD_CertifyKey              0x00000032
#define TPM_ORD_CertifyKey2             0x00000033
#define TPM_ORD_CertifySelfTest         0x00000052
#define TPM_ORD_ChangeAuth              0x0000000C
#define TPM_ORD_ChangeAuthAsymFinish    0x0000000F
#define TPM_ORD_ChangeAuthAsymStart     0x0000000E
#define TPM_ORD_ChangeAuthOwner         0x00000010
#define TPM_ORD_CMK_CreateBlob          0x0000001B
#define TPM_ORD_CMK_CreateKey           0x00000013
#define TPM_ORD_CMK_CreateTicket        0x00000012
#define TPM_ORD_CMK_SetRestrictions     0x0000001C
#define TPM_ORD_ContinueSelfTest        0x00000053
#define TPM_ORD_ConvertMigrationBlob    0x0000002A
#define TPM_ORD_CreateCounter                  0x000000DC
#define TPM_ORD_CreateEndorsementKeyPair       0x00000078
#define TPM_ORD_CreateMaintenanceArchive       0x0000002C
#define TPM_ORD_CreateMigrationBlob            0x00000028
#define TPM_ORD_CreateRevocableEK              0x0000007F
#define TPM_ORD_CreateWrapKey                  0x0000001F
#define TPM_ORD_Delegate_CreateKeyDelegation   0x000000D4
#define TPM_ORD_Delegate_CreateOwnerDelegation 0x000000D5
#define TPM_ORD_Delegate_LoadOwnerDelegation   0x000000D8
#define TPM_ORD_Delegate_Manage                0x000000D2
#define TPM_ORD_Delegate_ReadAuth              0x000000D9
#define TPM_ORD_Delegate_ReadTable             0x000000DB
#define TPM_ORD_Delegate_UpdateVerification    0x000000D1
#define TPM_ORD_Delegate_VerifyDelegation      0x000000D6
#define TPM_ORD_DirRead                        0x0000001A
#define TPM_ORD_DirWriteAuth                   0x00000019
#define TPM_ORD_DisableForceClear              0x0000005E
#define TPM_ORD_DisableOwnerClear              0x0000005C
#define TPM_ORD_DisablePubekRead               0x0000007E
#define TPM_ORD_DSAP                           0x00000011
#define TPM_ORD_EstablishTransport             0x000000E6
#define TPM_ORD_EvictKey                       0x00000022
#define TPM_ORD_ExecuteTransport               0x000000E7
#define TPM_ORD_Extend                         0x00000014
#define TPM_ORD_FieldUpgrade                   0x000000AA
#define TPM_ORD_FlushSpecific                  0x000000BA
#define TPM_ORD_ForceClear                     0x0000005D
#define TPM_ORD_GetAuditDigest                 0x00000085
#define TPM_ORD_GetAuditDigestSigned           0x00000086
#define TPM_ORD_GetAuditEvent                  0x00000082
#define TPM_ORD_GetAuditEventSigned            0x00000083
#define TPM_ORD_GetCapability                  0x00000065
#define TPM_ORD_GetCapabilityOwner             0x00000066
#define TPM_ORD_GetCapabilitySigned            0x00000064
#define TPM_ORD_GetOrdinalAuditStatus          0x0000008C
#define TPM_ORD_GetPubKey                      0x00000021
#define TPM_ORD_GetRandom                      0x00000046
#define TPM_ORD_GetTestResult                  0x00000054
#define TPM_ORD_GetTick                        0x000000F1
#define TPM_ORD_IncrementCounter               0x000000DD
#define TPM_ORD_Init                           0x00000097
#define TPM_ORD_KeyControlOwner         0x00000023
#define TPM_ORD_KillMaintenanceFeature  0x0000002E
#define TPM_ORD_LoadAuthContext         0x000000B7
#define TPM_ORD_LoadContext             0x000000B9
#define TPM_ORD_LoadKey                 0x00000020
#define TPM_ORD_LoadKeyContext          0x000000B5
#define TPM_ORD_LoadMaintenanceArchive  0x0000002D
#define TPM_ORD_LoadManuMaintPub        0x0000002F
#define TPM_ORD_MakeIdentity            0x00000079
#define TPM_ORD_NV_DefineSpace          0x000000CC
#define TPM_ORD_NV_ReadValue            0x000000CF
#define TPM_ORD_NV_ReadValueAuth        0x000000D0
#define TPM_ORD_NV_WriteValue           0x000000CD
#define TPM_ORD_NV_WriteValueAuth       0x000000CE
#define TPM_ORD_OIAP                    0x0000000A
#define TPM_ORD_OSAP                    0x0000000B
#define TPM_ORD_OwnerClear              0x0000005B
#define TPM_ORD_OwnerReadInternalPub    0x00000081
#define TPM_ORD_OwnerReadPubek          0x0000007D
#define TPM_ORD_OwnerSetDisable         0x0000006E
#define TPM_ORD_PCR_Reset               0x000000C8
#define TPM_ORD_PcrRead                 0x00000015
#define TPM_ORD_PhysicalDisable         0x00000070
#define TPM_ORD_PhysicalEnable          0x0000006F
#define TPM_ORD_PhysicalSetDeactivated  0x00000072
#define TPM_ORD_Quote                   0x00000016
#define TPM_ORD_ReadCounter             0x000000DE
#define TPM_ORD_ReadManuMaintPub        0x00000030
#define TPM_ORD_ReadPubek               0x0000007C
#define TPM_ORD_ReleaseCounter          0x000000DF
#define TPM_ORD_ReleaseCounterOwner     0x000000E0
#define TPM_ORD_ReleaseTransportSigned  0x000000E8
#define TPM_ORD_Reset                   0x0000005A
#define TPM_ORD_RevokeTrust             0x00000080
#define TPM_ORD_SaveAuthContext         0x000000B6
#define TPM_ORD_SaveContext             0x000000B8
#define TPM_ORD_SaveKeyContext          0x000000B4
#define TPM_ORD_SaveState               0x00000098
#define TPM_ORD_Seal                    0x00000017
#define TPM_ORD_SelfTestFull            0x00000050
#define TPM_ORD_SetOperatorAuth         0x00000074
#define TPM_ORD_SetOrdinalAuditStatus  0x0000008D
#define TPM_ORD_SetOwnerInstall        0x00000071
#define TPM_ORD_SetOwnerPointer        0x00000075
#define TPM_ORD_SetRedirection         0x0000009A
#define TPM_ORD_SetTempDeactivated     0x00000073
#define TPM_ORD_SetTickType            0x000000F0
#define TPM_ORD_SHA1Complete           0x000000A2
#define TPM_ORD_SHA1CompleteExtend     0x000000A3
#define TPM_ORD_SHA1Start              0x000000A0
#define TPM_ORD_SHA1Update             0x000000A1
#define TPM_ORD_Sign                   0x0000003C
#define TPM_ORD_Startup                0x00000099
#define TPM_ORD_StirRandom             0x00000047
#define TPM_ORD_TakeOwnership          0x0000000D
#define TPM_ORD_Terminate_Handle       0x00000096
#define TPM_ORD_TickStampBlob          0x000000F2
#define TPM_ORD_UnBind                 0x0000001E
#define TPM_ORD_Unseal                 0x00000018

/* Return Codes */
#define TPM_BASE 0x0
#define TPM_AUTHFAIL (TPM_BASE + 1)
#define TPM_BADINDEX           (TPM_BASE + 2)
#define TPM_BAD_PARAMETER      (TPM_BASE + 3)
#define TPM_AUDITFAILURE       (TPM_BASE + 4)
#define TPM_CLEAR_DISABLED     (TPM_BASE + 5)
#define TPM_DEACTIVATED        (TPM_BASE + 6)
#define TPM_DISABLED           (TPM_BASE + 7)
#define TPM_DISABLED_CMD       (TPM_BASE + 8)
#define TPM_FAIL               (TPM_BASE + 9)
#define TPM_BAD_ORDINAL        (TPM_BASE + 10)
#define TPM_INSTALL_DISABLED   (TPM_BASE + 11)
#define TPM_INVALID_KEYHANDLE  (TPM_BASE + 12)
#define TPM_KEYNOTFOUND        (TPM_BASE + 13)
#define TPM_INAPPROPRIATE_ENC  (TPM_BASE + 14)
#define TPM_MIGRATEFAIL        (TPM_BASE + 15)
#define TPM_INVALID_PCR_INFO   (TPM_BASE + 16)
#define TPM_NOSPACE            (TPM_BASE + 17)
#define TPM_NOSRK              (TPM_BASE + 18)
#define TPM_NOTSEALED_BLOB     (TPM_BASE + 19)
#define TPM_OWNER_SET          (TPM_BASE + 20)
#define TPM_RESOURCES          (TPM_BASE + 21)
#define TPM_SHORTRANDOM        (TPM_BASE + 22)
#define TPM_SIZE               (TPM_BASE + 23)
#define TPM_WRONGPCRVAL        (TPM_BASE + 24)
#define TPM_BAD_PARAM_SIZE     (TPM_BASE + 25)
#define TPM_SHA_THREAD         (TPM_BASE + 26)
#define TPM_SHA_ERROR          (TPM_BASE + 27)
#define TPM_FAILEDSELFTEST     (TPM_BASE + 28)
#define TPM_AUTH2FAIL          (TPM_BASE + 29)
#define TPM_BADTAG             (TPM_BASE + 30)
#define TPM_IOERROR            (TPM_BASE + 31)
#define TPM_ENCRYPT_ERROR      (TPM_BASE + 32)
#define TPM_DECRYPT_ERROR      (TPM_BASE + 33)
#define TPM_INVALID_AUTHHANDLE (TPM_BASE + 34)
#define TPM_NO_ENDORSEMENT     (TPM_BASE + 35)
#define TPM_INVALID_KEYUSAGE   (TPM_BASE + 36)
#define TPM_WRONG_ENTITYTYPE   (TPM_BASE + 37)
#define TPM_INVALID_POSTINIT   (TPM_BASE + 38)
#define TPM_INAPPROPRIATE_SIG  (TPM_BASE + 39)
#define TPM_BAD_KEY_PROPERTY   (TPM_BASE + 40)
#define TPM_BAD_MIGRATION          (TPM_BASE + 41)
#define TPM_BAD_SCHEME             (TPM_BASE + 42)
#define TPM_BAD_DATASIZE           (TPM_BASE + 43)
#define TPM_BAD_MODE               (TPM_BASE + 44)
#define TPM_BAD_PRESENCE           (TPM_BASE + 45)
#define TPM_BAD_VERSION            (TPM_BASE + 46)
#define TPM_NO_WRAP_TRANSPORT      (TPM_BASE + 47)
#define TPM_AUDITFAIL_UNSUCCESSFUL (TPM_BASE + 48)
#define TPM_AUDITFAIL_SUCCESSFUL   (TPM_BASE + 49)
#define TPM_NOTRESETABLE           (TPM_BASE + 50)
#define TPM_NOTLOCAL               (TPM_BASE + 51)
#define TPM_BAD_TYPE               (TPM_BASE + 52)
#define TPM_INVALID_RESOURCE       (TPM_BASE + 53)
#define TPM_NOTFIPS                (TPM_BASE + 54)
#define TPM_INVALID_FAMILY         (TPM_BASE + 55)
#define TPM_NO_NV_PERMISSION       (TPM_BASE + 56)
#define TPM_REQUIRES_SIGN          (TPM_BASE + 57)
#define TPM_KEY_NOTSUPPORTED       (TPM_BASE + 58)
#define TPM_AUTH_CONFLICT          (TPM_BASE + 59)
#define TPM_AREA_LOCKED            (TPM_BASE + 60)
#define TPM_BAD_LOCALITY           (TPM_BASE + 61)
#define TPM_READ_ONLY              (TPM_BASE + 62)
#define TPM_PER_NOWRITE            (TPM_BASE + 63)
#define TPM_FAMILYCOUNT            (TPM_BASE + 64)
#define TPM_WRITE_LOCKED           (TPM_BASE + 65)
#define TPM_BAD_ATTRIBUTES         (TPM_BASE + 66)
#define TPM_INVALID_STRUCTURE      (TPM_BASE + 67)
#define TPM_KEY_OWNER_CONTROL      (TPM_BASE + 68)
#define TPM_BAD_COUNTER            (TPM_BASE + 69)
#define TPM_NOT_FULLWRITE          (TPM_BASE + 70)
#define TPM_CONTEXT_GAP            (TPM_BASE + 71)
#define TPM_MAXNVWRITES            (TPM_BASE + 72)
#define TPM_NOOPERATOR             (TPM_BASE + 73)
#define TPM_RESOURCEMISSING        (TPM_BASE + 74)
#define TPM_DELEGATE_LOCK          (TPM_BASE + 75)
#define TPM_DELEGATE_FAMILY        (TPM_BASE + 76)
#define TPM_DELEGATE_ADMIN         (TPM_BASE + 77)
#define TPM_TRANSPORT_EXCLUSIVE    (TPM_BASE + 78)
#define TPM_OWNER_CONTROL (TPM_BASE + 79)
#define TPM_DAA_RESOURCES (TPM_BASE + 80)

#endif
