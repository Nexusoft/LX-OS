#include <nexus/defs.h>
#include <libtcpa/tpm.h>
#include <libtcpa/keys.h>
#include <libtcpa/tcpa.h>
#include <libtcpa/buildbuff.h>

/****************************************************************************/
/*                                                                          */
/*  Take Ownership of the TPM                                               */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* ownpass   is the authorization data (password) for the new owner         */
/* dsrkpass  is the authorization data (password) for the new root key      */
/*           both authorization values MUST be 20 bytes long                */
/* key       a pointer to a keydata structure to receive the SRK public key */
/*           or NULL if this information is not required                    */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_TakeOwnership(int oencsize, unsigned char *ownerencr,
			   int sencsize, unsigned char *srkencr)
{
  unsigned char *opass = get_opass();
  int oencdatasize = htonl(oencsize);
  int sencdatasize = htonl(sencsize);

    unsigned char take_owner_fmt[] = "00 c2 T l s @ @ % L % 00 %";
    uint32_t srkparamsize;      /* SRK parameter buffer size */

    KeyData srk;                /* key info for SRK */
    uint32_t ret = 0;
    uint32_t command;           /* command ordinal */
    uint16_t protocol;          /* protocol ID */
    uint32_t authhandle;        /* auth handle (from OIAPopen) */


    unsigned char *nonceeven = (unsigned char *)galloc(TCPA_HASH_SIZE);
    unsigned char *nonceodd = (unsigned char *)galloc(TCPA_HASH_SIZE);     /* odd nonce */
    unsigned char *authdata = (unsigned char *)galloc(TCPA_HASH_SIZE);     /* auth data */
    unsigned char *srk_param_buff = (unsigned char *)galloc(TCPA_SRK_PARAM_BUFF_SIZE);
    unsigned char *tcpadata = (unsigned char *)galloc(TCPA_MAX_BUFF_SIZE); /* request/response buffer */


    /* set up command and protocol values for TakeOwnership function */
    command = htonl(0x0d);
    protocol = htons(0x05);

    /* fill the SRK-params key structure */
    printk_red("%s:%d:tcpa version %d %d %d %d\n", __FILE__, __LINE__, TCPA_VERSION[0], TCPA_VERSION[1], TCPA_VERSION[2], TCPA_VERSION[3]);
    memcpy(srk.version, TCPA_VERSION, TCPA_VERSION_SIZE);
    srk.keyusage = 0x0011;      /* Storage Key */
    srk.keyflags = 0;
    srk.authdatausage = 0x01;   /* Key usage must be authorized */
    srk.privkeylen = 0;         /* private key not specified here */
    srk.pub.algorithm = TCPA_ALG_RSA;
    srk.pub.encscheme = TCPA_ES_RSAESOAEP_SHA1_MGF1;
    srk.pub.sigscheme = TCPA_SS_NONE;
    srk.pub.keybitlen = RSA_MODULUS_BIT_SIZE;
    srk.pub.numprimes = RSA_NUMPRIMES;
    srk.pub.expsize = 0;        /* defaults to 0x010001 */
    srk.pub.keylength = 0;      /* not used here */
    srk.pub.pcrinfolen = 0;     /* not used here */
    //XXX link srk to nexus + ownerapp pcrs

    /* convert to a memory buffer */
    srkparamsize = BuildKey(srk_param_buff, &srk);
    /* generate the odd nonce */
    ret = RAND_bytes(nonceodd, TCPA_NONCE_SIZE);
    if (ret != 1)
      goto done;
    /* initiate the OIAP protocol */
    ret = TPM_OIAP(&authhandle, nonceeven);
    if (ret)
      goto done;

    /* calculate the Authorization Data */
    ret = authhmac(authdata, opass, TCPA_HASH_SIZE, nonceeven,
                   nonceodd, 0, 4, &command, 2,
                   &protocol, 4, &oencdatasize,
                   ntohl(oencdatasize), ownerencr, 4,
                   &sencdatasize, ntohl(sencdatasize), srkencr,
                   srkparamsize, srk_param_buff, 0, 0);
    if (ret < 0) {
        TPM_Terminate_Handle(authhandle);
	goto done;	
    }
    /* insert all the calculated fields into the request buffer */
    ret = buildbuff(take_owner_fmt, tcpadata,
                    command,
                    protocol,
                    ntohl(oencdatasize),
                    ownerencr,
                    ntohl(sencdatasize),
                    srkencr,
                    srkparamsize,
                    srk_param_buff,
                    authhandle,
                    TCPA_HASH_SIZE, nonceodd, TCPA_HASH_SIZE, authdata);
    if (ret <= 0) {
        TPM_Terminate_Handle(authhandle);
	goto done;
    }
    ret = TPM_Transmit(tcpadata, "Take Ownership");
    TPM_Terminate_Handle(authhandle);
    if (ret != 0)
	goto done;
    /* check the response HMAC */
    srkparamsize = KeySize(tcpadata + TCPA_DATA_OFFSET);
    ret = checkhmac1(tcpadata, command, nonceodd, opass,
                     TCPA_HASH_SIZE, srkparamsize, TCPA_DATA_OFFSET, 0, 0);

 done:
    gfree(nonceeven);
    gfree(nonceodd);
    gfree(authdata);
    gfree(srk_param_buff);
    gfree(tcpadata);

    return ret;
}


