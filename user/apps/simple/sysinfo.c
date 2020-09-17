/** NexusOS: system information utility */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <tpmfunc.h>
#include <openssl/rand.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <nexus/test.h>
#include <nexus/Net.interface.h>
#include <nexus/Thread.interface.h>

#define DEBUG 0
#define cpuid(func,ax,bx,cx,dx)\
    __asm__ __volatile__ ("cpuid":\
    "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

/* taken from libtpm: tpm_utils/tpm_demo.c */
uint32_t TPM_GetCapability_Pcrs(uint32_t * pcrs)
{
    unsigned char blob[4096] = {
        0, 193,     /* TPM_TAG_RQU_COMMAND */
        0, 0, 0, 22,    /* blob length, bytes */
        0, 0, 0, 101,   /* TPM_ORD_GetCapability */
        0, 0, 0, 5, /* TCPA_CAP_PROPERTY */
        0, 0, 0, 4, /* SUB_CAP size, bytes */
        0, 0, 1, 1  /* TCPA_CAP_PROP_PCR */
    };
    uint32_t ret;
    ret = TPM_Transmit(blob, "TPM_GetCapability_Pcrs");
    if (ret)
        return (ret);
    *pcrs = ntohl(*(uint32_t *) (blob + 14));
    return (ret);
}

uint32_t TPM_GetCapability_Slots(uint32_t * slots)
{
        unsigned char blob[4096] = {
                0, 193,         /* TPM_TAG_RQU_COMMAND */
                0, 0, 0, 22,    /* blob length, bytes */
                0, 0, 0, 101,   /* TPM_ORD_GetCapability */
                0, 0, 0, 5,     /* TCPA_CAP_PROPERTY */
                0, 0, 0, 4,     /* SUB_CAP size, bytes */
                0, 0, 1, 4      /* TCPA_CAP_PROP_SLOTS */
        };
        uint32_t ret;
        ret = TPM_Transmit(blob, "TPM_GetCapability_Slots");
        if (ret)
                return (ret);
        *slots = ntohl(*(uint32_t *) (blob + 14));
        return (ret);
}

uint32_t TPM_GetCapability_Version(int *major, int *minor, int *version, int *rev)
{
        unsigned char blob[4096] = {
                0, 193,         /* TPM_TAG_RQU_COMMAND */
                0, 0, 0, 18,    /* blob length, bytes */
                0, 0, 0, 101,   /* TPM_ORD_GetCapability */
                0, 0, 0, 6,     /* TCPA_CAP_VERSION */
                0, 0, 0, 0      /* no sub capability */
        };
        uint32_t ret;
        ret = TPM_Transmit(blob, "TPM_GetCapability_Version");
        if (ret)
                return (ret);
        *major = (int) (blob[14]);
        *minor = (int) (blob[15]);
        *version = (int) (blob[16]);
        *rev = (int) (blob[17]);
        return (ret);
}

/*
 * This program gets a bunch of information about the system (CPU and TPM info)
 * and prints out valid NAL statements to be fed into a Python X.509 certificate
 * creation program.
 */
int main(int argc, char **argv)
{
    char filepath[128];
    char sysinfo[14][1024];
    char *sysinfoptrs[14];
    int ret;
    char ipaddr[4];
    unsigned int a,b,c,d;
    int i;

    printf("[sysinfo] up\n");
    // get the number of available PCRs in the TPM
    uint32_t pcrs;
    if (TPM_GetCapability_Pcrs(&pcrs))
        ReturnError(1, "no TPM found. Aborting");

    // get the number of available key slots in the TPM
    uint32_t slots;
    if (TPM_GetCapability_Slots(&slots))
        ReturnError(1, "Error at getslots");

    // get the TPM's version numbers
    int major, minor, version, rev;
    if (TPM_GetCapability_Version(&major, &minor, &version, &rev))
        ReturnError(1, "Error at get version");

    // Sysinfo includes 
    // 1. cpuinfo vendor string
    // 2. num cores
    // 3. clockspeed frequency+units
    // 4. stepping number
    // 5. model number
    // 6. family number
    // 7. processor type
    // 8. cache_size
    // 9. SSE
    // 10. SSE2
    // 11. SSE3
    // 12. Quoted hash of pcrs
    // 13. Pubkey for tpm quote

    /*
     * Cpuid function 0 returns the Vendor String
     * It is a 12 character string
     * b holds the first 4 characters
     * d holds the next 4 characters
     * c holds the last 4 characters
     * a holds the maximum number of functions (the value we pass into cpuid) that the CPU recognizes
     */
    a=0; b=0; c=0; d=0;
    cpuid(0,a,b,c,d);
    sprintf(sysinfo[0],"cpu.vendor = ");
    sprintf(sysinfo[0]+13,"%c%c%c%c",(char)b,(char)(b>>8),(char)(b>>16),(char)(b>>24));
    sprintf(sysinfo[0]+17,"%c%c%c%c",(char)d,(char)(d>>8),(char)(d>>16),(char)(d>>24));
    sprintf(sysinfo[0]+21,"%c%c%c%c",(char)c,(char)(c>>8),(char)(c>>16),(char)(c>>24));

    /*
     * Cpuid function 4 returns cache/cores information I think
     * eax (a):
     * Bits 26-31: Number of cores (+1 to value for the result)
     */
    a=0; b=0; c=0; d=0;
    cpuid(4,a,b,c,d);
    sprintf(sysinfo[1],"cpu.cores = %d",((a>>26)&63)+1);

    /* CPU Clock speed
     * function #: 80000004H
     * ecx (c) contains frequency
     * edx (d) contains units
     */

    a=0; b=0; c=0; d=0;
    cpuid(0x80000004,a,b,c,d);
    sprintf(sysinfo[2],"cpu.speed = ");
    sprintf(sysinfo[2]+12,"%c%c%c%c",(char)c,(char)(c>>8),(char)(c>>16),(char)(c>>24));
    sprintf(sysinfo[2]+16,"%c%c%c%c",(char)d,(char)(d>>8),(char)(d>>16),(char)(d>>24));
    
    /*
     * Cpuid function 1 returns some processor information
     * eax (a):
     * Bits 0-3: Stepping number
     * Bits 4-7: Model number
     * Bits 8-11: Family numbers
     * Bits 12-13: Processor Type
     * ebx (b):
     * Bits 8-15: CLFLUSH line size (*8 = cache size in bytes)
     * ~~ cache information is different for AMD processors ~~
     * edx (d):
     * Bit 25: SSE
     * Bit 26: SSE2
     * ecx (c):
     * Bit 0: SSE3
     */
    a=0; b=0; c=0; d=0;
    cpuid(1,a,b,c,d);
    sprintf(sysinfo[3],"cpu.stepping = %d",a&15);
    sprintf(sysinfo[4],"cpu.model = %d", a&240);
    sprintf(sysinfo[5],"cpu.family = %d", (a>>8)&15);
    sprintf(sysinfo[6],"cpu.type = %d", (a>>8)&48);

    sprintf(sysinfo[7],"cpu.cachesize = %d",(b>>5));

    sprintf(sysinfo[8],"cpu.sse = %s",((d>>25)&1)?"True":"False");
    sprintf(sysinfo[9],"cpu.sse2 = %s",((d>>26)&1)?"True":"False");
    sprintf(sysinfo[10],"cpu.sse3 = %s",(c&1)?"True":"False");

    // read and print the pcr values
    unsigned char pcrvalues[pcrs][20];
    unsigned char pcrvalue[20];
    int j;
    ret = 0;
    for (i = 0; i < pcrs; i++) {
        // HDR: TPM_PcrRead(uint32_t pcrindex, unsigned char *pcrvalue)
        ret = TPM_PcrRead((uint32_t) i, pcrvalue);
        if (ret) {
            fprintf(stderr,"Could not read PCR-%02d\n",i);
            memset(pcrvalues[i],0,20); // set to all 0s to indicate error
        } else
            for (j = 0; j < 20; j++)
                sprintf(pcrvalues[i]+j,"%c",pcrvalue[j]);
    }

    /* We must add randomness to the randomness, otherwise various things will fail (e.g. TSS_Bind) */
    unsigned char * buf = malloc(256);
    RAND_seed(buf, 256);

    unsigned char * srkpass = "SRK PASS";
    unsigned char srkauth[20];
    TSS_sha1(srkpass, strlen(srkpass), srkauth);

    unsigned char *ownpass = "OWN PASS";
    unsigned char ownauth[20];
    TSS_sha1(ownpass, strlen(ownpass), ownauth);

    /* Try to take ownership of TPM. This also returns the SRK as a keydata struct*/
    ret = TPM_TakeOwnership(ownauth, srkauth, NULL);
    if (ret) 
        fprintf(stderr,"TPM_TakeOwnership failed with error %p: %s\n",(void *)ret, TPM_GetErrMsg(ret));
    else 
        fprintf(stdout,"TPM_TakeOwnership succeeded.\n");

    // ~~~~~ CREATE AND LOAD AIK ~~~~~ //
    uint32_t srkkeyhandle = 0x40000000;
    uint32_t newkeyhandle;

    unsigned char *newpass = "NEW PASS";
    unsigned char newauth[20];
    TSS_sha1(newpass, strlen(newpass), newauth);

    unsigned char *migpass = "MIG PASS";
    unsigned char migauth[20];
    TSS_sha1(migpass, strlen(migpass), migauth);

    char keytype = 's';
    unsigned char kblob[4096];
    unsigned int kblen;

    keydata k;              /* input key parameters */
    keydata q;              /* resulting key */

    /* initialize new key parameters */
    k.keyflags = 0;
    if (migpass != NULL)
        k.keyflags |= 0x00000002;       /* key flags - migratable */
    if (newpass != NULL)
        k.authdatausage = 1;    /* key requires authorization ) */
    else
        k.authdatausage = 0;    /* key requires no authorization */
    k.privkeylen = 0;       /* no private key specified here */
    k.pub.algorithm = 0x00000001;   /* key algorithm 1 = RSA */
    if (keytype == 's') {
        k.keyusage = 0x0010;    /* key Usage - 0x0010 = signing */
        k.pub.encscheme = 0x0001;
        k.pub.sigscheme = 0x0002;       /* signature scheme RSA/SHA1  */
    } else if (keytype == 'e') {
        k.keyusage = 0x0011;    /* key Usage - 0x0011 = encryption */
        k.pub.encscheme = 0x0003;       /* encryption scheme 3 RSA */
        k.pub.sigscheme = 0x0001;       /* signature scheme NONE  */
    } else if (keytype == 'b') {
        k.keyusage = 0x0014;    /* key Usage - 0x0014 = bind */
        k.pub.encscheme = 0x0003;       /* encryption scheme 3 RSA */
        k.pub.sigscheme = 0x0001;       /* signature scheme none */
    } else if (keytype == 'l') {
        k.keyusage = 0x0015;    /* key Usage - 0x0015 = legacy */
        k.pub.encscheme = 0x0003;       /* encryption scheme 3 RSA */
        k.pub.sigscheme = 0x0002;       /* signature scheme RSA/SHA1  */
    } else 
        ReturnError(1, "Error at key type");

    k.pub.keybitlen = 2048; /* RSA modulus size 2048 bits */
    k.pub.numprimes = 2;    /* required */
    k.pub.expsize = 0;      /* RSA exponent - default 0x010001 */
    k.pub.keylength = 0;    /* key not specified here */
    k.pub.pcrinfolen = 0;   /* no PCR's used at this time */

    ret = TPM_CreateWrapKey(srkkeyhandle, srkauth, newauth, migauth, &k, &q, kblob, &kblen);
    if (ret) 
        fprintf(stderr,"TPM_CreateWrapKey error %p: %s\n",(int*)ret, TPM_GetErrMsg(ret));
    else 
        fprintf(stdout,"TPM_CreateWrapKey success! Key len: %d\n",kblen);

    ret = TPM_LoadKey(srkkeyhandle, srkauth, &q, &newkeyhandle);
    if (ret)
        fprintf(stderr,"TPM_Load failed with error %p: %s\n",(void *)ret, TPM_GetErrMsg(ret));
    else
        fprintf(stdout,"TPM_Load success! newkeyhandle: %p\n",(void *)newkeyhandle);

    // ~~~~~ TPM QUOTE ~~~~~ //
    uint32_t pcrmap = 0x00FFFFFF; // First 24 pcrs
    unsigned char data[20];
    unsigned char pcrcompos[4096];
    unsigned char blob[4096];
    unsigned int bloblen;

    // hash of the pcrvalues, because quote wants 20 bytes
    TSS_sha1((char *)pcrvalues, 20*pcrs, data);

    ret = TPM_Quote(newkeyhandle, pcrmap, newauth, data, pcrcompos, blob, &bloblen);
    if (ret) 
        fprintf(stderr,"TPM_Quote failed with error %p: %s\n",(void *)ret, TPM_GetErrMsg(ret));
    else 
        fprintf(stdout,"TPM_Quote(pcrmap: %x) success! Bloblen: %d\n", pcrmap, bloblen);

    // evict the key, we don't need it anymore
    ret = TPM_EvictKey(newkeyhandle);
    if (ret) 
        fprintf(stderr,"TPM_Evict(%p) failed with error %p: %s\n",(void *)newkeyhandle,(void *)ret, TPM_GetErrMsg(ret));
    else 
        fprintf(stdout,"TPM_Evict(%p) success!\n", (void *)newkeyhandle);

    sprintf(sysinfo[11], "tpm says quote(pcrs) = <<");
    for (i = 0; i < bloblen; i++)
        sprintf(sysinfo[11]+25+2*i,"%02x",blob[i]);
    sprintf(sysinfo[11]+25+2*bloblen, ">>");

    // print out the public key used for qoute
    sprintf(sysinfo[12], "tpm says quote(pcrs).pubkey = <<");
    for (i = 0; i < q.pub.keylength; i++) 
        sprintf(sysinfo[12]+32+2*i, "%02x", q.pub.modulus[i]);
    sprintf(sysinfo[12]+32+2*q.pub.keylength, ">>");

    // add the network address
    Net_get_ip((unsigned int*) ipaddr, NULL, NULL);
    sprintf(sysinfo[13], "ipv4.addr = %hu.%hu.%hu.%hu\n", 
	    ipaddr[3], ipaddr[2], ipaddr[1], ipaddr[0]);
    
    for (i = 0; i < 13; i++)
        sysinfoptrs[i] = &(sysinfo[i][0]);
        
    sysinfoptrs[13] = 0;
    Thread_Sha1_SaysCert(sysinfoptrs, filepath);

    // rename to name that fauxbook expects (fragile!)
    if (rename(filepath, "/tmp/sysinfo.pem"))
        ReturnError(1, "rename()");

    printf("[sysinfo] OK\n");
    return 0;
}

