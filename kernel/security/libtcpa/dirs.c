#include <nexus/defs.h>
#include <libtcpa/tcpa.h>
#include <libtcpa/hmac.h>
#include <libtcpa/oiaposap.h>
#include <libtcpa/buildbuff.h>

unsigned char dirdata[TCPA_MAX_BUFF_SIZE]; /* request/response buffer */
uint32_t TPM_DirRead(int i, unsigned char *databuf, int datalen){
  unsigned char dir_fmt[] = "00 c1 T l l";
  uint32_t ret;
  int ordinal, dirindex;

  if(datalen != TCPA_HASH_SIZE + TCPA_DATA_OFFSET){
    printk("Incorrect size of buffer for TPM_DirRead\n");
    return -1;
  }

  dirindex = htonl(i);
      
  ordinal = htonl(26);
  ret = buildbuff(dir_fmt, databuf, ordinal, dirindex);
  if (ret < 0)
    return -1;
  ret = TPM_Transmit(databuf, "DirRead");
#if 0
  printk("DIR: \n");
  for(j = 10; j < 30; j++)
    printk("0x%02x ", databuf[j]);
  printk("\n");
#endif

  return 0;
}

/*
 * index = index of DIR to write to 
 * value = value to place in DIR
 * ohash = hash of owner's password
 */
uint32_t TPM_DirWriteAuth(int index, unsigned char *value, unsigned char *ohash){
  unsigned char dir_fmt[] = "00 c2 T l l % l % o %";
  unsigned char c;
  unsigned int authhandle, ret;
  int ordinal, dirindex;
  unsigned char oddnonce[TCPA_NONCE_SIZE];
  unsigned char evennonce[TCPA_NONCE_SIZE];
  unsigned char pubauth[TCPA_HASH_SIZE];

  ordinal = htonl(25);
  dirindex = htonl(index);

  /* generate odd nonce */
  RAND_bytes(oddnonce, TCPA_NONCE_SIZE);
  /* Open OIAP Session */
  ret = TPM_OIAP(&authhandle, evennonce);

  if (ret != 0)
    return -1;

  /* move Network byte order data to variables for hmac calculation */
  ordinal = htonl(25);
  dirindex = htonl(index);
  c = 0;

  /* calculate authorization HMAC value */
  ret = authhmac(pubauth, ohash, TCPA_HASH_SIZE, evennonce, oddnonce,
		 c, 4, &ordinal, 4, &dirindex, TCPA_HASH_SIZE, value, 0, 0);

  if (ret < 0) {
    TPM_Terminate_Handle(authhandle);
    return -1;
  }
  
  /* build the request buffer */
  ret = buildbuff(dir_fmt, dirdata,
		  ordinal,
		  dirindex,
		  TCPA_HASH_SIZE, value,
		  htonl(authhandle),
		  TCPA_NONCE_SIZE, oddnonce, 
		  c, 
		  TCPA_HASH_SIZE, pubauth);
  
  if (ret <= 0) {
    TPM_Terminate_Handle(authhandle);
    return -1;
  }
  
  ret = TPM_Transmit(dirdata, "DirWriteAuth");
  return ret;
}
