#include <libtcpa/tpm.h>
#include <nexus/vkey.h>
#include <nexus/policy.h>
#include <nexus/guard.h>
#include <nexus/generaltime.h>
#include <string.h>
#include <assert.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <nexus/util.h>
 #include <sys/types.h>
 #include <sys/stat.h>
 #include <fcntl.h>
 #include <unistd.h>
 #include <netinet/in.h>
//#include "ca_cert.h"

int check_serialization(VKey *vkey1){
  int ret;
  printf("checking serialization...\n");

  char *buf1 = vkey_serialize(vkey1, 0);
  assert(buf1);
  int len1 = der_msglen(buf1);

  VKey *vkey2 = vkey_deserialize(buf1, len1);
  assert(vkey2);
  
  char *buf2 = vkey_serialize(vkey2, 0);
  assert(buf2);
  int len2 = der_msglen(buf2);

  printf("  len1=%d len2=%d\n", len1, len2);
  assert(len1 == len2);

  ret = memcmp(buf2, buf1, len2);
    
  if(ret != 0){
    printf("  buffers didn't match!!\n");
    ret = -1;
  }else{
    printf("  buffers matched!!\n");
    ret = 0;
  }

  vkey_destroy(vkey2);
  free(buf1);
  free(buf2);

  return ret;
}

int check_enc(VKey *vkey, int size){
  unsigned char *buf = (unsigned char *)malloc(size);

  printf("checking encryption...\n");
  printf("  filling buf with %d random bytes\n", size);
  RAND_bytes(buf, size);

  int enclen = vkey_encrypt_len(vkey, buf, size);
  printf("  expecting %d bytes encrypted\n", enclen);
  unsigned char *encbuf = (unsigned char *)malloc(enclen);
  int ret = vkey_encrypt(vkey, buf, size, encbuf, &enclen);
  printf("  got %d bytes encrypted (ret = %d)\n", enclen, ret);
  assert(ret == 0);

  int declen = vkey_decrypt_len(vkey, encbuf, enclen);
  printf("  expecting %d got %d bytes decrypted\n", size, declen);
  assert(declen == size);
  unsigned char *decbuf = (unsigned char *)malloc(declen);
  ret = vkey_decrypt(vkey, encbuf, enclen, decbuf, &declen);
  printf("  got %d bytes decrypted (ret = %d)\n", declen, ret);
  assert(ret == 0);

  if(memcmp(buf, decbuf, size) != 0){
    printf("  decryption doesn't match!\n");
    ret = -1;
  }else{
    printf("  decryption matches!\n");
    ret = 0;
  }

  free(buf);
  free(encbuf);
  free(decbuf);
  return ret;
}
int check_encryption(VKey *vkey){
#define BUFLEN_SHORT (20)
#define BUFLEN_LONG (65536)
  int ret;
  ret = check_enc(vkey, BUFLEN_SHORT);
  if(ret < 0){
    printf("  failed for %d\n", BUFLEN_SHORT);
    return -1;
  }
  ret = check_enc(vkey, BUFLEN_LONG);
  if(ret < 0){
    printf("  failed for %d\n", BUFLEN_LONG);
    return -1;
  }
  return 0;
}


int check_signing(VKey *vkey){
  char *signmsg = "hello";
  char *signmsg2 = "hello2";
  int ret;
  printf("checking signing...\n");

  unsigned char sig[256];
  int siglen = 256;

  printf("  signing %s (len %d)\n", signmsg, strlen(signmsg));
  /* sign a message */
  ret = vkey_sign(vkey, signmsg, strlen(signmsg), sig, &siglen);
  if(ret < 0){
    printf("  Couldn't sign\n");
    return -1;
  }

  /* verify signature with key that signed it */
  ret = vkey_verify(vkey, signmsg, strlen(signmsg), sig, siglen);
  if(ret < 0){
    printf("  Couldn't verify %d\n", ret);
    return -1;
  }

  printf("  verified\n");

  printf("  perturbing message\n");
  printf("  verifying %s (len %d)\n", signmsg2, strlen(signmsg2));

  /* verify signature with key that signed it */
  ret = vkey_verify(vkey, signmsg2, strlen(signmsg2), sig, siglen);
  if(ret == 0){
    printf("  verified bad message %d\n", ret);
    return -1;
  }

  printf("  correctly did not verify bad message\n");

  return 0;
}


int check_sealing(VKey *vkey){
  int ret;

  printf("checking sealing (user key)...\n");


  _Policy *policy1 = policy_all();
  printf("  getting seal_len...");
  int seallen = vkey_seal_len(vkey, vkey, policy1, policy1);
  printf("%d\n", seallen);
  assert(seallen > 0);

  unsigned char *sealeddata = malloc(seallen);

  printf("  sealing...");

  _Policy *policy2, *policy3;

  ret = vkey_seal(vkey, vkey, policy1, policy1, sealeddata, &seallen);
  printf("  ret = %d, seallen = %d\n", ret, seallen);
  assert(ret == 0);
  printf("  sealed: ");
  PRINT_BYTES(sealeddata, 20);
  printf("...\n  unsealing...");
  VKey *vkey2 = vkey_user_unseal(vkey, sealeddata, seallen, &policy2, &policy3);

  ret = memcmp(policy1, policy2, _Policy_len(policy1));
  if(ret != 0)
    return -1;
  ret = memcmp(policy1, policy3, _Policy_len(policy1));
  if(ret != 0)
    return -1;

  assert(vkey2 != NULL);
  
  char *buf1 = vkey_serialize(vkey, 0);
  assert(buf1);
  int keylen1 = der_msglen(buf1);

  char *buf2 = vkey_serialize(vkey2, 0);
  assert(buf2);
  int keylen2 = der_msglen(buf2);

  assert(keylen1 == keylen2);

  ret = memcmp(buf1, buf2, keylen1);
  if(ret != 0){
    printf("  keys didn't match!\n");
    ret = -1;
  }else{
    printf("  keys matched!\n");
    ret = 0;
  }

  vkey_destroy(vkey2);
  free(buf1);
  free(buf2);
  free(sealeddata);
    
  return ret;
}



int check_seal_buffer(VKey *nrk, int buflen){
  int ret;

  unsigned char *buf = (unsigned char *)malloc(buflen);
  RAND_bytes(buf, buflen);

  printf("checking sealing (local buffer)...\n");
  

  printf("  getting seal_len...");
  _Policy *policy = policy_all();
  int seallen = vkey_seal_data_len(nrk, buflen, policy, policy);
  printf("%d\n", seallen);
  assert(seallen > 0);

  
  unsigned char *sealeddata = (unsigned char *)malloc(seallen);
  printf("  sealing...");

  ret = vkey_seal_data(nrk, buf, buflen, policy, policy, sealeddata, &seallen);
  printf("  ret = %d, seallen = %d\n", ret, seallen);
  assert(ret == 0);


  unsigned char *buf2 = (unsigned char *)malloc(buflen);
  int buflen2 = buflen;
  printf("  unsealing...");
  _Grounds *pg = NULL;
  ret = vkey_nrk_unseal_data(nrk, sealeddata, seallen, buf2, &buflen2, pg);
  printf("  ret=%d\n", ret);
  assert(ret == 0);

  assert(buflen == buflen2);

  ret = memcmp(buf, buf2, buflen);
  if(ret != 0){
    printf("  bufs didn't match!\n");
    ret = -1;
  }else{
    printf("  bufs matched!\n");
    ret = 0;
  }

  free(buf);
  free(buf2);
  free(sealeddata);
    
  return ret;
}

int check_seal_buffer_sizes(VKey *nrk){
  #define SEAL_BUFLEN_SHORT (4)
#define SEAL_BUFLEN_LONG (65536)
  int ret;
  ret = check_seal_buffer(nrk, SEAL_BUFLEN_SHORT);
  if(ret < 0){
    printf("  failed for %d\n", SEAL_BUFLEN_SHORT);
    return -1;
  }
  ret = check_seal_buffer(nrk, SEAL_BUFLEN_LONG);
  if(ret < 0){
    printf("  failed for %d\n", SEAL_BUFLEN_LONG);
    return -1;
  }
  return 0;
}

int check_sealing_local(VKey *nrk, VKey *vkey){
  int ret;

  printf("checking sealing (local nrk)...\n");


  printf("  getting seal_len...");
  _Policy *policy = policy_all();
  int seallen = vkey_seal_len(nrk, vkey, policy, policy);
  printf("%d\n", seallen);
  assert(seallen > 0);

  unsigned char *sealeddata = malloc(seallen);

  printf("  sealing...");

  ret = vkey_seal(nrk, vkey, policy, policy, sealeddata, &seallen);
  printf("  ret = %d, seallen = %d\n", ret, seallen);
  assert(ret == 0);
  printf("  sealed: ");
  PRINT_BYTES(sealeddata, 20);
  printf("...\n  unsealing...");
  _Grounds *pg = NULL;
  VKey *vkey2 = vkey_nrk_unseal(nrk, sealeddata, seallen, pg);

  assert(vkey2 != NULL);
  
  char *buf1 = vkey_serialize(vkey, 0);
  assert(buf1);
  int keylen1 = der_msglen(buf1);
  char *buf2 = vkey_serialize(vkey2, 0);
  assert(buf2);
  int keylen2 = der_msglen(buf2);

  assert(keylen1 == keylen2);

  ret = memcmp(buf1, buf2, keylen1);
  if(ret != 0){
    printf("  keys didn't match!\n");
    ret = -1;
  }else{
    printf("  keys matched!\n");
    ret = 0;
  }

  vkey_destroy(vkey2);
  free(buf1);
  free(buf2);
  free(sealeddata);
    
  return ret;
}


int check_certify_x509(VKey *nsk, VKey *vkey){
  printf("checking certify x509\n");

  TimeString *starttime = timestring_create(2007, 6, 13, 18, 0, 0);
  TimeString *endtime = timestring_create(2007, 6, 14, 18, 0, 0);

  printf("  certifying key\n");
  int buflen = vkey_nsk_certify_key_len(nsk, vkey, starttime, endtime);
  printf("   buflen = %d\n", buflen);

  unsigned char *buf = (unsigned char *)malloc(buflen);

  int ret = vkey_nsk_certify_key(nsk, vkey, starttime, endtime, buf, &buflen);
  assert(ret == 0);

  printf("   buflen = %d\n", buflen);

  timestring_destroy(starttime);
  timestring_destroy(endtime);

  int fd = open("/nfs/testx509.pem", O_CREAT | O_RDWR | O_TRUNC);
  write(fd, buf, buflen);
  fsync(fd);
  close(fd);

  return ret;
}

char capem[5000];
char nexuscapem[5000];
int check_nsk_cert(VKey *nsk){
  printf("getting nsk cert\n");
  int buflen, buflen2;
  unsigned char *buf;

  int fd;
  fd = open("/nfs/ca.crt", O_RDONLY);
  int calen = read(fd, capem, 5000);
  close(fd);
  fd = open("/nfs/nexusca.crt", O_RDONLY);
  int nexuscalen = read(fd, nexuscapem, 5000);
  close(fd);

  buf = vkey_get_remote_certification(nsk, 
				      nexuscapem, nexuscalen,
				      capem, calen,
				      &buflen, &buflen2);
  assert(buf != NULL);
  printf("  buflen = %d buflen2 = %d\n", buflen, buflen2);

  fd = open("/nfs/testx509nsk.der", O_CREAT | O_RDWR | O_TRUNC);
  write(fd, buf, buflen);
  fsync(fd);
  close(fd);

  fd = open("/nfs/testsformnsk.der", O_CREAT | O_RDWR | O_TRUNC);
  write(fd, buf+buflen, buflen2);
  fsync(fd);
  close(fd);

  return 0;
}

#if 0
void encrypt_sizer(VKey *k){
  extern int asym_encrypt_helper(VKey *vkey, 
				 unsigned char *from, int flen, 
				 unsigned char *to, int tolen);
  unsigned char from[1000];
  unsigned char to[1000];
  int buflen, ret;
  for(buflen = 16; buflen < 1000; buflen++){
    ret = asym_encrypt_helper(k, from, buflen, to, 256);
    if(ret != 0)
      printf("ret = %d on %d\n", ret, buflen);
    assert(ret == 0);
  }
}
#endif

#define NSKFILE  "/nfs/nexus.nsk"
#define NRKFILE  "/nfs/nexus.nrk"


int check_x509(VKey *sigvkey){

  printf("checking user x509\n");
  VKey *newenc = vkey_create(VKEY_TYPE_PAIR, ALG_RSA_ENCRYPT);
  if(newenc == NULL){
    printf("Couldn't create vkey\n");
    return -1;
  }
  int serialnum = htonl(4096);

  TimeString *starttime = timestring_create(2007, 6, 13, 18, 0, 0);
  TimeString *endtime = timestring_create(2007, 6, 14, 18, 0, 0);
  printf("  starttime = %s, endtime = %s\n", starttime, endtime);

  int len;
  len = vkey_user_certify_key_len(sigvkey, newenc,
				  (unsigned char *)&serialnum, sizeof(int),
				  "US", "New York",
				  "Ithaca", "Test org",
				  "unit", "test common name",
				  "CA", "Ontario",
				  "Toronto", "Test2 org",
				  "unit2", "test2",
				  starttime, endtime);
  printf("  len = %d\n", len);
  assert(len > 0);
  unsigned char *x509buf = (unsigned char *)malloc(len);
  
  int ret;
  ret = vkey_user_certify_key(sigvkey, newenc,
			      (unsigned char *)&serialnum, sizeof(int),
			      "US", "New York",
			      "Ithaca", "Test org",
			      "unit", "test common name",
			      "CA", "Ontario",
			      "Toronto", "Test2 org",
			      "unit2", "test2",
			      starttime, endtime,
			      x509buf, &len);
  assert(ret == 0);

  timestring_destroy(starttime);
  timestring_destroy(endtime);
  printf("  len = %d\n", len);

  int fd = open("/nfs/testuserx509.der", O_CREAT | O_RDWR | O_TRUNC);
  write(fd, x509buf, len);
  fsync(fd);
  close(fd);

  return 0;
}

int main(int argc, char **argv){
  VKey *nsk, *nrk;
  printf("starting vkeytest\n");

  printf("TCPA version number is %d.%d.%d.%d\n", 
	 TCPA_VERSION[0], TCPA_VERSION[1],
	 TCPA_VERSION[2], TCPA_VERSION[3]);
  int do_nsk = 0;
  int do_nrk = 0;
  int do_user = 0;

  VKey *encvkey = vkey_create(VKEY_TYPE_PAIR, ALG_RSA_ENCRYPT);
  if(encvkey == NULL){
    printf("Couldn't create vkey\n");
    return -1;
  }
  VKey *sigvkey = vkey_create(VKEY_TYPE_PAIR, ALG_RSA_SHA1);
  if(sigvkey == NULL){
    printf("Couldn't create vkey\n");
    return -1;
  }


  //encrypt_sizer(vkey);
  
  if(argc == 1){
    do_nsk = 1;
    do_nrk = 1;
    do_user = 1;
  }else{
    if(strcmp(argv[1], "nsk") == 0)
      do_nsk = 1;
    if(strcmp(argv[1], "nrk") == 0)
      do_nrk = 1;
    if(strcmp(argv[1], "user") == 0)
      do_user = 1;
  }

  if(do_user == 1){
    /* user vkey ops */
    if(check_serialization(sigvkey) != 0)
      return -1;
    if(check_encryption(encvkey) != 0)
      return -1;
    if(check_signing(sigvkey) != 0)
      return -1;
    if(check_sealing(encvkey) != 0)
      return -1;
    if(check_x509(sigvkey) != 0)
      return -1;
  }

  if(do_nsk == 1){
    int fd;
    fd = open(NSKFILE, O_RDONLY);
    if(fd <= 0){
      printf("couldn't get saved nsk from %s\n", NSKFILE);
      nsk = vkey_create(VKEY_TYPE_NSK, ALG_RSA_SHA1);
      fd = open(NSKFILE, O_CREAT | O_WRONLY);

      char *buf = vkey_serialize(nsk, 0);
      write(fd, buf, der_msglen(buf));
      close(fd);
      free(buf);
    }else{
      int len = 5000;
      unsigned char *buf = (unsigned char *)malloc(len);
      len = read(fd, buf, len);
      nsk = vkey_deserialize(buf, len);
      if (!nsk) printf("saved nsk from %s could not be deserialized\n", NSKFILE);
    }
    assert(nsk != NULL);

    if(check_certify_x509(nsk,encvkey) != 0)
      return -1;

#if 1
    if(check_nsk_cert(nsk) != 0)
      return -1;
#endif
  }


  if(do_nrk == 1){
    int fd;
    fd = open(NRKFILE, O_RDONLY);
    if(fd <= 0){
      printf("couldn't get saved nrk from %s\n\n", NRKFILE);
      nrk = vkey_create(VKEY_TYPE_NRK, ALG_RSA_ENCRYPT);
      fd = open(NRKFILE, O_CREAT | O_WRONLY);

      char *buf = vkey_serialize(nrk, 0);
      int len = der_msglen(buf);
      write(fd, buf, len);
      close(fd);
      free(buf);
    }else{
      int len = 5000;
      unsigned char *buf = (unsigned char *)malloc(len);
      len = read(fd, buf, len);
      nrk = vkey_deserialize(buf, len);
      if (!nrk) printf("saved nsk from %s could not be deserialized\n", NSKFILE);
    }
    assert(nrk != NULL);


    if(check_sealing_local(nrk, sigvkey) != 0)
      return -1;
    if(check_seal_buffer_sizes(nrk) != 0)
      return -1;
  }

  printf("SUCCESS!!!");
  return 0;
}
