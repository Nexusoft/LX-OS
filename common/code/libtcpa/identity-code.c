
/* organize data in an identity contents struct before getting a chosenidhash */
int fillIdentityContentsData(IdentityContentsData *new,
			     unsigned char *idlabel, int idlabelsize,
			     PubKeyData *cakey,
			     PubKeyData *idkey){
  int dbg = 1;

  new->idlabelsize = idlabelsize;

  assert(idlabel != NULL);
  assert(cakey != NULL);


  if(idlabel){
    memcpy(new->idlabel, idlabel, idlabelsize);
    if(dbg){
      unsigned char hash[TCPA_HASH_SIZE];
      SHA1(idlabel, idlabelsize, hash);
      printf("idlabel (len=%d) hash:", idlabelsize);
      PRINT_HASH(hash);
    }
  } 
  if(cakey){
    memcpy(&new->cakey, cakey, sizeof(PubKeyData));
    if(dbg){
      unsigned char *keybuf = (unsigned char *)nxcompat_alloc(TCPA_PUBKEY_SIZE);
      int keylen = BuildPubKey(keybuf, cakey);
      unsigned char hash[TCPA_HASH_SIZE];
      SHA1(keybuf, keylen, hash);
      printf("cakey (keylen=%d) hash:", keylen);
      PRINT_HASH(hash);
      nxcompat_free(keybuf);
    }
  }
  if(idkey){
    memcpy(&new->idkey, idkey, sizeof(PubKeyData));
    if(dbg){
      unsigned char *keybuf = (unsigned char *)nxcompat_alloc(TCPA_PUBKEY_SIZE);
      int keylen = BuildPubKey(keybuf, idkey);
      unsigned char hash[TCPA_HASH_SIZE];
      SHA1(keybuf, keylen, hash);
      printf("idkey (keylen=%d) hash:", keylen);
      PRINT_HASH(hash);
      nxcompat_free(keybuf);
    }
  }
  return 0;
}



/* this one won't ever be extracted (hashes are one-way) */
int BuildChosenIdHash(unsigned char *buffer, IdentityContentsData *id){
  int dbg = 0;
  unsigned char build_chosenid_fmt[] = "% %";

  /* we have to be careful how much we put on the stack if the function
   * will be used by the kernel. */
  unsigned char *chosenid = (unsigned char *)nxcompat_alloc(TCPA_PUBKEY_SIZE + MAX_IDLABEL_LEN);
  unsigned char *cakey = (unsigned char *)nxcompat_alloc(TCPA_PUBKEY_SIZE);

  
  int keylen = BuildPubKey(cakey, &id->cakey);

  if(dbg){
    unsigned char hash[TCPA_HASH_SIZE];
    SHA1(cakey, keylen, hash);
    printf("cakey (keylen=%d) hash:", keylen);
    PRINT_HASH(hash);
  }

  int len = buildbuff(build_chosenid_fmt, chosenid,
		      id->idlabelsize, id->idlabel,
		      keylen, cakey);
  
  int i;
  if(dbg){
    printf("pre-sha: bufsize=%d\n", len - id->idlabelsize);
    for(i = 0; i < len - id->idlabelsize; i++)
      printf("%02x ", chosenid[i + id->idlabelsize]);
    printf("\n");
  }

 SHA1(chosenid, len, buffer);

  printf("chosenid hash = ");
  for(i = 0; i < TCPA_HASH_SIZE; i++)
    printf("%02x ", buffer[i]);
  printf("\n");

  nxcompat_free(chosenid);
  nxcompat_free(cakey);

  return TCPA_HASH_SIZE;
}

