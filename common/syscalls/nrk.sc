syscall nrk {

  decls{
    includefiles{ "<nexus/kvkey.h>" } 
    includefiles{ "<libtcpa/tpm.h>" } /* XXX This shouldn't be a
					 shared header file.  The
					 kernel should be the only one
					 that cares about tpm
					 defines. */

    static const unsigned char seal_tcpa_version[5] = "\01\01\00\00";

    struct macro_definitions{
#define SEALBUNDLE_SECRET(bundle) ((bundle)->data + 0)
#define SEALBUNDLE_UNSEALPOLICY(bundle) ((bundle)->data + (bundle)->secretlen)
#define SEALBUNDLE_RESEALPOLICY(bundle) ((bundle)->data + (bundle)->secretlen + (bundle)->unsealpolicylen)
#define SEALBUNDLE_LEN(bundle) ((bundle)->secretlen + (bundle)->unsealpolicylen + (bundle)->resealpolicylen + sizeof(SealBundle))
#define AES_INDIRECTION_KEYSIZE (32)
#define AES_INDIRECTION_IVSIZE (16)
#define NRK_SEAL_MAX (1048576)
#define SEAL_TCPA_VERSION (seal_tcpa_version)
#define SEAL_TCPA_VERSION_SIZE (4)
    };

    /* shared structures internal to unseal routines */
    typedef struct SealBundle{
      int secretlen;
      int unsealpolicylen;
      int resealpolicylen;
      unsigned char data[0];
    } SealBundle;
    

    typedef struct TPMSealHdr{
      /* tcpa_version should always be 1.1.0.0, as this is the version
	 of the spec the structure is from */
      unsigned char tcpa_version[TCPA_VERSION_SIZE];  
      unsigned char payload;  /* should be TCPA_PT_BIND */
      unsigned char data[0]; /* The TPM will strip off the bind
				header; the returned data starts
				here */
    }TPMSealHdr;


    /* the aes structure that gets sealed/encrypted */
    typedef struct AESKeyBuf{
      TPMSealHdr tpmhdr;
      unsigned char key[AES_INDIRECTION_KEYSIZE];
      unsigned char iv[AES_INDIRECTION_IVSIZE];
    }AESKeyBuf;

    /* This structure must be shared so that things sealed in
       userspace have the internal format expected in the kernel at
       unseal time.  Also, this allows nrk_encrypt_len to be
       implemented entirely in user space. */
    typedef struct KEncBuf{
      int privenclen;
      unsigned char privenc[TCPA_ENC_SIZE];
      int datalen;
      unsigned char encdata[0];
    }KEncBuf;

    enum NRK_ERRORS{
      NRK_ERR_OUTSPACE = 1,
      NRK_ERR_PARAM,
      NRK_ERR_SEAL,
      NRK_ERR_UNSEAL,
      NRK_ERR_CREATE,
      NRK_ERR_LOAD,
      NRK_ERR_RESEAL,
      NRK_ERR_DENIED
    };

    int nrk_encrypt_len(int len);
    void init_tpmhdr(TPMSealHdr *hdr);
  }

  decls __caller__ {

    void init_tpmhdr(TPMSealHdr *hdr){
      memcpy(hdr->tcpa_version, SEAL_TCPA_VERSION, SEAL_TCPA_VERSION_SIZE);
      hdr->payload = TCPA_PT_BIND;
    }

    int nrk_encrypt_len(int len){
      return sizeof(KEncBuf) + sizeof(SealBundle) + len;
    }
  }

  decls __callee__ {
    includefiles{ "<libtcpa/tcpa.h>" }
    includefiles{ "<nexus/policy.h>" }
    includefiles{ "<nexus/guard.h>" } 
    includefiles{ "<nexus/thread.h>" }
    includefiles{ "<nexus/thread-inline.h>" }

    void init_tpmhdr(TPMSealHdr *hdr){
      memcpy(hdr->tcpa_version, SEAL_TCPA_VERSION, SEAL_TCPA_VERSION_SIZE);
      hdr->payload = TCPA_PT_BIND;
    }

    // does not check policies
    int unbind_bundle(KVKey_nrk *nrk, unsigned char *sealeddata, int sealeddatalen,
			 /* output : */ SealBundle **bundle){
      int dbg = 1;
      int ret;

      *bundle = NULL;

      if(dbg)
	printk_red("sealeddatalen = %d\n", sealeddatalen);

      if(sealeddatalen <= 0 || sealeddatalen > NRK_SEAL_MAX + sizeof(KEncBuf))
	return -NRK_ERR_PARAM;

      assert(sizeof(nrk->wrappednrk) == sizeof(struct KeyData));
      KeyData *kwrapnrk = (KeyData *)galloc(sizeof(struct KeyData));
      KEncBuf *kencbuf = (KEncBuf *)galloc(sealeddatalen);
      Map *map = nexusthread_current_map();
      peek_user(map, (unsigned int)nrk->wrappednrk, kwrapnrk, sizeof(struct KeyData));
      peek_user(map, (unsigned int)sealeddata, kencbuf, sealeddatalen);

      int bundlelen = kencbuf->datalen;

      if(dbg)
	printk_red("bundlelen == %d\n", bundlelen);

      if((bundlelen <= 0) || (bundlelen > NRK_SEAL_MAX)){
	ret =  -NRK_ERR_PARAM;
	goto unsealkey_err;
      }
      *bundle = (SealBundle *)galloc(bundlelen);

      unsigned char *spass = get_spass();

      unsigned int knexushandle;
      ret = TPM_LoadKey(TPM_KH_SRK, spass, kwrapnrk, &knexushandle);
      if(ret != 0){
	printk_red("can't load key!!! %d\n", ret);
	ret = -NRK_ERR_LOAD;
	goto unsealkey_err;
      }

      if(kencbuf->datalen < RSA_MAX_CLEAR_SIZE){
	bundlelen = kencbuf->datalen - sizeof(TPMSealHdr);

	if(dbg)
	  printk_red("unbinding: %d 0x%p 0x%p %d 0x%p 0x%p %d\n", knexushandle, spass, 
		     kencbuf->privenc, kencbuf->privenclen, *bundle, &bundlelen, bundlelen);
	ret = TPM_UnBind(knexushandle, spass, 
			 kencbuf->privenc, kencbuf->privenclen, 
			 (unsigned char *)*bundle, &bundlelen);
	TPM_EvictKey(knexushandle);
	if(ret != 0){
	  printk_red("unbind err (small) %d\n", ret);
	  ret = -NRK_ERR_UNSEAL;
	  goto unsealkey_err;
	}
	assert(bundlelen == kencbuf->datalen - sizeof(TPMSealHdr));
      }else{    
	/* unseal aes key */
	AESKeyBuf ksymkey;
	int ksymkeylen = sizeof(AESKeyBuf) - sizeof(TPMSealHdr);
	ret = TPM_UnBind(knexushandle, spass, 
			 kencbuf->privenc, kencbuf->privenclen, 
			 (unsigned char *)ksymkey.key, &ksymkeylen);
	TPM_EvictKey(knexushandle);
	if(ret != 0){
	  printk_red("unbind err (aes) %d\n", ret);
	  ret = -NRK_ERR_UNSEAL;
	  goto unsealkey_err;
	}

	if(dbg)
	  printk_red("ksymkeylen = %d, aeskeybuf = %d\n", 
		     ksymkeylen, sizeof(AESKeyBuf) - sizeof(TPMSealHdr));
	assert(ksymkeylen == sizeof(AESKeyBuf) - sizeof(TPMSealHdr));

	/* decrypt data */
	nexus_cbc_decrypt(kencbuf->encdata, kencbuf->datalen,
			  (unsigned char *)*bundle, &bundlelen,
			  ksymkey.key, AES_DEFAULT_KEYSIZE, 
			  ksymkey.iv, AES_IV_SIZE);
	assert(bundlelen == kencbuf->datalen);
      }

      ret = 0;

    unsealkey_err:
      gfree(kwrapnrk);
      gfree(kencbuf);
      if (ret) {
	gfree(*bundle);
	*bundle = NULL;
      }

      return ret;
    }

  }

  interface int create(/* output: */ KVKey_nrk *nrk) {
    // no policy needed: only nrk operation is unseal(bundle), which already checks
    // the policy specified in the bundle; the seal(data) operation is entirely
    // in user space, and can be performed by anyone with the public half
    Map *map = nexusthread_current_map();

    unsigned char *spass = get_spass();
    KeyData *knewkey = (KeyData *)galloc(sizeof(struct KeyData));
    memset(knewkey, 0, sizeof(struct KeyData)); 

    printk_red("creating wrap key...");
    int ret = createKey(TPM_KH_SRK, spass, spass, knewkey, TCPA_DEFAULT_PCRS, TPM_KEY_BIND);
    printk_red("done.\n");

    if(ret != 0){
      gfree(knewkey);
      return -NRK_ERR_CREATE;
    }

    int kmodlen = RSA_MODULUS_BYTE_SIZE;
    AlgType kalgtype = ALG_RSA_ENCRYPT;
    poke_user(map, (unsigned int)&nrk->pub.algtype, &kalgtype, sizeof(AlgType));
    poke_user(map, (unsigned int)&nrk->pub.moduluslen, &kmodlen, sizeof(int));
    poke_user(map, (unsigned int)nrk->pub.modulus, knewkey->pub.modulus, kmodlen);

    assert(sizeof(nrk->wrappednrk) == sizeof(struct KeyData));
    poke_user(map, (unsigned int)nrk->wrappednrk, knewkey, sizeof(struct KeyData));
   
    gfree(knewkey); 
    return 0;
  }

  /* note: seal at the app/kernel boundary uses bind at the kernel/tpm boundary */
  interface int unseal(KVKey_nrk *nrk,
		       unsigned char *sealeddata, int sealeddatalen,
		       _Grounds *upg,
		       /* output : */
		       unsigned char *unsealeddata, int *unsealeddatalen){
    int kavaillen = 0;
    SealBundle *bundle = NULL;
    Map *map = nexusthread_current_map();

    _Policy *kpol = NULL;
    _Grounds *kpg = NULL;
    Guard *g = NULL;
    if (upg) {
      int err;
      kpg = peek_grounds(map, upg, 1024*1024, &err);
      if (err) {
	printk_red("peek_grounds failed");
	return err;
      }
    }

    peek_user(map, (unsigned int)unsealeddatalen, &kavaillen, sizeof(int));

    int ret = unbind_bundle(nrk, sealeddata, sealeddatalen, &bundle);
    if (ret) {
      ret = -NRK_ERR_UNSEAL;
      goto unsealkey_err;
    }

    /* check unseal policy */
    int kpollen = bundle->unsealpolicylen;
    kpol = galloc(kpollen);
    if (_Policy_deserialize(kpol, &kpollen, SEALBUNDLE_UNSEALPOLICY(bundle), bundle->unsealpolicylen)) {
      ret = -NRK_ERR_UNSEAL;
      goto unsealkey_err;
    }

    g = guard_create();
    guard_setdebug(g, GUARD_DEBUG_ALL);
    if (guard_setgoal(g, &kpol->gf)) {
      ret = -NRK_ERR_DENIED;
      goto unsealkey_err;
    }
   
    Form *req = form_fmt("%{term} says unseal() = 1", ipd_get_speaker(nexusthread_current_ipd()));
    ret = guard_check(g, req, kpg);
    if (ret)
      goto unsealkey_err;
    
    if(kavaillen < bundle->secretlen){
      printk_red("available=%d needed=%d\n", kavaillen, bundle->secretlen);
      ret = -NRK_ERR_OUTSPACE;
      goto unsealkey_err;
    }

    poke_user(map, (unsigned int)unsealeddatalen, &bundle->secretlen, sizeof(int));
    poke_user(map, (unsigned int)unsealeddata, SEALBUNDLE_SECRET(bundle), bundle->secretlen);

    ret = 0;

  unsealkey_err:
    if (kpg) grounds_free(kpg);
    if (kpol) gfree(kpol);
    if (g) guard_free(g);
    if (bundle) gfree(bundle);

    return ret;
  }

  interface int reseal(KVKey_nrk *nrk, KVKey_public *anystoragepub,
		       unsigned char *sealeddata, int sealeddatalen,
		       /* output : */ unsigned char *resealeddata, int *resealeddatalen,
		       _Grounds *upg){
    SealBundle *bundle = NULL;

    _Policy *kpol = NULL;
    _Grounds *kpg = NULL;
    Guard *g = NULL;
    if (upg) {
      int err;
      kpg = peek_grounds(nexusthread_current_map(), upg, 1024*1024, &err);
      if (err) {
	printk_red("peek_grounds failed");
	return err;
      }
    }

    int ret = unbind_bundle(nrk, sealeddata, sealeddatalen, &bundle);
    if (ret) {
      ret = -NRK_ERR_RESEAL;
      goto resealkey_err;
    }

    /* check reseal policy */
    int kpollen = bundle->resealpolicylen;
    kpol = galloc(kpollen);
    if (_Policy_deserialize(kpol, &kpollen, SEALBUNDLE_RESEALPOLICY(bundle), bundle->resealpolicylen)) {
      ret = -NRK_ERR_RESEAL;
      goto resealkey_err;
    }

    g = guard_create();
    guard_setdebug(g, GUARD_DEBUG_ALL);
    if (guard_setgoal(g, &kpol->gf)) {
      ret = -NRK_ERR_DENIED;
      goto resealkey_err;
    }

    // reseal uses new key as requesting principal rather than the current ipd
    Form *req = form_fmt("%{term} says reseal() = 1", kvkey_prin(anystoragepub));
    ret = guard_check(g, req, kpg);
    if (ret)
      goto resealkey_err;

    // reseal bundle under a the new key
    ret = kvkey_encrypt(anystoragepub, (unsigned char *)bundle, SEALBUNDLE_LEN(bundle), resealeddata, resealeddatalen);

  resealkey_err:
    if (kpg) grounds_free(kpg);
    if (kpol) gfree(kpol);
    if (g) guard_destroy(g);
    if (bundle) gfree(bundle);

    return ret;
  }
}
