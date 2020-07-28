syscall nsk {

  decls{
    includefiles{ "<nexus/kvkey.h>" }
    includefiles{ "<libtcpa/keys.h>" } /* for TCPA_SYM_KEY_SIZE... */
    includefiles{ "<nexus/generaltime.h>" } /* for TIME_MAX_SIZE */
    includefiles{ "<nexus/x509parse.h>" }

    enum NSK_ERRORS{
      NSK_ERR_OUTSPACE = 2,
      NSK_ERR_PARAM,
      NSK_ERR_CREATE,
      NSK_ERR_SIGN,
      NSK_ERR_LOAD,
      NSK_ERR_AIK,
      NSK_ERR_PROOF,
      NSK_ERR_UNLOCK,
      NSK_ERR_CERTIFY,
    };




    int nsk_certify_x509_len(KVKey_public *anypub,
			     KVKey_nsk *nsk,
			     char *starttime, int starttimelen,
			     char *endtime, int endtimelen);
    int nsk_request_tpm_certification_len(KVKey_public *capubkey);
    int nsk_unlock_tpm_certification_len(void);
    int nsk_request_nexus_certification_len(void);

    struct macro_defs{
#define NEXUS_X509_MAX (917)
#define NEXUS_X509_COUNTRY "US"
#define NEXUS_X509_STATE "New York"
#define NEXUS_X509_LOCALITY "Ithaca"
#define NEXUS_X509_ORG "Cornell University Nexus"
#define NEXUS_X509_ORGUNIT "NONE"
#define NEXUS_X509_COMMONNAME "Trusted Nexus"
    };
  }

  decls __caller__ {
    includefiles{ "<nexus/x509parse.h>" }

    int nsk_certify_x509_len(KVKey_public *anypub,
			     KVKey_nsk *nsk,
			     char *starttime, int starttimelen,
			     char *endtime, int endtimelen){
      
      return construct_x509(NULL, sizeof(long long),
			    ALG_RSA_SHA1,//kvkey->algtype,
			    NEXUS_X509_COUNTRY, NEXUS_X509_STATE, 
			    NEXUS_X509_LOCALITY, NEXUS_X509_ORG, 
			    NEXUS_X509_ORGUNIT, NEXUS_X509_COMMONNAME, 
			    starttime, endtime, 
			    ALG_RSA_ENCRYPT,
			    anypub->modulus, anypub->moduluslen,
			    RSA_DEFAULT_EXPONENT_ARRAY, RSA_EXPONENT_BYTE_SIZE,
			    NEXUS_X509_COUNTRY, NEXUS_X509_STATE, 
			    NEXUS_X509_LOCALITY, NEXUS_X509_ORG, 
			    NEXUS_X509_ORGUNIT, "xxxxxxxxxxxxxxxx", //XXX get name len
			    TCPA_SIG_SIZE,
			    NULL, 0);

    }
    int nsk_request_tpm_certification_len(KVKey_public *capubkey){
      //XXX how can we tell how big this will be?
#define NEXUS_PARTIAL_PROOF_SIZE (100000)
      return NEXUS_PARTIAL_PROOF_SIZE;
    }
    int nsk_unlock_tpm_certification_len(void){
      return TCPA_SYM_KEY_SIZE;
    }

    int nsk_request_nexus_certification_len(void){
      return TCPA_CERTIFY_REQ_SIZE + 8 * 20 + 1; /* kwalsh: also send first 8 PCRs, plus a byte to indicate nsk versus nrk */
    }

  }

  decls __callee__ {
    includefiles{ "<libtcpa/tcpa.h>" }
    includefiles{ "<nexus/tpm_platform.h>" } /* for platform crt macros */
    includefiles{ "<libtcpa/identity_private.h>" } /* for TCPA_PROOF_SIZE */
    includefiles{ "<nexus/util.h>" } /* for PRINT_HASH (debugging) */
    includefiles{ "<nexus/synch-inline.h>" } 

    Sema *serialnumsema;
    static int serialnum = 0; /* this will combine with boot number
				 for a unique serialnum */

    char *tpm_platform_crt = NULL;
    char *tpm_conformance_crt = NULL;
    char *tpm_ek_crt = NULL;
    
    int tpm_platform_crt_len = 0;
    int tpm_conformance_crt_len = 0;
    int tpm_ek_crt_len = 0;

#define NEXUS_IPD_NAME_LEN  16    //XXX move this 

    int nsk_sign_len(KVKey_nsk *nsk) {
      return TCPA_SIG_SIZE;
    }

    int nsk_sign(KVKey_nsk *nsk, char *msg, unsigned int msglen, char *sig, unsigned int siglen) {
      int ret;
      unsigned int knexushandle;
      unsigned char *spass = get_spass();

      ret = TPM_LoadKey(TPM_KH_SRK, spass, (KeyData *)nsk->wrappednsk, &knexushandle);
      if(ret != 0){
	printk_red("can't load key!!! err=%d\n", ret);
	return -NSK_ERR_LOAD;
      }

      unsigned char tmphash[TCPA_HASH_SIZE];
      sha1(msg, msglen, tmphash);

      int i;
      printk("hash =");
      for (i = 0; i < TCPA_HASH_SIZE; i++) 
	printk(" %02x", tmphash[i]);
      printk("\n");

      assert(siglen == TCPA_SIG_SIZE);

      ret = TPM_Sign(knexushandle, spass,
		     tmphash, TCPA_HASH_SIZE,
		     sig, &siglen);
      TPM_EvictKey(knexushandle);

      if (ret != 0) {
	printk_red("Error %d from TPM_Sign\n", ret);
	return -NSK_ERR_SIGN;
      }

      return 0;
    }
  }

  __callee__ {
    serialnumsema = sema_new();
    sema_initialize(serialnumsema, 1);
  }

  interface int set_local(KVKey_nsk *nsk) {
    Map *map = nexusthread_current_map();

    if (!nsk)
      return -SC_INVALID;

    KVKey_nsk *kvkey = galloc(sizeof(KVKey_nsk));
    if (peek_user(map, (unsigned int)nsk, kvkey, sizeof(KVKey_nsk)) < 0) {
      gfree(kvkey);
      return -SC_ACCESSERROR;
    }

    // XXX FIXME: We really need to check that this nsk belongs to this machine
    // before accepting it. Not sure how to do that... maybe try to load the
    // wrapped half of the private key, then verify that the public matches the
    // private (by signing and verifying something, perhaps? or with algebra?).
    // TODO: this should go away anyway in favor of the kernel just keeping the
    // keys around. Or, the kernel should pass back a certificate that this nsk
    // belongs to this machine.

    if (ipd_set_nsk(nexusthread_current_ipd(), kvkey)) {
      gfree(kvkey);
      return -SC_INVALID;
    }

    return 0;
  }
  
  /* create but don't certify nsk (yet) */
  interface int create(/* output: */ KVKey_nsk *unsk) {
    Map *map = nexusthread_current_map();

    unsigned char *spass = get_spass();
    KeyData *knewkey = (KeyData *)galloc(sizeof(struct KeyData));
    memset(knewkey, 0, sizeof(struct KeyData)); 

    printk("creating wrap key...");
    printk_red("creating wrap key...");
    int ret = createKey(TPM_KH_SRK, spass, spass, knewkey, TCPA_DEFAULT_PCRS, TPM_KEY_SIGNING);
    printk("done.\n");
    printk_red("done.\n");

    if(ret != 0){
      gfree(knewkey);
      return -NSK_ERR_CREATE;
    }

    int kmodlen = RSA_MODULUS_BYTE_SIZE;
    AlgType kalgtype = ALG_RSA_SHA1;
    poke_user(map, (unsigned int)&unsk->pub.algtype, &kalgtype, sizeof(AlgType));
    poke_user(map, (unsigned int)&unsk->pub.moduluslen, &kmodlen, sizeof(int));
    poke_user(map, (unsigned int)unsk->pub.modulus, knewkey->pub.modulus, kmodlen);
    assert(sizeof(unsk->wrappednsk) == sizeof(struct KeyData));
    poke_user(map, (unsigned int)unsk->wrappednsk, knewkey, sizeof(struct KeyData));
  
    gfree(knewkey);  
    return 0;
  }


  interface int certify_x509(KVKey_public *uanypub, KVKey_nsk *unsk,
			     char *starttime, int starttimelen,
			     char *endtime, int endtimelen,
			     //output:
			     unsigned char *cert, int *certlen){
    int dbg = 0;
    IPD *ipd = nexusthread_current_ipd();
    Map *map = nexusthread_current_map();
    int kcertlen;

    peek_user(map, (unsigned int)certlen, &kcertlen, sizeof(int));


    if(starttimelen - 1 < TIME_MIN_SIZE) /* don't count string terminator */
      return -NSK_ERR_PARAM;
    if(endtimelen - 1 < TIME_MIN_SIZE) /* don't count string terminator */
      return -NSK_ERR_PARAM;
    if(starttimelen - 1 > TIME_MAX_SIZE) /* don't count string terminator */
      return -NSK_ERR_PARAM;
    if(endtimelen - 1 > TIME_MAX_SIZE) /* don't count string terminator */
      return -NSK_ERR_PARAM;

    if(dbg)
      printk_red("kcertlen = %d\n", kcertlen);

    if(kcertlen <= 0)
      return -NSK_ERR_OUTSPACE;
    if(kcertlen > NEXUS_X509_MAX) {
      printk_red("WARNING!!! Cert Len > x509 max! (%d > %d)\n",
		 kcertlen, NEXUS_X509_MAX);
    }
    kcertlen = min(kcertlen, NEXUS_X509_MAX);

    KVKey_nsk *nsk = galloc(sizeof(KVKey_nsk));
    KVKey_public *anypub = galloc(sizeof(KVKey_public));
    
    char *kstarttime = (char *)galloc(starttimelen);
    char *kendtime = (char *)galloc(endtimelen);
    unsigned char *kcert = (unsigned char *)galloc(kcertlen);

    peek_user(map, (unsigned int)unsk, nsk, sizeof(KVKey_nsk));
    peek_user(map, (unsigned int)uanypub, anypub, sizeof(KVKey_public));
    peek_user(map, (unsigned int)starttime, kstarttime, starttimelen);
    peek_user(map, (unsigned int)endtime, kendtime, endtimelen);

    /* make sure the null string terminator is on the end so we can strlen */
    kstarttime[starttimelen - 1] = '\0';
    kendtime[endtimelen - 1] = '\0';

    int ret;
    char ipdname[17]; 
    
    snprintf(ipdname, 16, "%08x%08x", ipd->id, get_bootnum());

    P(serialnumsema);
    int myserialnum = ++serialnum; 
    V(serialnumsema);

    unsigned char serialnumarray[sizeof(int) + sizeof(int)];
    assert( (unsigned int)NEXUSBOOTNUM < 0x80000000U );
    *(int *)serialnumarray = ntohl(NEXUSBOOTNUM);
    serialnumarray[0] = 0x01; // XXX Hack: Force DER encoding to full length
    *(int *)(serialnumarray + sizeof(int)) = ntohl(myserialnum);

    printk_red("algtype == %d\n", nsk->pub.algtype);
    ret = construct_x509(serialnumarray, sizeof(serialnumarray),
			 ALG_RSA_SHA1 /*kvkey->algtype*/, 
			 NEXUS_X509_COUNTRY, NEXUS_X509_STATE, 
			 NEXUS_X509_LOCALITY, NEXUS_X509_ORG, 
			 NEXUS_X509_ORGUNIT, NEXUS_X509_COMMONNAME, 
			 kstarttime, kendtime, 
			 ALG_RSA_ENCRYPT,
			 anypub->modulus, anypub->moduluslen,
			 RSA_DEFAULT_EXPONENT_ARRAY, RSA_EXPONENT_BYTE_SIZE,
			 NEXUS_X509_COUNTRY, NEXUS_X509_STATE, 
			 NEXUS_X509_LOCALITY, NEXUS_X509_ORG, 
			 NEXUS_X509_ORGUNIT, ipdname, 
			 TCPA_SIG_SIZE,
			 kcert, kcertlen);

    if(dbg)
      printk_red("kcertlen = %d, ret = %d\n", kcertlen, ret);

    if(kcertlen < ret){
      ret = -NSK_ERR_OUTSPACE;
      goto certifyx509_err;
    }

    unsigned int kmsglen;
    unsigned int ksiglen;
    unsigned char *kmsg = parsex509_getmsg(kcert, &kmsglen);
    unsigned char *ksig = parsex509_getsig(kcert, &ksiglen);

    ret = nsk_sign(nsk, kmsg, kmsglen, ksig, ksiglen);
    if(ret != 0){
      goto certifyx509_err;
    }

    poke_user(map, (unsigned int)certlen, &kcertlen, sizeof(int));
    poke_user(map, (unsigned int)cert, kcert, kcertlen);

  certifyx509_err:
    gfree(nsk);
    gfree(kstarttime);
    gfree(kendtime);
    gfree(kcert);

    return ret;
  }

  interface int request_tpm_certification(KVKey_public *cavkey,
					  unsigned char *wrappedaik, int *wrappedaiklen,
					  unsigned char *reqbuf, int *reqlen){
    int dbg = 0;
    int ret;
    Map *map = nexusthread_current_map();
    KeyData* kidkey;
    PubKeyData *kcakey;
    KVKey_public *kvkey;
    unsigned char *kidbindbuf, *kproofbuf;
    int kidbindlen, kwrappedaiklen;
    int kavaillen;
    unsigned char build_idproof_fmt[]     = "% L L L L L % % % % % %";

    char *idlabel = "Nexus";
    int idlabellen = strlen("Nexus");
    
    if((TPM_ENDORSEMENT_CRED_SIZE == 0) || 
       (TPM_PLATFORM_CRED_SIZE == 0) || 
       (TPM_CONFORMANCE_CRED_SIZE == 0) || 
       (TPM_ENDORSEMENT_CRED == NULL) || 
       (TPM_PLATFORM_CRED == NULL) || 
       (TPM_CONFORMANCE_CRED == NULL)){
      printk_red("TPM platform certificates not loaded.\n");  
      printk_red("Use the kernel shell command:\n");
      printk_red("    `tftp_fetch_tpmcerts tpm_platform.crt tpm_platform.crt tpm_platform.crt'\n");
      return -NSK_ERR_PARAM;
    }
	
    peek_user(map, (unsigned int)reqlen, &kavaillen, sizeof(int));
    peek_user(map, (unsigned int)wrappedaiklen, &kwrappedaiklen, sizeof(int));

    if(kwrappedaiklen < TPMKEY_WRAPPED_SIZE)
      return -NSK_ERR_OUTSPACE;
    if(kavaillen < TCPA_PROOF_SIZE)
      return -NSK_ERR_OUTSPACE;
    kwrappedaiklen = TPMKEY_WRAPPED_SIZE;

    kidkey = (KeyData *)galloc(sizeof(KeyData));
    kcakey = (PubKeyData *)galloc(sizeof(PubKeyData));
    kvkey = (KVKey_public *)galloc(sizeof(KVKey_public));
    kproofbuf = (unsigned char *)galloc(TCPA_PROOF_SIZE);

    memset((unsigned char *)kidkey, 0, sizeof(KeyData));
    
    kidbindlen = TCPA_SIG_SIZE;
    kidbindbuf = (unsigned char *)galloc(kidbindlen);

    peek_user(map, (unsigned int)cavkey, kvkey, sizeof(KVKey_public));


    if(kvkey->algtype != ALG_RSA_ENCRYPT){
      ret = -NSK_ERR_PARAM;
      goto request_tpm_err1;
    }
      
    create_pubkey(kcakey, kvkey->modulus, TCPA_ES_RSAESOAEP_SHA1_MGF1, TCPA_SS_NONE);

    ret = createaik(idlabel, idlabellen, kcakey, kidkey, kidbindbuf, &kidbindlen);

    if(ret != 0){
      ret = -NSK_ERR_AIK;
      goto request_tpm_err1;
    }

    unsigned char *kidkeybuf = (unsigned char *)galloc(TCPA_PUBKEY_SIZE);

    if(dbg){
      unsigned char tmphash[TCPA_HASH_SIZE];
      sha1((unsigned char *)&kidkey->pub, sizeof(PubKeyData), tmphash);
      printk_red("idpubkeydata (len=%d) hash:", sizeof(PubKeyData));
      PRINT_HASH(tmphash);
      PRINT_BYTES((unsigned char *)&kidkey->pub, sizeof(PubKeyData));
      printk_red("\n");
      printk_red("pcrinfolen=%d\n", kidkey->pub.pcrinfolen);
    }

    int kidkeybuflen = BuildPubKey(kidkeybuf, &kidkey->pub);
    
    if(dbg){
      unsigned char tmphash[TCPA_HASH_SIZE];
      sha1(kidkeybuf, kidkeybuflen, tmphash);
      printk_red("id pubkey (%d) has hash:", kidkeybuflen);
      //PRINT_BYTES(kidkeybuf, kidkeybuflen);
      //printk_red("\n");
      PRINT_HASH(tmphash);
    }


    if(dbg)
      printk_red("about to buildbuf lens = %d 0x%p %d %d %d %d %d %d 0x%p %d 0x%p %d 0x%p %d 0x%p %d 0x%p %d 0x%p \n", 
		 TCPA_VERSION_SIZE, TCPA_VERSION, 
		 idlabellen,
		 kidbindlen,
		 TPM_ENDORSEMENT_CRED_SIZE,
		 TPM_PLATFORM_CRED_SIZE,
		 TPM_CONFORMANCE_CRED_SIZE,
		 kidkeybuflen, kidkeybuf,
		 idlabellen, idlabel, 
		 kidbindlen, kidbindbuf,
		 TPM_ENDORSEMENT_CRED_SIZE, TPM_ENDORSEMENT_CRED,
		 TPM_PLATFORM_CRED_SIZE, TPM_PLATFORM_CRED,
		 TPM_CONFORMANCE_CRED_SIZE, TPM_CONFORMANCE_CRED);
	       

    printk_red("%s:%d:tcpa version %d %d %d %d\n", __FILE__, __LINE__, TCPA_VERSION[0], TCPA_VERSION[1], TCPA_VERSION[2], TCPA_VERSION[3]);
    /* build "identity proof" for request */
    int kprooflen = buildbuff(build_idproof_fmt, kproofbuf,
			      TCPA_VERSION_SIZE, TCPA_VERSION, 
			      idlabellen,
			      kidbindlen,
			      TPM_ENDORSEMENT_CRED_SIZE,
			      TPM_PLATFORM_CRED_SIZE,
			      TPM_CONFORMANCE_CRED_SIZE,
			      kidkeybuflen, kidkeybuf,
			      idlabellen, idlabel, 
			      kidbindlen, kidbindbuf,
			      TPM_ENDORSEMENT_CRED_SIZE, TPM_ENDORSEMENT_CRED,
			      TPM_PLATFORM_CRED_SIZE, TPM_PLATFORM_CRED,
			      TPM_CONFORMANCE_CRED_SIZE, TPM_CONFORMANCE_CRED);
    if(dbg)
      printk_red("prooflen - cred sizes = %d\n", kprooflen
		 - TPM_ENDORSEMENT_CRED_SIZE
		 - TPM_PLATFORM_CRED_SIZE
		 - TPM_CONFORMANCE_CRED_SIZE);
    if(dbg){
      unsigned char tmphash[TCPA_HASH_SIZE];
      sha1(kproofbuf, kprooflen, tmphash);
      printk_red("proof has hash:");
      PRINT_HASH(tmphash);
    }
    
    poke_user(map, (unsigned int)reqlen, &kprooflen, sizeof(int));
    poke_user(map, (unsigned int)reqbuf, kproofbuf, kprooflen);
    poke_user(map, (unsigned int)wrappedaiklen, &kwrappedaiklen, sizeof(int));
    poke_user(map, (unsigned int)wrappedaik, kidkey, sizeof(KeyData));

    ret = 0;

    gfree(kidkeybuf);
  request_tpm_err1:
    gfree(kidkey);
    gfree(kcakey);
    gfree(kvkey);
    gfree(kproofbuf);
    gfree(kidbindbuf);
    
    return ret;
  }

  interface int unlock_tpm_certification(unsigned char *wrappedaik, int wrappedaiklen,
					 unsigned char *enc, int enclen,
					 unsigned char *clear, int *clearlen){

    int kavaillen, kclearlen;
    int ret;

    Map *map = nexusthread_current_map();
    KeyData *kaik;
    unsigned char *kenc, *ksymkey;

    if(wrappedaiklen != sizeof(KeyData))
      return -NSK_ERR_PARAM;
    if(enclen <= 0)
      return -NSK_ERR_PARAM;
    if(enclen > TCPA_ENC_SIZE)
      return -NSK_ERR_PARAM;

    peek_user(map, (unsigned int)clearlen, &kavaillen, sizeof(int));
    kclearlen = kavaillen;

    if(kavaillen < TCPA_SYM_KEY_SIZE)
      return -NSK_ERR_OUTSPACE;

    kaik = (KeyData *)galloc(wrappedaiklen);
    kenc = (unsigned char *)galloc(enclen);
    ksymkey = (unsigned char *)galloc(TCPA_SYM_KEY_SIZE);

    peek_user(map, (unsigned int)wrappedaik, kaik, wrappedaiklen);
    peek_user(map, (unsigned int)enc, kenc, enclen);

    ret = TPM_ActivateIdentity(kaik, 
			       kenc, enclen,
			       ksymkey, &kclearlen);
    if(ret < 0){
      ret = -NSK_ERR_UNLOCK;
      goto unlock_tpm_err;
    }

    poke_user(map, (unsigned int)clearlen, &kclearlen, sizeof(int));
    poke_user(map, (unsigned int)clear, ksymkey, kclearlen);

    ret = 0;

  unlock_tpm_err:
    gfree(kaik);
    gfree(kenc);
    gfree(ksymkey);

    return ret;
  }

  interface int or_nrk_request_nexus_certification(unsigned char *wrappedaik, int wrappedaiklen,
					    KVKey_tpm *nsrk, int is_nrk,
					    unsigned char *req, int *reqlen){
    Map *map = nexusthread_current_map();
    int kreqlen = TCPA_CERTIFY_REQ_SIZE + 8 * 20 + 1;
    int kcertlen = TCPA_CERTIFY_INFO_SIZE;
    int ksiglen = TCPA_SIG_SIZE;
    int kavaillen;

    if(wrappedaiklen != sizeof(KeyData))
      return -NSK_ERR_PARAM;

    peek_user(map, (unsigned int)reqlen, &kavaillen, sizeof(int));
    
    if(kavaillen < kreqlen)
      return -NSK_ERR_OUTSPACE;


    KeyData *kaik = (KeyData *)galloc(wrappedaiklen);
    KeyData *knsrk = (KeyData *)galloc(sizeof(KeyData));

    unsigned char *kcert = (unsigned char *)galloc(kcertlen);
    unsigned char *ksig = (unsigned char *)galloc(ksiglen);
    unsigned char *kreq = (unsigned char *)galloc(kreqlen);

    CertifyKeyData *certifydata = (CertifyKeyData *)galloc(sizeof(CertifyKeyData));

    peek_user(map, (unsigned int)wrappedaik, kaik, wrappedaiklen);
    assert(sizeof(nsrk->wrappedkey) == sizeof(KeyData));
    peek_user(map, (unsigned int)nsrk->wrappedkey, knsrk, sizeof(KeyData));
    
    unsigned char *spass = get_spass();
    unsigned int kaikhandle;
    unsigned int knsrkhandle;
    int ret;

    ret = TPM_LoadKey(TPM_KH_SRK, spass, kaik, &kaikhandle);
    if(ret != 0){
      ret = -NSK_ERR_LOAD;
      printk_red("could not load tpm aik\n");
      goto createkey_err;
    }

    ret = TPM_LoadKey(TPM_KH_SRK, spass, knsrk, &knsrkhandle);
    if(ret != 0){
      ret = -NSK_ERR_LOAD;
      printk_red("could not load tpm srk\n");
      goto createkey_err;
    }

    /* XXX is nonce necessary? */
    unsigned char knonce[TCPA_NONCE_SIZE];
    memset(knonce, 0, TCPA_NONCE_SIZE);

    ret = TPM_CertifyKey(knsrkhandle, spass, 
			 kaikhandle, spass,
			 knonce, 
			 ksig, &ksiglen,
			 kcert, &kcertlen);
    TPM_EvictKey(kaikhandle);
    TPM_EvictKey(knsrkhandle);
    if(ret != 0){
      ret = -NSK_ERR_CERTIFY;
      printk_red("could not certify tpm key\n");
      goto createkey_err;
    }
    assert(ksiglen == TCPA_SIG_SIZE);
    assert(kcertlen == TCPA_CERTIFY_INFO_SIZE);

    ExtractCertifyKeyData(certifydata, kcert, &knsrk->pub, ksig);
    kreqlen = BuildCertifyKeyReq(kreq, certifydata);
    assert(kreqlen > 0 && kreqlen <= TCPA_CERTIFY_REQ_SIZE);

    kreq[kreqlen++] = (is_nrk ? 1 : 0);

    int i;
    for (i = 0; i < 8; i++) {
      int err = TPM_PcrRead(i, &kreq[kreqlen]);
      if (err)
	printk_red("error reading pcr %d\n", i);
      kreqlen += 20;
    }
    
    poke_user(map, (unsigned int)reqlen, &kreqlen, sizeof(int));
    poke_user(map, (unsigned int)req, kreq, kreqlen);
    
    ret = 0;
  createkey_err:
    gfree(kaik);
    gfree(knsrk);
    gfree(kcert);
    gfree(ksig);
    gfree(kreq);
    gfree(certifydata);

    return ret;
  }


}
