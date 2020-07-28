syscall Attestation {

  decls{
    includefiles { "<libtcpa/keys.h>" }
  }

  decls __callee__ {
    includefiles { "<libtcpa/tcpa.h>" }
    includefiles { "<nexus/synch.h>" }
    includefiles { "<nexus/synch-inline.h>" }
  }

  interface int GetPubek(struct PubKeyData *upubek){
    PubKeyData kpubek;
    int ret;
    if((ret = TPM_ReadPubek(&kpubek)) < 0)
      return ret;
    poke_user(nexusthread_current_map(), (unsigned int)upubek, &kpubek, sizeof(struct PubKeyData));
    return 0;
  }

  interface int TakeOwnership(unsigned char *oenc, unsigned char *senc){
    extern int takeowner_syscall;
    extern int takeowner_result;
    extern Sema *takeowner_sema;

    // only allow ownership.app started from within the kernel.
    // what an ugly hack! 
    if (takeowner_syscall == 0)
      return -1;

    int oencsize, sencsize;
    oencsize = sencsize = RSA_MODULUS_BYTE_SIZE;
      
    unsigned char *koenc = (unsigned char *)galloc(oencsize);
    unsigned char *ksenc = (unsigned char *)galloc(sencsize);

    peek_user(nexusthread_current_map(), (unsigned int)oenc, koenc, oencsize);
    peek_user(nexusthread_current_map(), (unsigned int)senc, ksenc, sencsize);
    
    int ret = TPM_TakeOwnership(oencsize, koenc, sencsize, ksenc);
    if(ret != 0){
      printk_red("Take Ownership failed with %d\n", ret);
    }
    
    gfree(koenc);
    gfree(ksenc);

    takeowner_result = ret;
    V(takeowner_sema);

    return ret;
  }
}

