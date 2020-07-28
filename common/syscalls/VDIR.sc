syscall VDIR {
  /* Audited 5/12/2006 */
  decls {
    includefiles { "<nexus/policy.h>" }
  }
  decls __callee__ {
    includefiles { "<nexus/defs.h>" }
    includefiles { "<nexus/ipd.h>" }
    includefiles { "<nexus/tftp.h>" }
    includefiles { "<nexus/thread-inline.h>" }
    includefiles { "<nexus/vdir.h>" }

    unsigned int sys_vdirkeycreate(VDirKeyType which, 
				   char *user_name,
				   unsigned char *initsrc, int initsrclen,
				   /*unsigned char *initdest, int *initdestlen,*/
				   POLICY user_write_policy,
				   POLICY user_read_policy,
				   POLICY user_destroy_policy,
				   void *timing){

      // Audited 6/2/2006: Params safe
      // user_name: uses peek_strdup()
      // which: trusted
      // timing: uses safe interface, but doesn't verify copy success (not strictly needed since this is Nexus debugging code)
      char *name = NULL;
      int err;

      POLICY write_policy = user_write_policy;
      POLICY read_policy = user_read_policy;
      POLICY destroy_policy = user_destroy_policy;

      unsigned char *tmpdest = NULL, *initdata = NULL;
      //int tmpdestlen;
      //int ret;

      /* ensure the vdir initial value is 20 bytes*/
      if(which == VDIR_TYPE){
	if((initsrc == NULL) || (initsrclen != TCPA_HASH_SIZE)){
	  err = -SC_INVALID;
	  goto out_dealloc;
	}
      }

      /* ensure there is a src and dest, and preliminary check the
	 amount of space in dest. */
      if(which == VKEY_TYPE){
	if((initsrc == NULL) || (initsrclen <= 0)){
	  err = -SC_INVALID;
	  goto out_dealloc;
	}
#if 0
	ret = peek_user(nexusthread_current_map(), (unsigned int)initdestlen, &tmpdestlen, sizeof(unsigned int));
	if(ret < 0){
	  err = -SC_NOPERM;
	  goto out_dealloc;
	}
	if((initdest == NULL) || (tmpdestlen < initsrclen)){
	  err = -SC_INVALID;
	  goto out_dealloc;
	}
	tmpdest = (unsigned char *)galloc(tmpdestlen);
	if(tmpdest == NULL){
	  err = -SC_NOMEM;
	  goto out_dealloc;
	}
#endif
      }

      /* get the initial value into initdata */
      initdata = (unsigned char *)galloc(initsrclen);
      if(initdata == NULL){
	err = -SC_NOMEM;
	goto out_dealloc;
      }
      if(peek_user(nexusthread_current_map(), (unsigned int)initsrc, initdata, initsrclen) != 0) {
	err = -SC_ACCESSERROR;
	goto out_dealloc;
      }

      /* get the name */
      int peek_err = 0;
      name = peek_strdup(nexusthread_current_map(), (unsigned)user_name, &peek_err);
      if(name == NULL) {
	err = -SC_NOMEM;
	goto out_dealloc;
      }
      switch(which){
      case VKEY_TYPE:
	err = vkey_create(name, initdata, initsrclen, /*tmpdest, &tmpdestlen, */
			  write_policy, read_policy, destroy_policy);
	break;
      case VDIR_TYPE:
	err = vdir_create(name, initdata, initsrclen, write_policy, read_policy, destroy_policy);
	break;
      default:
	err = -SC_INVALID;
      }

    out_dealloc:
      if(name != NULL)
	gfree(name);
      if(tmpdest != NULL)
	gfree(tmpdest);
      if(initdata != NULL)
	gfree(initdata);
      return err;
    }

    unsigned int sys_vdirkeylookup(char *user_name, VDirKeyType which, void *timing) {
      // Audited 6/2/2006 argument usage safe
      /* 
	 user_name: safe -- peek_strdup()
	 which: trusted
	 timing: peek_/poke_user ; return value is not checked, but is
	 used only by nexus debugging code
      */
      int err = 0;
      char *name = peek_strdup(nexusthread_current_map(),
			       (unsigned int) user_name, &err);
      if(name == NULL) {
	return -SC_ACCESSERROR;
      }

      int ret = ((which == VKEY_TYPE) ? vkey_lookup(name) : vdir_lookup(name));

      gfree(name);
      return ret;
    }

    int sys_vdirkeydestroy(int handle, GROUNDS user_destroy_grounds, VDirKeyType which, void *timing){
      // Audited 6/2/2006 : Arguments safe
      /* 
	 handle: depends on handling of handle in vdir_destroy() -- checked & fixed 6/2/2006
	 which: trusted
	 timing: uses peek/poke, no error check after copy -- safe
      */
      /* written 5/12/2006 */
      Map *m = nexusthread_current_map();

      GROUNDS destroy_grounds = user_destroy_grounds;

      if (((which == VKEY_TYPE) ? vkey_destroy(handle, destroy_grounds) : vdir_destroy(handle, destroy_grounds)) != 0) {
	return -SC_NOPERM;
      }

      return 0;
    }
  }

  interface int Create(char *user_name,
		       unsigned char *initval, int initlen,
		       POLICY user_write_policy,
		       POLICY user_read_policy,
		       POLICY user_destroy_policy,
		       void *timing) {
    // Audited 6/2/2006: see sys_vdir_create()
    return sys_vdirkeycreate(VDIR_TYPE,
			     user_name,
			     initval, initlen,
			     /*NULL, NULL,*/
			     user_write_policy,
			     user_read_policy,
			     user_destroy_policy,
			     timing);
  }
  interface int Lookup(char *user_name, void *timing) {
    // Audited 6/2/2006: see sys_vdir_lookup()
    return sys_vdirkeylookup(user_name, VDIR_TYPE, timing);
  }
  interface int Destroy(int handle, GROUNDS user_destroy_grounds, void *timing) {
    // Audited 6/2/2006: see sys_vdir_destroy()
    return sys_vdirkeydestroy(handle, user_destroy_grounds, VDIR_TYPE, timing);
  }
  interface int Rebind(void){
    printk("Rebind not yet designed\n");
    return -SC_INVALID;
  }
  interface int Write(int handle, GROUNDS user_write_grounds, unsigned char *user_data, void *timing) {
    // Audited 6/2/2006: Argument use safe
    /* Arguments:
       	handle: depends on vdir_write; checked 06/2/2006
	user_data: accessed with peek_user, return value checked
	timing: not used
    */
#define DBG_VDIR_WRITE (0)
    Map *m = nexusthread_current_map();
    unsigned int ret = 0;
    unsigned char data[TCPA_HASH_SIZE];

    if(peek_user(m, (unsigned)user_data, (char *)data, TCPA_HASH_SIZE) != 0) {
      return -SC_ACCESSERROR;
    }

    if(DBG_VDIR_WRITE){
      printk_red("vdir_write: data = %02x %02x %02x %02x %02x\n", data[0], data[1], data[2], data[3], data[4]);
    }

    GROUNDS write_grounds = user_write_grounds;

    if(vdir_write(handle, data, write_grounds) != 0) {
      ret = -SC_NOPERM;
    }
    return ret;
  }
  interface int Read(int handle, GROUNDS user_read_grounds, unsigned char *user_data, void *timing) {
    // Audited 6/2/2006: Argument use safe
    /* 
       	handle: depends on handle use in vdir_read() -- checked 6/2/2006 and found to be good
	user_data: poke_user used, error checked
	timing: not used
    */
    Map *m = nexusthread_current_map();
    unsigned int ret = 0;
    unsigned char data[TCPA_HASH_SIZE];

    GROUNDS read_grounds = user_read_grounds;

    if(vdir_read(handle, data, read_grounds) == 0) {
      if(poke_user(m, (unsigned) user_data, data, TCPA_HASH_SIZE) != 0) {
	ret = -SC_ACCESSERROR;
      }
    } else {
      ret = -SC_NOPERM;
    }

    return ret;
  }
}
