syscall VKey {
  decls {
    includefiles { "<nexus/policy.h>" }
  }
  decls __callee__ {
    includefiles {
		"<nexus/defs.h>",
		"<nexus/ipd.h>",
		"<nexus/vdir.h>"
	}
    includefiles { "<nexus/thread-inline.h>" }

    typedef enum VKeyReadOrWrite VKeyReadOrWrite;
    enum VKeyReadOrWrite{
      VKEY_READ = 1,
      VKEY_WRITE,
    };
    
  }

  interface int Create(char *user_name, 
		       unsigned char *src, int srclen,
		       /* unsigned char *dest, int *destlen, */
		       POLICY user_write_policy,
		       POLICY user_read_policy,
		       POLICY user_destroy_policy,
		       void *timing) {
    return sys_vdirkeycreate(VKEY_TYPE, 
			     user_name, 
			     src, srclen,
			     /*dest, destlen,*/
			     user_write_policy,
			     user_read_policy,
			     user_destroy_policy,
			     timing);
  }
  interface int Lookup(char *user_name, void *timing) {
    // Audited 6/3/2006 -- depends on sys_vdirkeylookup() (which was checked on 6/2/2006)
    return sys_vdirkeylookup(user_name, VKEY_TYPE, timing);
  }
  interface int Destroy(int handle, GROUNDS user_destroy_grounds, void *timing) {
    // Audited 6/3/2006 -- depends on sys_vdirkeydestroy() (which was checked on 6/2/2006)
    return sys_vdirkeydestroy(handle, user_destroy_grounds, VKEY_TYPE, timing);
  }
  interface int Rebind(void){
    printk("Rebind not yet designed\n");
    return -SC_INVALID;
  }
  interface int Read(int handle, GROUNDS user_read_grounds,
		     /*char *user_enc_key, int enc_key_len,*/
		     unsigned char *user_key, int max_key_len,
		     void *timing) {
    unsigned char *output = NULL;
    int outputlen = max_key_len;
    Map *m = nexusthread_current_map();

    output = (unsigned char *)galloc(outputlen);
    if(output == NULL) {
      outputlen = -SC_NOMEM;
      goto out_dealloc;
    }

    GROUNDS read_grounds = user_read_grounds;

    if(vkey_read(handle, output, &outputlen, read_grounds) != 0) {
      printk_red("vkey_read() error\n");
      outputlen = -SC_NOPERM;
      goto out_dealloc;
    }

    if(outputlen > 0) {
      if(poke_user(m, (unsigned int)user_key,
		   output, outputlen) != 0) {
	outputlen = -SC_ACCESSERROR;
	goto out_dealloc;
      }
    }

  out_dealloc:
    if(output != NULL) {
      gfree(output);
    }

    return outputlen;
  }

  interface int Write(int handle, GROUNDS user_write_grounds, 
		      unsigned char *user_key, int key_len,
		      /*char *user_enc_key, int max_enc_key_len,*/
		      void *timing) {
    unsigned char *data = NULL;
    int outputlen = 0;
    Map *m = nexusthread_current_map();

    data = (unsigned char *)galloc(key_len);
    if(data == NULL) {
      return -SC_NOMEM;
    }
    if(peek_user(m, (unsigned int)user_key, data, key_len) != 0) {
      outputlen = -SC_ACCESSERROR;
      goto out_dealloc;
    }

    GROUNDS write_grounds = user_write_grounds;

    if(vkey_write(handle, user_key, key_len, write_grounds) != 0) {
      printk_red("vkey_write() error\n");
      outputlen = -SC_NOPERM;
      goto out_dealloc;
    }

  out_dealloc:
    if(data != NULL) {
      gfree(data);
    }

    return outputlen;
  }
}

