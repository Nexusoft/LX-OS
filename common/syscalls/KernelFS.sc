syscall KernelFS {
  /* Except for the SetFSRoot call, this is really a debugging file, and is not
   * to be confused with lower-case "kernelfs" which is the kernel's reflection
   * service */
  decls {
    includefiles { "<nexus/fs.h>" }
  }

  decls __callee__ {
    includefiles { "<nexus/defs.h>" }
    includefiles { "<nexus/ipd.h>" }
    includefiles { "<nexus/tftp.h>" }
    includefiles { "<nexus/thread-inline.h>" }
    includefiles { "<nexus/kernelfs.h>" }

    int ignore_file(char *pathname) {
      if(strcmp(pathname,"/dev/urandom") == 0) {
	printk("/dev/random, ignoring\n");
	return 1;
      }
      if(strcmp(pathname,"/dev/random") == 0) {
	printk("/dev/random, ignoring\n");
	return 1;
      }
      if(strcmp(pathname,"/dev/srandom") == 0) {
	printk("/dev/srandom, ignoring\n");
	return 1;
      }
      return 0;
    }
  }

  interface int SetRoot(FSID fsid) {
    return 0;
  }

  // these should be deprecated
  interface int TFTP_Get(const char *user_pathname, char *user_dest, int max_len) {
    /* Audited 5/9/2006 */
    Map *current_map = nexusthread_current_map();
    int size;
#define MAX_PATHNAME (1024)
    char pathname[MAX_PATHNAME];

    if(peek_strncpy(current_map, (unsigned int)user_pathname, pathname, MAX_PATHNAME) != 0) {
      return -SC_ACCESSERROR;
    }

    if(ignore_file(pathname)) return 0;
    if (fetchpoke_file(pathname, &size, current_map, (unsigned)user_dest, max_len) == -1)
      return -SC_ACCESSERROR;

    return size;
  }

  interface int TFTP_Put(char *user_pathname, char *user_src, int len) {
    /* Audited 5/9/2006 */
    Map *current_map = nexusthread_current_map();
    char pathname[MAX_PATHNAME];

    if(peek_strncpy(current_map, (unsigned int)user_pathname, pathname, MAX_PATHNAME) != 0) {
      return -SC_ACCESSERROR;
    }

    if(ignore_file(pathname)) return 0;
    peeksend_file((char *)pathname, current_map, (unsigned)user_src, len);
    return 0;
  }

  interface int Cache_Add(char *user_fname, char *user_data, int size) {
    /* Audited 5/10/2006 */
    // Removed unsafe memcpy()s

    // Duplicate the file
    char *dup = galloc(size);
    if(dup == NULL) {
      printk("could not duplicate file\n");
      return -SC_NOMEM;
    } else {
#define MAX_FNAME (256)
      char filename[MAX_FNAME];
      if(peek_strncpy(nexusthread_current_map(),
		      (unsigned int)user_fname, filename, MAX_FNAME) != 0) {
	return -SC_ACCESSERROR;
      }
      if(peek_user(nexusthread_current_map(),
		   (unsigned int)user_data, dup, size) != 0) {
	gfree(dup);
	return -SC_ACCESSERROR;
      }
      cache_add(filename, dup, size);
#if 0
      int i;
      int sum = 0;
      for(i=0; i < size; i++) {
	sum += file[i];
      }
      printk("checksum is %d\n", sum);
#endif
      return size;
    }
  }

  interface int GetFileLen(const char *user_fname) {
    /* audited 5/11/2006 */
    char filename[MAX_FNAME];
    if(peek_strncpy(nexusthread_current_map(), (unsigned int) user_fname, filename, MAX_FNAME) != 0) {
      return -SC_ACCESSERROR;
    }
    int size;
    cache_find(filename, &size);
    return size;
  }

  interface int SetEnv(const char *user_env_name, const char *user_env_val, int val_len) {
    char env_name[MAX_FNAME], env_val[MAX_FNAME];

    if(peek_strncpy(nexusthread_current_map(), (unsigned int) user_env_name, env_name, MAX_FNAME) != 0) {
      printk_red("Could not get env name\n");
      return -SC_ACCESSERROR;
    }
    if(val_len > MAX_FNAME) {
      printk_red("Bad env val len\n");
      return -SC_INVALID;
    }
    if(copy_from_generic(nexusthread_current_map(), env_val, user_env_val, val_len) != 0) {
      printk_red("Could not get env value\n");
      return -SC_ACCESSERROR;
    }
    printk_green("Setting environment: %s => %s\n", env_name, env_val);
    KernelFS_setenv_bin(env_name, env_val, val_len);
    return 0;
  }

}

