syscall Crypto {

  decls __callee__ {
    includefiles { "<nexus/defs.h>" }
    includefiles { "<nexus/ipd.h>" }
    includefiles { "<libtcpa/tcpa.h>" }
    includefiles { "<nexus/thread-inline.h>" }
  }

  // XXX deprecated: use openssl in userspace
  interface int GetRandBytes(unsigned char *user_data, int num_bytes) {
    // rewritten 05/12/2006
    unsigned char *data = galloc(num_bytes);
    // make sure we don't leak any data from the kernel stack
    if(data == NULL) {
      return -SC_NOMEM;
    }
    memset(data, 0, num_bytes);
    int rv = RAND_bytes(data, num_bytes);
    if(poke_user(nexusthread_current_map(), (unsigned int)user_data, data, num_bytes) != 0) {
      rv = -SC_ACCESSERROR;
    }
    gfree(data);
    return rv;
  }
}
