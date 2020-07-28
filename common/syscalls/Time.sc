syscall Time {
  decls __callee__ {
    includefiles { "<nexus/defs.h>" }
    includefiles { "<nexus/ipd.h>" }
    includefiles { "<nexus/clock.h>" }
    includefiles { "<asm/param.h>" }
    includefiles { "<nexus/thread-inline.h>" }
  }

  interface int gettimeofday(struct timeval *user_tv) {
    struct nxtimeval tv;

    gettimeofday(&tv);
    if (poke_user_fast((unsigned int) user_tv, &tv, sizeof(tv)))
      return -SC_ACCESSERROR;

    return 0;
  }

  interface void set_ntp_offset(int new_offset) {
	// XXX use copy_from_user
  	memcpy(&ntp_offset, &new_offset, sizeof(int));
	nxcompat_printf("[ntp] seconds since 1970-01-01 set to %dB\n", ntp_offset);
  }

  interface int GetUSECPERTICK(void){
    return USECPERTICK;
  }
  interface int GetTSCCONST(void){
    return TSCCONST;
  }
}
