syscall Time {
  decls __callee__ {
    includefiles { "<nexus/defs.h>" }
    includefiles { "<nexus/mem.h>" }
    includefiles { "<nexus/clock.h>" }
    includefiles { "<nexus/thread-inline.h>" }
  }

  interface int 
  gettimeofday(void *user_tv) 
  {
  	return gettimeofday_posix(user_tv);
  }

  interface void 
  set_ntp_offset(int new_offset) 
  {
	ntp_offset = new_offset;
  }

  interface int 
  GetTicks(void) 
  {
  	return nexustime;
  }
}

