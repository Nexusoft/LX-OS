syscall Profile {

  decls __callee__ {
    includefiles { "<nexus/defs.h>" }
    includefiles { "<nexus/ipc.h>" }
    includefiles { "<nexus/profile.h>" }
    includefiles { "<nexus/ipd.h>" }
    includefiles { "<nexus/tftp.h>" }
    includefiles { "<asm/param.h>" }
    includefiles { "<nexus/thread-inline.h>" }

    extern int profile_enabled;
    extern struct ProfileEntry *profile_sample_data;
    extern int profile_sample_count;
    extern int profile_sample_maxcount;

    unsigned int profile_alt_info;

    u64 last_profile_time = 0;
    s64 cumulative_missing_profile_cycles = 0;

    static int compute_measurement_error(int count){
      if(cumulative_missing_profile_cycles > TSC_PER_TICK) {
// kernel cannot perform 64 bit division: approximate
	long long delta = 
	  (cumulative_missing_profile_cycles + TSC_PER_TICK / 2)
	  / TSC_PER_TICK;
	printk_red("Cumu_missing = %lld (%lld)", cumulative_missing_profile_cycles, delta);
	cumulative_missing_profile_cycles = 0;

	// write the cumulative mising cycles as a last sample,
	// overwriting the last one if there is no space
	if(count == profile_sample_maxcount) {
	  count--;
	}
	memset(&profile_sample_data[count],
	       0, sizeof(profile_sample_data[count]));
	profile_sample_data[count].ipd_id = -1;
	profile_sample_data[count].thread_id = -1;
	profile_sample_data[count].address = delta;
	count++;
      }
      return count;
    }
    static void reset_sample_info(int saved){
      profile_sample_count = 0;
      profile_enabled = saved;
    }

  }
  interface int Enable(int x) {
    extern int profile_enabled;
    if(x) {
      if(profile_sample_data == NULL) {
	profile_sample_data = galloc(sizeof(profile_sample_data[0]) * profile_sample_maxcount);
      }
      last_profile_time = 0;
      cumulative_missing_profile_cycles = 0;
    }
    profile_enabled = x;
    return profile_enabled;
  }

  interface int Dump(const char *uname){
    int saved = profile_enabled;
    profile_enabled = 0;
    int count = profile_sample_count;
    count = compute_measurement_error(count);
    int len = count * sizeof(profile_sample_data[0]);

    int err;
    char *filename = peek_strdup(nexusthread_current_map(), (unsigned int)uname, &err);
    if(err != 0)
      return err;
    
    send_file(filename, (char *)profile_sample_data, len);
    gfree(filename);
    reset_sample_info(saved);

    return 0;
  }


  interface int ReadSamples(unsigned char *target) {
    int saved = profile_enabled;
    profile_enabled = 0;
    int count = profile_sample_count;
    count = compute_measurement_error(count);


    int len = count * sizeof(profile_sample_data[0]);
    poke_user(nexusthread_current_map(), (unsigned int) target, profile_sample_data,
	      len);

    reset_sample_info(saved);
    return len;
  }
}
