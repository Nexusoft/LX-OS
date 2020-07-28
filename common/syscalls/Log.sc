syscall Log {
  decls {
    struct LOG___ignored {
      // unused struct to get following #defines to expand
#define NEXUS_SYSLOG "nexuslog"

#define Log_PrintStandard(FMT, ...) 	Log_Print(NEXUS_SYSLOG, FMT, __VA_ARGS__)
#define Log_DumpStandard(FMT)  		Log_Dump(NEXUS_SYSLOG)

    };
  }

  decls __callee__ {
    includefiles { "<nexus/defs.h>" }
    includefiles { "<nexus/ipd.h>" }
    includefiles { "<nexus/log.h>" }

    includefiles { "<nexus/synch.h>" }
    includefiles { "<nexus/synch-inline.h>" }
    includefiles { "<nexus/hashtable.h>" }

    static Sema *log_table_mutex;
    static struct HashTable *log_table; // char * => NexusLog *

    static NexusLog *log_find(char *log_name) {
      return hash_findItem(log_table, log_name);
    }

  }

  decls __caller__ {
    	includefiles { "<stdio.h>" }
    	includefiles { "<string.h>" }
    	includefiles { "<stdarg.h>" }

	/* logging for debugging in Nexus */
	void Log_Print(char *log_name, char *fmt, ...) {
	  va_list args;
	  char printk_buf[1024];
	  int len;
	  int i;

	  /* Emit the output into the temporary buffer */
	  va_start(args, fmt);
	  len = vsnprintf(printk_buf, sizeof(printk_buf) - 1, fmt, args);
	  va_end(args);

	  for(i = 0; i < len; ++i) {
	    Log_PrintChar(NEXUS_SYSLOG, printk_buf[i]);
	  }
	}
  }

  __callee__ {
    log_table_mutex = sema_new_mutex();
    log_table = hash_new_vlen(16, hash_strlen);

    P(log_table_mutex);
    hash_insert(log_table, NEXUS_SYSLOG, klog_syslog());
    V(log_table_mutex);
  }

  interface int PrintChar(char *log_name_user, int c) {
     /* Audited 5/30/2006: Safe */

     // Examined nexuslog()

     // This usage of nexuslog() is safe because printing a single
     // charater to the klog linebuf will not overflow the buffer.

     // linebuf is transferred copied character-by-character to the
     // target, a circular buffer.

#define COPY_NAME()							\
    int err = 0;							\
    char *name =							\
      peek_strdup(nexusthread_current_map(), (unsigned int)log_name_user, &err); \
    if(name == NULL || err != 0) {					\
      printk_red("could not copy name\n");				\
      return -SC_ACCESSERROR;						\
    }

#define LOG_FIND()							\
    P(log_table_mutex);							\
    NexusLog *log = log_find(name);					\
    V(log_table_mutex);							\
									\
    if(log == NULL) {							\
      printk_red("could not find log '%s'\n", name);			\
      gfree(name);							\
      return -SC_INVALID;						\
    }									\
    gfree(name);

    COPY_NAME();
    LOG_FIND();

    klog(log, "%c", c);
    return 0;
  }

  interface int Dump(char *log_name_user) {
    /* Audited 5/30/2006: Safe */

    // Examined nexusdumplog(). nexusdumplog() should be safe so long
    // as klog_syslog() returns a valid log 
    // (0 <= log->istart <LOGSIZE, and 
    // log->log is pointer to array of size at least LOGSIZE.

    COPY_NAME();
    LOG_FIND();
    klog_dump(log);
    return 0;
  }

  interface int GetLen(char *log_name_user) {
    COPY_NAME();
    LOG_FIND();
    return strlen(klog_get(log));
  }

  interface int GetData(char *log_name_user, char *dest_user, int max_size) {
    COPY_NAME();
    LOG_FIND();

    Map *m = nexusthread_current_map();

    printk("Getting log:\n");
    printk("%s", klog_get(log));

    if(poke_strncpy(m, (unsigned) dest_user, klog_get(log), max_size) != 0) {
      return -SC_ACCESSERROR;
    } else {
      return 0;
    }
  }

  interface int Clear(char *log_name_user) {
    COPY_NAME();
    LOG_FIND();
    klog_clear(log);
    return 0;
  }

  interface int Create(char *log_name_user, int log_len) {
    COPY_NAME();

    P(log_table_mutex);
    NexusLog *log = log_find(name);

    if(log != NULL) {
      printk_red("log named '%s' already exists\n", name);
      err = -SC_INVALID;
      goto err;
    }

    log = klog_new(log_len);
    if(log == NULL) {
      err = -SC_NOMEM;
      goto err;
    }
    hash_insert(log_table, name, log);

  err:
    gfree(name);
    V(log_table_mutex);
    return err;
  }
}
