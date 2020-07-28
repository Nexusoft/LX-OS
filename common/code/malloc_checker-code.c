
// note: this code exists in both userspace and kernelspace
// do not use any includes in this file

/* DANGER: don't use malloc in here unless you disable the malloc
 * recorder with record_off() and record_on() */

/* records to be written out to disk */
#define END_PADDING (20 * 1024)
char record[RECORDSIZE + END_PADDING];
char *recordptr = record;

int numrecords = 0;

static __attribute__((unused)) int __no_tls_disabled = 1;

#ifdef __NEXUSKERNEL__
int __disabled = 1;
#else
int __thread __disabled = 1;
#endif

#define OFFSET (recordptr - record)

static int RECORD_OFF(void){ 
  int ret = __disabled;
  __disabled = 1;
  return ret;
}

static void RECORD_ON(int restore){
  __disabled = restore;
}

#define TMPSIZE 256
void malloc_write_record(void){
  int recordstate = RECORD_OFF();
  char tmpname[TMPSIZE];
  int dbg=0;

  memset(tmpname, 0, TMPSIZE);
  snprintf(tmpname, TMPSIZE, "%s.%03d", FILEPREFIX, numrecords);
  if(dbg)PRINT("malloc checker writing record %s 0x%p %d\n", tmpname, record, OFFSET);

  WRITEFILE(record, OFFSET, tmpname);
  numrecords++;
    
  memset(record, 0, RECORDSIZE);
  recordptr = record;

  RECORD_ON(recordstate);
}

int malloc_record_disabled(void){
  return __disabled;
}

void malloc_record_enable(void){
  RECORD_ON(0);
}

#define TRACE_LEN 20
void malloc_free_record(const char *type, void *ptr, int size, int line, const char *filename){
  if(malloc_record_disabled())
    return;
  int recordstate = RECORD_OFF();

  //PRINT("malloc checker offset=%d/%d, numrecords=%d\n", OFFSET, RECORDSIZE, numrecords);

  int cont = 0;
  do{
    int space = RECORDSIZE - OFFSET;
    
    unsigned long addrs[TRACE_LEN];
    memset(addrs, 0, sizeof(addrs));
    
    GET_TRACE(addrs, TRACE_LEN);

    *recordptr = '\0';
    int num = snprintf(recordptr, space, 
		   "%s: 0x%p %d %s:%d "
		       "0x%lx 0x%lx 0x%lx 0x%lx 0x%lx "
		       "0x%lx 0x%lx 0x%lx 0x%lx 0x%lx "
		       "0x%lx 0x%lx 0x%lx 0x%lx 0x%lx\n",
		       type, ptr, size, filename, line,
		       addrs[0], addrs[1], addrs[2], addrs[3], addrs[4],
		       addrs[5], addrs[6], addrs[7], addrs[8], addrs[9],
		       addrs[10], addrs[11], addrs[12], addrs[13], addrs[14]
		       );

    /* not enough space for this record, write everything out */
    if(num > space || num <0){
      cont++;
      malloc_write_record();
    }else{
      recordptr += num;
      break;
    }
    if(cont > 1){
      PRINT("mallocchecker can't write malloc record!!!\n");
      assert(0);
    }
  }while(cont > 0);
  
  RECORD_ON(recordstate);
}


