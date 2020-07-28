#ifndef __LOG_H__
#define __LOG_H__

void klog_dump(NexusLog *log);
void klog_send(NexusLog *log, const char *filename);
char *klog_get(NexusLog *log);
void klog_display(NexusLog *log, int val);
void klog(NexusLog *log, char *fmt, ...);

NexusLog *klog_new(int size);
void klog_destroy(NexusLog *log);

void klog_clear(NexusLog *log);

int klog_size(NexusLog *log);
void klog_memcpy(NexusLog *log, char *dst);


void nexuslog_init(void);
NexusLog *klog_syslog(void);

void init_tracing(void);
void log_stack(void);
void log_trace(unsigned long *esp);
void show_trace(unsigned long *esp);


#define nexuslog(x...) klog(klog_syslog(), x)
#define nexusdumplog() klog_dump(klog_syslog())
#define nexussendlog(FNAME) klog_send(klog_syslog(), FNAME)
#define nexusgetlog() klog_get(klog_syslog())
#define nexusdisplaylog(x) klog_display(klog_syslog(),x);

#endif
