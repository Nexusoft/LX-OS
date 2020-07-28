#ifndef MALLOC_CHECKER_H
#define MALLOC_CHECKER_H

#define malloc_record(p,s,l,f) malloc_free_record("malloc",p,s,l,f)
#define free_record(p,s,l,f) malloc_free_record("free",p,s,l,f)
#define pagealloc_record(p,s,l,f) malloc_free_record("pagealloc",p,s,l,f)
#define pagefree_record(p,s,l,f) malloc_free_record("pagefree",p,s,l,f)

void malloc_free_record(const char *type, void *ptr, int size, int line, const char *filename);
void malloc_write_record(void);
int malloc_record_disabled(void);
void malloc_record_enable(void);

#endif
