
#ifndef SAFE_MALLOC_H_SHIELD
#define SAFE_MALLOC_H_SHIELD

#ifdef __cplusplus
extern "C" {
void safe_malloc_init(void);
void *safe_malloc(size_t size);
void safe_free(void *val);
}
#else
void safe_malloc_init(void);
void *safe_malloc(size_t size);
void safe_free(void *val);
#endif

#endif
