#ifndef CONTAINERS_H
#define CONTAINERS_H

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { FALSE=0, TRUE } gboolean;
typedef int gint;
typedef unsigned int guint;
typedef void *gpointer;
typedef const void *gconstpointer;
typedef char gchar;

typedef struct _GArray {
	int len, alloc, elem_size;
	guint zero_terminated:1;
	char *data;
} GArray;

typedef unsigned int (*GHashFunc)(gconstpointer key);
typedef int (*GCompareFunc)(gconstpointer a, gconstpointer b);
typedef void (*GDestroyNotify)(gpointer p);
typedef void (*GHFunc)(gpointer key, gpointer val, gpointer data);
struct _HashKV;
typedef struct _GHashTable {
	GHashFunc hash;
	GCompareFunc cmp;
	GDestroyNotify keydel, valdel;
	struct _HashKV **data;
	int size_idx, count;
} GHashTable;

#define __stmt_start do{
#define __stmt_end }while(0)
#define g_assert(cond) __stmt_start if (!(cond)) { fprintf(stderr, "%s:%d: failed condition: %s\n", __FILE__, __LINE__, #cond); raise(SIGABRT); } __stmt_end
#define g_assert_not_reached() __stmt_start fprintf(stderr, "%s:%d: should not be reached\n", __FILE__, __LINE__); raise(SIGABRT); __stmt_end
#define g_return_if_fail(cond) __stmt_start if (!(cond)) { fprintf(stderr, "%s:%d: failed condition: %s\n", __FILE__, __LINE__, #cond); return; } __stmt_end
#define g_return_val_if_fail(cond,val) __stmt_start if (!(cond)) { fprintf(stderr, "%s:%d: failed condition: %s\n", __FILE__, __LINE__, #cond); return val; } __stmt_end

#define MAX(a,b) ({typeof(a) _a=(a); typeof(b) _b=(b); _a>_b?_a:_b;})
#define MIN(a,b) ({typeof(a) _a=(a); typeof(b) _b=(b); _a<_b?_a:_b;})
#define ABS(n) ({typeof(n) _n=(n); _n<0?-_n:_n;})
#define SWAP(a,b) do{typeof(a) _t=(a); (a)=(b); (b)=_t;}while(0)

#define GINT_TO_POINTER(i) ((gpointer)i)
#define GPOINTER_TO_INT(p) ((int)p)

void g_warning(const char *fmt, ...);

GArray *g_array_new(gboolean zero_terminated, gboolean clear_, int elem_size);
void g_array_free(GArray *arr, gboolean free_seg);
#define g_array_append_val(arr, val) g_array_append_vals(arr, &(val), 1)
#define g_array_index(arr, type, idx) (((type*)(arr)->data)[idx])
void g_array_append_vals(GArray *arr, gconstpointer data, int count);
void g_array_remove_index(GArray *arr, int idx);
void g_array_remove_index_fast(GArray *arr, int idx);

GHashTable *g_hash_table_new(GHashFunc hash, GCompareFunc cmp);
GHashTable *g_hash_table_new_full(GHashFunc hash, GCompareFunc cmp,
		GDestroyNotify keydel, GDestroyNotify valdel);
void g_hash_table_destroy(GHashTable *hash);
void g_hash_table_insert(GHashTable *hash, gpointer key, gpointer val);
void g_hash_table_remove(GHashTable *hash, gconstpointer key);
void *g_hash_table_lookup(GHashTable *hash, gconstpointer key);
gboolean g_hash_table_lookup_extended(GHashTable *hash, gconstpointer key,
		gpointer *okey, gpointer *val);
void g_hash_table_foreach(GHashTable *hash, GHFunc func, gpointer data);
guint g_direct_hash(gconstpointer key);
gint g_direct_equal(gconstpointer a, gconstpointer b);
guint g_str_hash(gconstpointer key);
gint g_str_equal(gconstpointer a, gconstpointer b);

#define g_new(type,count) (type*)g_malloc(count*sizeof(type))
#define g_new0(type,count) (type*)calloc(count, sizeof(type))
#define g_malloc malloc
#define g_strdup strdup
char *g_strndup(const char *str, int count);
#define g_free free
#define g_realloc realloc

char *g_strchomp(char *str);
char *g_ascii_strdown(const char *str, int len);
char *g_ascii_strup(const char *str, int len);
char *g_strdup_printf(const char *fmt, ...);
char *g_strdup_vprintf(const char *fmt, va_list args);
char *g_strconcat(const char *s1, ...);
char *g_strstrip(char *s);
char **g_strsplit(const char *str, const char *delim, int max_tokens);
void g_strfreev(char **str_array);

#ifdef __cplusplus
}
#endif

#endif
