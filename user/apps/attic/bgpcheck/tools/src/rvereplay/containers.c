#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <strings.h>
#include "containers.h"

void g_warning(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fputc('\n', stderr);
}


/************************************************************/
/*                                                          */
/*                           ARRAYS                         */
/*                                                          */
/************************************************************/
GArray *g_array_new(gboolean zero_terminated, gboolean clear_, int elem_size) {
	g_return_val_if_fail(elem_size > 0, NULL);
	g_return_val_if_fail(!clear_, NULL);  /* not implemented */
	GArray *ret = g_new(GArray, 1);
	ret->elem_size = elem_size;
	ret->len = ret->alloc = 0;
	ret->data = NULL;
	ret->zero_terminated = zero_terminated ? 1 : 0;
	return ret;
}

void g_array_free(GArray *arr, gboolean free_seg) {
	g_return_if_fail(arr);
	if (free_seg && arr->data) g_free(arr->data);
	g_free(arr);
}

void g_array_append_vals(GArray *arr, const void *data, int count) {
	int space_needed = arr->len + arr->zero_terminated + count;
	if (space_needed > arr->alloc) {
		if (!arr->alloc) arr->alloc = 1;
		while (arr->alloc < space_needed) arr->alloc <<= 1;
		arr->data = (char*)g_realloc(arr->data, arr->alloc * arr->elem_size);
	}
	memcpy((char*)arr->data + arr->len*arr->elem_size, data,
		count*arr->elem_size);
	arr->len += count;
	if (arr->zero_terminated)
		bzero((char*)arr->data + arr->len*arr->elem_size, arr->elem_size);
}

void g_array_remove_index(GArray *arr, int idx) {
	if (idx != arr->len - 1)
		memmove(arr->data + idx*arr->elem_size, arr->data + (idx+1)*arr->elem_size,
			(arr->len - idx - 1)*arr->elem_size);
	arr->len--;
}

void g_array_remove_index_fast(GArray *arr, int idx) {
	if (idx != arr->len - 1)
		memcpy(arr->data + idx*arr->elem_size,
			arr->data + (arr->len-1)*arr->elem_size, arr->elem_size);
	arr->len--;
}



/************************************************************/
/*                                                          */
/*                        HASH TABLES                       */
/*                                                          */
/************************************************************/

static int hash_sizes[] = {
	53, 97, 193, 389, 769, 1543, 3079, 6151, 12289, 24593, 49157, 98317, 196613,
	393241, 786433, 1572869, 3145739, 6291469, 12582917, 25165843, 50331653,
	100663319, 201326611, 402653189, 805306457, 1610612741
};

typedef struct _HashKV {
	gpointer key, val;
	struct _HashKV *next;
} HashKV;

static HashKV *hash_kv_new(gpointer key, gpointer val, HashKV *next) {
	HashKV *ret = g_new(HashKV, 1);
	ret->key = key;
	ret->val = val;
	ret->next = next;
	return ret;
}

static void g_hash_table_grow(GHashTable *table) {
	g_return_if_fail(table);
	int new_size = hash_sizes[table->size_idx + 1];
	HashKV **new_data = g_new0(HashKV*, new_size);
	int i, remain=table->count;
	for (i=0; i<hash_sizes[table->size_idx]; i++) {
		HashKV *p = table->data[i];
		while (p) {
			int n = table->hash(p->key) % new_size;
			new_data[n] = hash_kv_new(p->key, p->val, new_data[n]);
			remain--;
			HashKV *next = p->next;
			g_free(p);
			p = next;
		}
	}
	g_assert(remain == 0);
	g_free(table->data);
	table->data = new_data;
	table->size_idx++;
}

GHashTable *g_hash_table_new(GHashFunc hash, GCompareFunc cmp) {
	return g_hash_table_new_full(hash, cmp, NULL, NULL);
}

GHashTable *g_hash_table_new_full(GHashFunc hash, GCompareFunc cmp,
		GDestroyNotify keydel, GDestroyNotify valdel) {
	g_return_val_if_fail(hash, NULL);
	g_return_val_if_fail(cmp, NULL);
	GHashTable *ret = g_new(GHashTable, 1);
	ret->hash = hash;
	ret->cmp = cmp;
	ret->keydel = keydel;
	ret->valdel = valdel;
	ret->size_idx = ret->count = 0;
	ret->data = g_new0(HashKV*, hash_sizes[ret->size_idx]);
	return ret;
}

void g_hash_table_destroy(GHashTable *hash) {
	g_return_if_fail(hash);

	int i;
	for (i=0; i<hash_sizes[hash->size_idx]; i++) {
		HashKV *p = hash->data[i];
		while (p) {
			hash->count--;
			HashKV *next = p->next;
			if (hash->keydel) hash->keydel(p->key);
			if (hash->valdel) hash->valdel(p->val);
			g_free(p);
			p = next;
		}
	}
	g_assert(hash->count == 0);
	g_free(hash->data);
	g_free(hash);
}

void g_hash_table_insert(GHashTable *hash, gpointer key, gpointer val) {
	g_return_if_fail(hash);
	if (hash->count+1 > hash_sizes[hash->size_idx]/3)
		g_hash_table_grow(hash);
	int n = hash->hash(key) % hash_sizes[hash->size_idx];
	HashKV *p;
	for (p=hash->data[n]; p; p=p->next)
		if (hash->cmp(key, p->key)) {
			if (hash->keydel) hash->keydel(key);
			if (hash->valdel) hash->valdel(p->val);
			p->val = val;
			return;
		}
	hash->data[n] = hash_kv_new(key, val, hash->data[n]);
	hash->count++;
}

void g_hash_table_remove(GHashTable *hash, gconstpointer key) {
	g_return_if_fail(hash);
	int n = hash->hash(key) % hash_sizes[hash->size_idx];
	HashKV **p=&hash->data[n];
	for (p=&hash->data[n]; *p; p=&(*p)->next)
		if (hash->cmp(key, (*p)->key)) {
			if (hash->keydel) hash->keydel((*p)->key);
			if (hash->valdel) hash->valdel((*p)->val);
			*p = (*p)->next;
			hash->count--;
			return;
		}
	g_warning("g_hash_table_remove: element not found");
}

void *g_hash_table_lookup(GHashTable *hash, gconstpointer key) {
	g_return_val_if_fail(hash, NULL);
	int n = hash->hash(key) % hash_sizes[hash->size_idx];
	HashKV *p;
	for (p=hash->data[n]; p; p=p->next)
		if (hash->cmp(key, p->key))
			return p->val;
	return NULL;
}

gboolean g_hash_table_lookup_extended(GHashTable *hash, gconstpointer key,
    gpointer *okey, gpointer *val) {
	g_return_val_if_fail(hash, FALSE);
	int n = hash->hash(key) % hash_sizes[hash->size_idx];
	HashKV *p;
	for (p=hash->data[n]; p; p=p->next)
		if (hash->cmp(key, p->key)) {
			*okey = p->key;
			*val = p->val;
			return TRUE;
		}
	return FALSE;
}

void g_hash_table_foreach(GHashTable *hash, GHFunc func, gpointer data) {
	g_return_if_fail(hash);
	g_return_if_fail(func);

	int i;
	for (i=0; i<hash_sizes[hash->size_idx]; i++) {
		HashKV *p = hash->data[i];
		while (p) {
			func(p->key, p->val, data);
			p = p->next;
		}
	}
}

guint g_direct_hash(gconstpointer key) {
	return GPOINTER_TO_INT(key);
}

gint g_direct_equal(gconstpointer a, gconstpointer b) {
	return a == b;
}

guint g_str_hash(gconstpointer key) {
	guint h = 0;
	const char *p;
	for (p=key; *p; p++)
		h = (h << 5) - h + *p;
	return h;
}

gint g_str_equal(gconstpointer a, gconstpointer b) {
	return strcmp(a, b) == 0;
}




char *g_strndup(const char *str, int count) {
	const char *end = memchr(str, '\0', count);
	int len = end ? end-str : count;
	char *ret;
	ret = g_new(char, len+1);
	memcpy(ret, str, len);
	ret[len] = '\0';
	return ret;
}

char *g_strchomp(char *str) {
	char *p = str + strlen(str) - 1;
	while (p > str && isspace((int)*p)) *(p--) = '\0';
	return str;
}

char *g_ascii_strdown(const char *str, int len) {
	int i;
	char *ret = g_strndup(str, len);
	for (i=0; i<len; i++)
		ret[i] = tolower(ret[i]);
	return ret;
}

char *g_ascii_strup(const char *str, int len) {
	int i;
	char *ret = g_strndup(str, len);
	for (i=0; i<len; i++)
		ret[i] = toupper(ret[i]);
	return ret;
}

char *g_strdup_printf(const char *fmt, ...) {
	char *ret;
	va_list args;
	va_start(args, fmt);
	ret = g_strdup_vprintf(fmt, args);
	va_end(args);
	return ret;
}

char *g_strdup_vprintf(const char *fmt, va_list args) {
	char *ret = g_new(char, 1000);
	int len = vsnprintf(ret, 1000, fmt, args);
	ret = g_realloc(ret, len+1);
	return ret;
}

char *g_strconcat(const char *s1, ...) {
	g_return_val_if_fail(s1, NULL);
	int len = strlen(s1);
	const char *s;
	char *ret, *p;
	va_list args, args_copy;
	va_start(args, s1);
	va_copy(args_copy, args);
	/* get the total length */
	s = va_arg(args, const char*);
	while (s) {
		len += strlen(s);
		s = va_arg(args, const char*);
	}
	len++;  /* trailing \0 */

	/* perform the copy */
	ret = g_new(char, len);
	strcpy(ret, s1);
	p = ret + strlen(ret);
	s = va_arg(args_copy, const char*);
	while (s) {
		strcpy(p, s);
		p += strlen(p);
		s = va_arg(args_copy, const char*);
	}

	return ret;
}

char *g_strstrip(char *s) {
	char *left, *right;
	for (left=s; *left && isspace((int)*left); left++) ;
	right = left + strlen(left) - 1;
	while (right >= left && isspace((int)*right)) *(right--) = '\0';
	return left;
}

char **g_strsplit(const char *str, const char *delim, int max_tokens) {
	g_return_val_if_fail(str != NULL, NULL);
	g_return_val_if_fail(delim != NULL, NULL);
	g_return_val_if_fail(delim[0] != '\0', NULL);

	if (str[0] == '\0') {
		char **ret = g_new(char*, 1);
		ret[0] = NULL;
		return ret;
	}

	GArray *ret = g_array_new(TRUE, FALSE, sizeof(char*));

	int delim_len = strlen(delim);
	const char *p, *end = str+strlen(str);
	for (p=str; p<=end; ) {
		char *sep;
		/* if max_tokens is less than 1, we split the whole string, because the
		 * first part of this condition is never true */
		if (ret->len == max_tokens-1 || (sep = strstr(p, delim)) == NULL) {
			char *copy = g_strdup(p);
			g_array_append_val(ret, copy);
			break;
		}
		else {
			char *copy = g_strndup(p, sep-p);
			g_array_append_val(ret, copy);
			p = sep + delim_len;
		}
	}
	g_assert(ret->len <= max_tokens || max_tokens < 1);

	char **ret_vec = (char**)ret->data;
	g_array_free(ret, FALSE);
	return ret_vec;
}

void g_strfreev(char **str_array) {
	if (!str_array) return;
	char **p;
	for (p=str_array; *p; p++) g_free(*p);
	g_free(str_array);
}
