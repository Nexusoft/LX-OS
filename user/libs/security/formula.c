/** NexusOS: in-memory parsetree version of NAL formulas */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <nexus/defs.h>
#include <nexus/commontypedefs.h>
#include <nexus/der.h>
#include <nexus/formula.h>
#include <nexus/base64.h>
#include <nexus/pem.h>
#include <nexus/util.h>
#include <nexus/vector.h>
#include <nexus/hashtable.h>
#include <nexus/debug.h>

// no idea. comes from TCPA library
#define RSA_EXPONENT_BYTE_SIZE (3)
unsigned char rsa_default_exponent_array_g[] = {0x01,0x00,0x01};

struct softbreak {
  int pos;
  int badness;
};

struct print_ctx {
  int p; // print position
  int w; // print width
  int nsoftbreaks; 
  struct softbreak *softbreaks;
  int elide; // allow boring parts to be omitted
  int s_min, s_flags, s_cut /* = min/k */, s_compact;
  int b_min, b_flags, b_cut /* = min/k */, b_compact;
};

/* todo: refactor print calls to take pctx as an argument */
static struct print_ctx pctx = {
  p: 0, w: 0,
  nsoftbreaks: 0, softbreaks: NULL,
  elide: 0,
  s_min: 15, s_flags: 0x4 | 0x1, s_cut: 5, s_compact: 40,
  b_min: 10, b_flags: 0x4 | 0x1, b_cut: 3, b_compact: 50
};

int rank(Form *f, int *assoc) {
#define LEFT(r) do { if (assoc) *assoc = -1; return r; } while (0)
#define RIGHT(r) do { if (assoc) *assoc = +1; return r; } while (0)
#define NONASSOC(r) do { if (assoc) *assoc = 0; return r; } while (0)
  switch(f->tag) {
//%right SAYS FORALL EXISTS
    case F_STMT_FORALL:
    case F_STMT_EXISTS:
    case F_STMT_SAYS: RIGHT(20);
//%nonassoc IFF
    case F_STMT_IFF: NONASSOC(19);
//%right IMP 
    case F_STMT_IMP: RIGHT(18);
//%left OR
    case F_STMT_OR: LEFT(17);
//%left AND
    case F_STMT_AND: LEFT(16);
//%right NOT
    case F_STMT_NOT: RIGHT(15);
//%nonassoc SPEAKSFOR ON
    case F_STMT_SFOR:
    case F_STMT_SFORON: NONASSOC(14);
//%nonassoc LT GT LE GE EQ NE
    case F_PRED_LT:
    case F_PRED_GT:
    case F_PRED_LE:
    case F_PRED_GE:
    case F_PRED_EQ:
    case F_PRED_NE: NONASSOC(13);
//%nonassoc PLUS MINUS IN
    case F_TERM_PLUS:
    case F_TERM_MINUS:
    case F_PRED_IN: NONASSOC(10);
//%left DOT ODOT
    case F_TERM_CSUB:
    case F_TERM_OSUB: LEFT(5);
    default: NONASSOC(40); // remainder are considered very-low precedence / very-high rank, so they get parens
  }
}


Form *form_new(int tag, Form *left, Form *mid, Form *right) {
	Form *f = nxcompat_alloc(sizeof(Form));
	memset(f, 0, sizeof(Form));
	// sanity check on arity of formula
	switch (tag & F_ARITY_MASK) {
		case F_IS_EMPTY:   assert(!left && !mid && !right); break;
		case F_IS_UNARY:   assert( left && !mid && !right); break;
		case F_IS_BINARY:  assert( left && !mid &&  right); break;
		case F_IS_TERNARY: assert( left &&  mid &&  right); break;
		//case F_IS_DATA:  assert(0); break; // use form_newdata() instead
		//case F_IS_VALUE: assert(0); break; // use form_newval() instead
		default:	   assert(0); break;
	}
	f->tag = tag;
	f->left = left;
	f->mid = mid;
	f->right = right;
	return f;
}

Form *form_newdata(int tag, void *data, int len) {
	Form *f = nxcompat_alloc(sizeof(Form));
	memset(f, 0, sizeof(Form));
	// sanity check on arity and subtypes
	assert((tag & F_ARITY_MASK) == F_IS_DATA);
	if ((tag & F_SUBTYPE_MASK) == F_SUBTYPE_PREF)
	  assert(len == -1 && '%' == ((char *)data)[0]);
	if ((tag & F_SUBTYPE_MASK) == F_SUBTYPE_QVAR)
	  assert(len == -1 && '$' == ((char *)data)[0]);
	if ((tag & F_SUBTYPE_MASK) == F_SUBTYPE_SVAR)
	  assert(len == -1 && '$' != ((char *)data)[0] && ((char *)data)[0] != '%');
	f->tag = tag;
	f->data = data;
	f->len = len;
	return f;
}

Form *form_newval(int tag, int val) {
	Form *f = nxcompat_calloc(1, sizeof(Form));
	
	// sanity check on arity of formula
	assert((tag & F_ARITY_MASK) == F_IS_VALUE);
	
	f->tag = tag;
	f->value = val;
	return f;
}

void form_free(Form *f) {

	// free children
	if (f->left) form_free(f->left);
	if (f->mid) form_free(f->mid);
	if (f->right) form_free(f->right);
	
	// free contents
	switch (f->tag & F_ARITY_MASK) {
		case F_IS_VALUE: f->value = 0; break;
		case F_IS_DATA: nxcompat_free(f->data); f->data = 0; break;
		default: break;
	}

	// free node
	nxcompat_free(f);
}

Form *form_dup(Form *f) {
  return form_repl(f, NULL, NULL);
}

Form *form_repl(Form *f, Form *s, Form *v) {
  Form *f2;
  int len;

  if (s && v && !form_cmp(f, s)) 
	  return form_repl(v, NULL, NULL);

  f2 = nxcompat_alloc(sizeof(Form));
  memcpy(f2, f, sizeof(Form));
  
  switch (f->tag & F_ARITY_MASK) {
    case F_IS_TERNARY:
      if (f->mid) 
	      f2->mid = form_repl(f->mid, s, v);
      if (f->mid && !f2->mid) 
	      return NULL;
      // fall through
    case F_IS_BINARY:
      if (f->right) 
	      f2->right = form_repl(f->right, s, v);
      if (f->right && !f2->right) 
	      return NULL;
      // fall through
    case F_IS_UNARY:
      if (f->left) 
	      f2->left = form_repl(f->left, s, v);
      if (f->left && !f2->left) 
	      return NULL;
      // fall through
    case F_IS_EMPTY:
      break; // nothing to do
    case F_IS_VALUE:
      break; // done by copy, above
    case F_IS_DATA:
      len = (f->len < 0 ? strlen(f->data) + 1 : f->len);
      if (len < 1 || len > 1 << 20) {
	fprintf(stderr, "NXDEBUG: failing alloc() found: len=%d\n", len);
	return NULL;
      }
      f2->data = nxcompat_alloc(len);
      if (!f2->data) {
	fprintf(stderr, "NXDEBUG: failing alloc() found #3: len=%d\n", len);
	return NULL;
      }
      memcpy(f2->data, f->data, len);
      break;
    default:
      assert(0);
      return NULL; // todo: free partially copied formula
  }
  return f2;
}

Form *form_repl_all(Form *f, PointerVector *s_list, PointerVector *v_list) {
  if (s_list && v_list) {
    int i, n = PointerVector_len(s_list);;
    for (i = 0; i < n; i++) {
      Form *s = PointerVector_nth(s_list, i);
      if (!form_cmp(f, s)) {
	Form *v = PointerVector_nth(v_list, i);
	return form_dup(v);
      }
    }
  }
  Form *f2 = nxcompat_alloc(sizeof(Form));
  *f2 = *f;
  int len;
  switch (f->tag & F_ARITY_MASK) {
    case F_IS_TERNARY:
      if (f->mid) f2->mid = form_repl_all(f->mid, s_list, v_list);
      if (f->mid && !f2->mid) return NULL;
      // fall through
    case F_IS_BINARY:
      if (f->right) f2->right = form_repl_all(f->right, s_list, v_list);
      if (f->right && !f2->right) return NULL;
      // fall through
    case F_IS_UNARY:
      if (f->left) f2->left = form_repl_all(f->left, s_list, v_list);
      if (f->left && !f2->left) return NULL;
      // fall through
    case F_IS_EMPTY:
      break; // nothing to do
    case F_IS_VALUE:
      break; // done by copy, above
    case F_IS_DATA:
      len = (f->len < 0 ? strlen(f->data)+1 : f->len);
      f2->data = nxcompat_alloc(len);
      memcpy(f2->data, f->data, len);
      break;
    default:
      assert(0);
      return NULL; // todo: free partially copied formula
  }
  return f2;
}


int form_cmp(Form *f, Form *g) {
  if (f->tag != g->tag)
    return 1;
  switch (f->tag & F_ARITY_MASK) {
    case F_IS_TERNARY:
      if (!f->mid != !g->mid) return 1;
      if (f->mid && form_cmp(f->mid, g->mid)) return 1;
      // fall through
    case F_IS_BINARY:
      if (!f->right != !g->right) return 1;
      if (f->right && form_cmp(f->right, g->right)) return 1;
      // fall through
    case F_IS_UNARY:
      if (!f->left != !g->left) return 1;
      if (f->left && form_cmp(f->left, g->left)) return 1;
      return 0;
    case F_IS_EMPTY:
      return 0;
    case F_IS_VALUE:
      return f->value != g->value;
    case F_IS_DATA:
      if (f->len != g->len) return 1;
      if (f->len == 0) return 0;
      if (f->len < 0) return strcmp(f->data, g->data);
      return memcmp(f->data, g->data, f->len);
    default:
      return 1; 
  }
}

static char *tagname(int tag) {
	switch (tag & F_SUBTYPE_MASK) {
		case F_SUBTYPE_AND: return "and";
		case F_SUBTYPE_OR: return "or";
		case F_SUBTYPE_IMP: return "imp";
		case F_SUBTYPE_IFF: return "iff";
		case F_SUBTYPE_NOT: return "not";
		case F_SUBTYPE_SAYS: return "says";
		case F_SUBTYPE_SFOR: return "speaksfor";
		case F_SUBTYPE_FORALL: return "forall";
		case F_SUBTYPE_EXISTS: return "exists";
		case F_SUBTYPE_TRUE: return "true";
		case F_SUBTYPE_FALSE: return "false";

		case F_SUBTYPE_EQ: return "=";
		case F_SUBTYPE_GT: return ">";
		case F_SUBTYPE_LT: return "<";
		case F_SUBTYPE_GE: return ">=";
		case F_SUBTYPE_LE: return "<=";
		case F_SUBTYPE_NE: return "!=";
		case F_SUBTYPE_IN: return "in";

		case F_SUBTYPE_UNION: return "union";
		case F_SUBTYPE_JOIN: return "join";

		case F_SUBTYPE_CLOSED: return "closed";
		case F_SUBTYPE_OPEN: return "open";
		case F_SUBTYPE_PEM: return "pem";
		case F_SUBTYPE_DER: return "der";
		case F_SUBTYPE_ISPRIN: return "prin";
		case F_SUBTYPE_SIZE: return "size";
		case F_SUBTYPE_ISINT: return "int";
		case F_SUBTYPE_ISSTR: return "str";
		case F_SUBTYPE_ISBYTES: return "bytes";
		case F_SUBTYPE_ISTLIST: return "list";
		case F_SUBTYPE_ISTSET: return "set";

		case F_SUBTYPE_CSUB: return ".";
		case F_SUBTYPE_OSUB: return ":";

		case F_SUBTYPE_PLUS: return "+";
		case F_SUBTYPE_MINUS: return "-";

		// todo: rest of the cases
		default: return "???";
	}
}

struct keylist {
  struct HashTable *bytes_hash; // (len,bytes) --> int
  struct HashTable *str_hash; // pem --> int
  PointerVector vec; // term*
};

struct keyrefs {
  PointerVector ref; // int
  PointerVector vec; // term*
};


#define DEST (buf+written), (len <= written ? 0 : len - written)

static int form_print(char *buf, int len, Form *f, struct keylist *keytable, int pr, int depth);
static int pred_print(char *buf, int len, Form *f, struct keylist *keytable, int pr, int depth);
static int term_print(char *buf, int len, Form *f, struct keylist *keytable, int pr, int depth);
static int list_print(char *buf, int len, Form *f, struct keylist *keytable, char lp, char rp, int depth);

static char *breakify(char *text, int w, int nsb, struct softbreak *sb) {
  if (nsb < 3) return NULL;
  assert(sb[0].pos == 0); // first break should be at start
  assert(sb[nsb-1].pos == strlen(text)); // last break should be at end

  // we can just work backwards, as in DAG shortest path
  int *cost = nxcompat_alloc(nsb * sizeof(int));
  int *cnt = nxcompat_alloc(nsb * sizeof(int));
  memset(cost, 0, nsb * sizeof(int));
  memset(cnt, 0, nsb * sizeof(int));
  int i, j, e = nsb-1;
  for (i = nsb-2; i >= 0; i--) {
    while (e > i + 1&& sb[e].pos - sb[i].pos > w) e--;
    for (j = i+1; j <= e; j++) {
      int bcost = sb[j].badness * sb[j].badness + cost[j];
      if (!cost[i] || bcost < cost[i]) {
	cost[i] = bcost;
	cnt[i] = cnt[j] + 1;
      }
    }
  }

//#define DEBUG_BREAKIFY

  int totcost = cost[0];
  int totcnt = cnt[0];
  int n = strlen(text);
#ifdef  DEBUG_BREAKIFY
    char *debug_buf = nxcompat_alloc(n + nsb + 1); 
    char *t = debug_buf;
#endif
  char *buf = nxcompat_alloc(n + (totcnt-1)*3 + 1); // two characters for each chosen break
  char *s = buf;
  e = 0;
  for (i = 0; i < n; i++) {
    if (sb[e].pos == i) {
      int bcost = sb[e].badness * sb[e].badness + cost[e];
      int bcnt = cnt[e] + 1;
      if (totcost == bcost && totcnt == bcnt) {
#ifdef DEBUG_BREAKIFY
	*(t++) = '*';
#endif
	*(s++) = '\n';
	*(s++) = ' ';
	if (text[i] != ' ') *(s++) = ' ';
	totcost = cost[e];
	totcnt = cnt[e];
      } else {
#ifdef DEBUG_BREAKIFY
	*(t++) = '\'';
#endif
      }
      e++;
    }
#ifdef DEBUG_BREAKIFY
    *(t++) = text[i];
#endif
    *(s++) = text[i];
  }
  assert(e == nsb - 1);
#ifdef DEBUG_BREAKIFY
  *(t++) = '\'';
  *t = '\0';
#endif
  *s = '\0';

#ifdef DEBUG_BREAKIFY
  printf("calls for %d lines of max %d width from %d softbreaks, at a cost of %d\n", cnt[0], w, nsb, cost[0]);
  e = 0;
  for (i = 0; i < n; i++) {
    if (sb[e].pos == i) {
      if (sb[e].badness >= 1000) printf("#");
      else if (sb[e].badness >= 100) printf("%d", sb[e].badness/100);
      else printf(" ");
      e++;
    }
    printf(" ");
  }
  if (sb[e].badness >= 100) printf("%d", sb[e].badness/100);
  else printf(" ");
  printf("|\n");
  e = 0;
  for (i = 0; i < n; i++) {
    if (sb[e].pos == i) {
      if (sb[e].badness >= 10) printf("%d", (sb[e].badness % 100)/10);
      else printf(" ");
      e++;
    }
    printf(" ");
  }
  if (sb[e].badness >= 10) printf("%d", sb[e].badness/10);
  else printf(" ");
  printf("|\n");
  e = 0;
  for (i = 0; i < n; i++) {
    if (sb[e].pos == i) {
      printf("%d", sb[e].badness % 10);
      e++;
    }
    printf(" ");
  }
  printf("%d", sb[e].badness % 10);
  printf("|\n");
  printf("%s\n", debug_buf);
  nxcompat_free(debug_buf);
#endif

  nxcompat_free(cost);
  nxcompat_free(cnt);
  return buf;
}

// just added delta more text, maybe insert a linebreak
static int softbreak(char *buf, int len, int delta, int badness) {
  pctx.p += delta;
  if (!pctx.w) return 0;
  if (delta > 0)
    pctx.nsoftbreaks++;
  if (pctx.softbreaks) {
    pctx.softbreaks[pctx.nsoftbreaks-1].pos = pctx.p;
    pctx.softbreaks[pctx.nsoftbreaks-1].badness = badness;
    //pctx.softbreaks[pctx.nsoftbreaks-1].space = 0;
  }
  return 0;
}

static int keys_print(char *buf, int len, struct keylist *keytable, int depth) {
  int written = 0, delta;
  int i, n = PointerVector_len(&keytable->vec);
  for (i = 0; i < n; i++) {
    Form *f = PointerVector_nth(&keytable->vec, i);
    written += softbreak(DEST, 0, 100);
    written += delta = snprintf(DEST, ",");
    written += softbreak(DEST, delta, depth+1);
    written += delta = snprintf(DEST, " ");
    written += softbreak(DEST, delta, 100);
    written += form_print(DEST, f, NULL, 50, depth+1);
  }
  written += softbreak(DEST, 0, depth+0);
  return written;
}

static int leaf_compact(struct keylist *keytable, Form *f) {
  struct HashTable *items = keytable->str_hash;
  char *buf = f->data;
  if (f->len >= 0) {
    buf = nxcompat_alloc(f->len + sizeof(int));
    ((int *)buf)[0] = f->len;
    memcpy(buf+sizeof(int), f->data, f->len);
    items = keytable->bytes_hash;
  }
  int keyrefplus1 = (int)hash_findItem(items, buf);
  if (!keyrefplus1) {
    keyrefplus1 = PointerVector_len(&keytable->vec) + 1;
    hash_insert(items, buf, (void *)keyrefplus1);
    PointerVector_append(&keytable->vec, f);
  }
  if (buf != f->data)
    nxcompat_free(buf);
  return keyrefplus1 - 1;
}

int form_qstr_escape(char *buf, int len, char *str, int justify)
{
  int written = 0;
  for (; *str; str++) {
    if (*str <= 0x1f || *str == 0x7f || *str & 0x80) {
      if (*str == '\n') {
	if (justify == 0) written += snprintf(DEST, "\\n");
	else if (justify < 0) written += snprintf(DEST, "\\l"); // goofy: left justify for dot
	else if (justify > 0) written += snprintf(DEST, "\\r"); // goofy: right justify for dot
      }
      else if (*str == '\t') written += snprintf(DEST, "\\t");
      else if (*str == '\r') written += snprintf(DEST, "\\r");
      else if (*str == '\b') written += snprintf(DEST, "\\b");
      else if (*str == '\f') written += snprintf(DEST, "\\f");
      else written += snprintf(DEST, "\\%03o", (int)*str & 0xff);
    }
    else if (*str == '\"') written += snprintf(DEST, "\\\"");
    else if (*str == '\\') written += snprintf(DEST, "\\\\");
    else written += snprintf(DEST, "%c", *str);
  }
  return written;
}

static int term_print(char *buf, int len, Form *f, struct keylist *keytable, int pr, int depth)
{
	int a, r = rank(f, &a), lr = (a == -1 ? r + 1 : r), rr = (a == +1 ? r + 1 : r);
	int i, j, n, will_elide;
	int written = 0, delta;
	switch (f->tag) {
		case F_TERM_APPLY:
			written += term_print(DEST, f->left, keytable, 50, depth+1);
			written += softbreak(DEST, 0, 100);
			written += list_print(DEST, f->right, keytable, '(', ')', depth+1);
			break;
		case F_TERM_INT:
			written += delta = snprintf(DEST, "%d", f->value);
			written += softbreak(DEST, delta, depth+1);
			break;
		case F_TERM_STR:
			n = strlen(f->data);
			will_elide = (pctx.elide && pctx.s_min > 0 && n > pctx.s_min);
			if (keytable && (will_elide ? pctx.s_min : n) > pctx.s_compact) {
			  written += delta = snprintf(DEST, "%%%d", leaf_compact(keytable, f));
			  written += softbreak(DEST, delta, depth+1);
			} else if (pctx.elide && pctx.s_min > 0 && n > pctx.s_min) {
			  char *alt = nxcompat_alloc(pctx.s_cut);
			  for (j = 0; j <= 2; j++) { // left, middle, right
			    int show = pctx.s_flags & (0x4 >> j);
			    if (show) {
			      int offset = ((n - pctx.s_cut) * j / 2);
			      memcpy(alt, f->data + offset, pctx.s_cut);
			      alt[pctx.s_cut] = '\0';
			      written += snprintf(DEST, "\"");
			      written += delta = form_qstr_escape(DEST, alt, 0);
			      written += snprintf(DEST, "\"");
			      written += softbreak(DEST, delta+2, depth+1);
			    }
			    if (j == 0 || (j == 1 && show)) {
			      written += delta = snprintf(DEST, "...");
			      written += softbreak(DEST, delta, depth+1);
			    }
			  }
			  nxcompat_free(alt);
			} else {
			  written += snprintf(DEST, "\"");
			  written += form_qstr_escape(DEST, f->data, 0);
			  written += snprintf(DEST, "\"");
			  written += softbreak(DEST, written, depth+1);
			}
			break;
		case F_TERM_BYTES:
			will_elide = (pctx.elide && pctx.b_min > 0 && f->len > pctx.b_min);
			if (keytable && (will_elide ? pctx.s_min : f->len) > pctx.b_compact) {
			  written += delta = snprintf(DEST, "%%%d", leaf_compact(keytable, f));
			  written += softbreak(DEST, delta, depth+1);
			} else {
			  written += delta = snprintf(DEST, "<<");
			  written += softbreak(DEST, delta, depth+1);
			  if (pctx.elide && pctx.b_min > 0 && f->len > pctx.b_min) {
			    for (j = 0; j <= 2; j++) { // left, middle, right
			      int show = pctx.b_flags & (0x4 >> j);
			      if (show) {
				int offset = ((f->len - pctx.b_cut) * j / 2);
				for (i = 0; i < pctx.b_cut; i++) {
				  written += delta = snprintf(DEST, "%02x", ((unsigned char *)f->data)[i+offset]);
				  written += softbreak(DEST, delta, depth+1);
				}
			      }
			      if (j == 0 || (j == 1 && show)) {
				written += delta = snprintf(DEST, "... ");
				written += softbreak(DEST, delta, depth+1);
			      }
			    }
			  } else {
			    for (i = 0; i < f->len; i++) {
			      written += delta = snprintf(DEST, "%02x", ((unsigned char *)f->data)[i]);
			      written += softbreak(DEST, delta, depth+1);
			    }
			  }
			  written += delta = snprintf(DEST, ">>");
			  written += softbreak(DEST, delta, depth+1);
			}
			break;
		case F_TERM_TLIST:
			written += list_print(DEST, f->left, keytable, '[', ']', depth);
			break;
		case F_TERM_TSET:
			written += list_print(DEST, f->left, keytable, '{', '}', depth);
			break;
		case F_TERM_SVAR:
		case F_TERM_QVAR:
		case F_TERM_PREF:
			written += delta = snprintf(DEST, "%s", f->data);
			written += softbreak(DEST, delta, depth+1);
			break;
		case F_TERM_CSUB:
		case F_TERM_OSUB:
			if (r >= pr) {
			  written += delta = snprintf(DEST, "(");
			  written += softbreak(DEST, delta, depth+5);
			}
			written += form_print(DEST, f->left, keytable, lr, depth+1);
			written += delta = snprintf(DEST, "%s", tagname(f->tag));
			written += softbreak(DEST, delta, depth+3);
			written += form_print(DEST, f->right, keytable, rr, depth+1);
			if (r >= pr) {
			  written += delta = snprintf(DEST, ")");
			  written += softbreak(DEST, delta, depth+5);
			}
			break;
		case F_TERM_PLUS:
		case F_TERM_MINUS:
			if (r >= pr) {
			  written += delta = snprintf(DEST, "(");
			  written += softbreak(DEST, delta, depth+1);
			}
			written += form_print(DEST, f->left, keytable, lr, depth+1);
			written += softbreak(DEST, 0, depth+0);
			written += delta = snprintf(DEST, " %s ", tagname(f->tag));
			written += softbreak(DEST, delta, depth+1);
			written += form_print(DEST, f->right, keytable, rr, depth+1);
			if (r >= pr) {
			  written += delta = snprintf(DEST, ")");
			  written += softbreak(DEST, delta, depth+1);
			}
			break;
		case F_TERM_UNION:
		case F_TERM_JOIN:
			written += delta = snprintf(DEST, "%s(", tagname(f->tag));
			written += softbreak(DEST, delta, depth+1);
			written += form_print(DEST, f->left, keytable, 50, depth+1);
			written += softbreak(DEST, 0, 100);
			written += delta = snprintf(DEST, ",");
			written += softbreak(DEST, delta, depth+1);
			written += form_print(DEST, f->right, keytable, 50, depth+1);
			written += softbreak(DEST, 0, 100);
			written += delta = snprintf(DEST, ")");
			written += softbreak(DEST, delta, depth+1);
			break;
		case F_TERM_SIZE:
		case F_TERM_PEM:
		case F_TERM_DER:
			written += delta = snprintf(DEST, "%s(", tagname(f->tag));
			written += softbreak(DEST, delta, depth+1);
			written += form_print(DEST, f->left, keytable, 50, depth+1);
			written += delta = snprintf(DEST, ")");
			written += softbreak(DEST, delta, depth+1);
			break;
		case F_TERM_DIGRP:
			written += delta = snprintf(DEST, "[( ");
			written += softbreak(DEST, delta, depth+1);
			written += form_print(DEST, f->left, keytable, 50, depth+1);
			written += softbreak(DEST, 0, 100);
			written += delta = snprintf(DEST, " : ");
			written += softbreak(DEST, delta, depth+1);
			written += form_print(DEST, f->right, keytable, 50, depth+1);
			written += softbreak(DEST, 0, 100);
			written += delta = snprintf(DEST, " )]");
			written += softbreak(DEST, delta, depth+1);
			break;
		case F_TERM_CIGRP:
			written += delta = snprintf(DEST, "[[ ");
			written += softbreak(DEST, delta, depth+1);
			written += form_print(DEST, f->left, keytable, 50, depth+1);
			written += softbreak(DEST, 0, 100);
			written += delta = snprintf(DEST, " : ");
			written += softbreak(DEST, delta, depth+1);
			written += form_print(DEST, f->right, keytable, 50, depth+1);
			written += softbreak(DEST, 0, 100);
			written += delta = snprintf(DEST, " ]]");
			written += softbreak(DEST, delta, depth+1);
			break;
		default:
			written += delta = snprintf(DEST, "???");
			written += softbreak(DEST, delta, depth+1);
			break;
	}
	written += softbreak(DEST, 0, depth+0);
	return written;
}

static int list_print(char *buf, int len, Form *f, struct keylist *keytable, char lp, char rp, int depth) {
	Form *g;
	int written = 0, delta;
	switch (f->tag) {
		case F_LIST_NONE:
			if (lp > 0) {
			  written += delta = snprintf(DEST, "%c", lp);
			  written += softbreak(DEST, delta, depth+1);
			}
			if (rp > 0) {
			  written += delta = snprintf(DEST, "%c", rp);
			  written += softbreak(DEST, delta, depth+1);
			}
			break;
		case F_LIST_CONS:
			if (lp > 0) {
			  written += delta = snprintf(DEST, "%c", lp);
			  written += softbreak(DEST, delta, depth+1);
			}
			written += form_print(DEST, f->left, keytable, 50, depth+1);
			for(g = f->right; g->tag == F_LIST_CONS; g = g->right) {
				written += softbreak(DEST, 0, 100);
				written += delta = snprintf(DEST, ", ");
				written += softbreak(DEST, delta, depth+1);
				written += form_print(DEST, g->left, keytable, 50, depth+1);
			}
			if (rp > 0) {
			  written += delta = snprintf(DEST, "%c", rp);
			  written += softbreak(DEST, delta, depth+1);
			}
			break;
		default:
			written += delta = snprintf(DEST, "???");
			written += softbreak(DEST, delta, depth+1);
			break;
	}
	written += softbreak(DEST, 0, depth+0);
	return written;
}

static int pred_print(char *buf, int len, Form *f, struct keylist *keytable, int pr, int depth) {
	int a, r = rank(f, &a), lr = (a == -1 ? r + 1 : r), rr = (a == +1 ? r + 1 : r);
	int written = 0, delta;
	switch(f->tag & F_ARITY_MASK) {
		case F_IS_BINARY:
			if (r >= pr) {
			  written += delta = snprintf(DEST, "(");
			  written += softbreak(DEST, delta, depth+1);
			}
			written += form_print(DEST, f->left, keytable, lr, depth+1);
			written += delta = snprintf(DEST, " %s ", tagname(f->tag));
			written += softbreak(DEST, delta, depth+1);
			written += form_print(DEST, f->right, keytable, rr, depth+1);
			if (r >= pr) {
			  written += delta = snprintf(DEST, ")");
			  written += softbreak(DEST, delta, depth+1);
			}
			break;
		case F_IS_UNARY:
			written += delta = snprintf(DEST, "%s(", tagname(f->tag));
			written += softbreak(DEST, delta, depth+1);
			written += form_print(DEST, f->left, keytable, 50, depth+1);
			written += delta = snprintf(DEST, ")");
			written += softbreak(DEST, delta, depth+1);
			break;
		default:
			written += form_print(DEST, f, keytable, pr, depth);
			break;
	}
	written += softbreak(DEST, 0, depth+0);
	return written;
}

static int stmt_print(char *buf, int len, Form *f, struct keylist *keytable, int pr, int depth) { 
	int written = 0, delta;
	int a, r = rank(f, &a), lr = (a == -1 ? r + 1 : r), rr = (a == +1 ? r + 1 : r);

	switch (f->tag) {
		case F_STMT_AND:
		case F_STMT_OR:
		case F_STMT_IMP:
		case F_STMT_IFF:
		case F_STMT_SAYS:
		case F_STMT_SFOR:
			if (r >= pr) {
			  written += delta = snprintf(DEST, "(");
			  written += softbreak(DEST, delta, depth+1);
			}
			written += form_print(DEST, f->left, keytable, lr, depth+1);
			written += softbreak(DEST, 0, depth+0);
			written += delta = snprintf(DEST, " %s ", tagname(f->tag));
			written += softbreak(DEST, delta, depth+1);
			written += form_print(DEST, f->right, keytable, rr, depth+1);
			if (r >= pr) {
			  written += delta = snprintf(DEST, ")");
			  written += softbreak(DEST, delta, depth+1);
			}
			break;
		case F_STMT_SFORON:
			if (r >= pr) {
			  written += delta = snprintf(DEST, "(");
			  written += softbreak(DEST, delta, depth+1);
			}
			written += term_print(DEST, f->left, keytable, lr, depth+1);
			written += softbreak(DEST, 0, depth+0);
			written += delta = snprintf(DEST, " on ");
			written += softbreak(DEST, delta, depth+1);
			written += term_print(DEST, f->mid, keytable, r, depth+1);
			written += softbreak(DEST, 0, depth+0);
			written += delta = snprintf(DEST, " speaksfor ");
			written += softbreak(DEST, delta, depth+1);
			written += term_print(DEST, f->right, keytable, rr, depth+1);
			if (r >= pr) {
			  written += delta = snprintf(DEST, ")");
			  written += softbreak(DEST, delta, depth+1);
			}
			break;
		case F_STMT_FORALL:
		case F_STMT_EXISTS:
			if (r >= pr) {
			  written += delta = snprintf(DEST, "(");
			  written += softbreak(DEST, delta, depth+1);
			}
			written += delta = snprintf(DEST, "%s ", tagname(f->tag));
			written += softbreak(DEST, delta, depth+1);
			written += term_print(DEST, f->left, keytable, 50, depth+1);
			written += delta = snprintf(DEST, " : ");
			written += softbreak(DEST, delta, depth+0);
			written += form_print(DEST, f->right, keytable, r, depth+1);
			if (r >= pr) {
			  written += delta = snprintf(DEST, ")");
			  written += softbreak(DEST, delta, depth+1);
			}
			break;
		case F_STMT_NOT:
			if (r >= pr) {
			  written += delta = snprintf(DEST, "(");
			  written += softbreak(DEST, delta, depth+1);
			}
			written += delta = snprintf(DEST, "%s ", tagname(f->tag));
			written += softbreak(DEST, delta, depth+1);
			written += form_print(DEST, f->left, keytable, rr, depth+1);
			if (r >= pr) {
			  written += delta = snprintf(DEST, ")");
			  written += softbreak(DEST, delta, depth+1);
			}
			break;
		case F_STMT_TRUE:
		case F_STMT_FALSE:
			written += delta = snprintf(DEST, "%s", tagname(f->tag));
			written += softbreak(DEST, delta, depth+1);
			break;
		case F_STMT_PREF:
			written += delta = snprintf(DEST, "%s", f->data);
			written += softbreak(DEST, delta, depth+1);
			break;
		default:
			written += delta = snprintf(DEST, "???");
			written += softbreak(DEST, delta, depth+1);
			break;
	}
	written += softbreak(DEST, 0, depth+0);
	return written;
}

static int form_print(char *buf, int len, Form *f, struct keylist *keytable, int pr, int depth) { 
	int written = 0, delta;
	switch (f->tag & F_TYPE_MASK) {
		case F_TYPE_LIST: written += list_print(DEST, f, keytable, 0, 0, depth); break;
		case F_TYPE_TERM: written += term_print(DEST, f, keytable, pr, depth); break;
		case F_TYPE_PRED: written += pred_print(DEST, f, keytable, pr, depth); break;
		case F_TYPE_STMT: written += stmt_print(DEST, f, keytable, pr, depth); break;
		case F_TYPE_FORM:
			/* compact statement: should never happen */
			assert(0);
			break;
		default:
			written += delta = snprintf(DEST, "???");
			written += softbreak(DEST, delta, depth+1);
			break;
	}
	written += softbreak(DEST, 0, depth+0);
	return written;
}

#undef DEST

int array_buflen(const void *key) {
  return ((int *)key)[0] + sizeof(int);
}

void form_set_elide_mode(
    int s_compact, int s_min, int s_left, int s_mid, int s_right,
    int b_compact, int b_min, int b_left, int b_mid, int b_right) {
  if (s_compact <= 5) s_compact = 5;
  pctx.s_compact = s_compact;
  if (s_min >= 0) {
    pctx.s_min = s_min;
    pctx.s_flags = (s_left ? 0x4 : 0) | (s_mid ? 0x2 : 0) | (s_right ? 0x1 : 0);
    pctx.s_cut = s_min / (1 + (s_left ? 1 : 0) + (s_mid ? 1 : 0) + (s_right ? 1 : 0));
    if (!pctx.s_cut) pctx.s_min = pctx.s_cut = 0;
  }
  if (b_compact <= 5) b_compact = 5;
  pctx.b_compact = b_compact;
  if (b_min >= 0) {
    pctx.b_min = b_min;
    pctx.b_flags = (b_left ? 0x4 : 0) | (b_mid ? 0x2 : 0) | (b_right ? 0x1 : 0);
    pctx.b_cut = b_min / (1 + (b_left ? 1 : 0) + (b_mid ? 1 : 0) + (b_right ? 1 : 0));
    if (!pctx.b_cut) pctx.b_min = pctx.b_cut = 0;
  }
}


//// Translate formula to human readable output
// 
// @return a string that the caller must deallocate
//
// if width == 0, put it all on one line, verbatim
// if width > 0, split every width characters or so
// if width == -1, put it all on line line, but elide boring parts
// if width < -1, split every -width characters or so
char *form_to_pretty(Form *f, int width) {
	if (!f)
		return NULL;
	pctx.p = 0;
	if (width == 0) {
	  pctx.w = pctx.elide = 0;
	} else if (width > 1) {
	  pctx.w = width;
	  pctx.elide = 0;
	} else if (width == -1) {
	  pctx.w = 0;
	  pctx.elide = 1;
	} else {
	  pctx.w = -width;
	  pctx.elide = 1;
	}
	pctx.nsoftbreaks = 1;
	pctx.softbreaks = NULL;
	struct keylist keytable;
	PointerVector_init(&keytable.vec, 16, POINTERVECTOR_ORDER_PRESERVING); // term*
	keytable.bytes_hash = hash_new_vlen(16, (Hash_VarLenFunction*)array_buflen); // (int, bytes) --> int 
	keytable.str_hash = hash_new_vlen(16, hash_strlen); // pem --> int 
	int len1 = form_print(0, 0, f, &keytable, 50, 1);
	assert(len1 >= 0); // special case leads to len1==0: printing an empty list with no outer scope to give delimiters
	int len2 = keys_print(0, 0, &keytable, 1);
	assert(len2 >= 0);
	assert(len1+len2 == pctx.p);
	char *buf = nxcompat_alloc(len1+len2+1);
	buf[0] = '\0'; // special case of len1+len2==0
	if (pctx.w) {
	  pctx.softbreaks = nxcompat_alloc(pctx.nsoftbreaks * sizeof(struct softbreak));
	  memset(pctx.softbreaks, 0, pctx.nsoftbreaks * sizeof(struct softbreak));
	}
	pctx.p = 0;
	pctx.nsoftbreaks = 1;
	form_print(buf, len1+1, f, &keytable, 50, 1);
	keys_print(buf+len1, len1+len2+1, &keytable, 1);
	assert(len1+len2 == pctx.p);
	hash_destroy(keytable.bytes_hash);
	hash_destroy(keytable.str_hash);
	PointerVector_dealloc(&keytable.vec);

	if (pctx.w) {
	  char *broken = breakify(buf, pctx.w, pctx.nsoftbreaks, pctx.softbreaks);
	  nxcompat_free(pctx.softbreaks);
	  pctx.softbreaks = NULL;
	  pctx.nsoftbreaks = 0;
	  if (!broken) return buf;
	  nxcompat_free(buf);
	  return broken;
	} else {
	  return buf;
	}
}

/* We encode most AST nodes in DER as a nested sequence. Each sequence starts
 * with a string, which identifies what kind of AST node the sequence
 * represents. The remainder of the elements in the sequence are the data,
 * value, or children.  For example, "A and B" would be encoded as:
 *   SEQUENCE { STRING("and") encode(A) encode(B) }.
 *
 * Some AST nodes do not follow this convention; these are documented below.
 *
 * The two methods below convert back and forth between 4-byte AST node tags and
 * ascii DER tags.
 */

int 
sequence_start(unsigned char *buf, int len, int bodylen, char *tag) 
{
	int written = 0;
	written += der_printable_encode(buf, len-written, tag);
	bodylen += written;
	written += der_tag_encode(buf, len-written, bodylen, DER_ASN1_SEQUENCE);
	return written;
}


#define CASES \
  CASE(F_STMT_AND, "and") \
  CASE(F_STMT_OR, "or") \
  CASE(F_STMT_IMP, "imp") \
  CASE(F_STMT_IFF, "iff") \
  CASE(F_STMT_NOT, "not") \
  CASE(F_STMT_SAYS, "says") \
  CASE(F_STMT_SFOR, "speaksfor") \
  CASE(F_STMT_SFORON, "speaksforon") \
  CASE(F_STMT_FORALL, "forall") \
  CASE(F_STMT_EXISTS, "exists") \
  CASE(F_STMT_PREF, "spref") \
  CASE(F_PRED_EQ, "=") \
  CASE(F_PRED_GT, ">") \
  CASE(F_PRED_LT, "<") \
  CASE(F_PRED_GE, ">=") \
  CASE(F_PRED_LE, "<=") \
  CASE(F_PRED_NE, "!=") \
  CASE(F_PRED_IN, "in") \
  CASE(F_TERM_SVAR, "svar") \
  CASE(F_TERM_QVAR, "qvar") \
  CASE(F_TERM_PREF, "tpref") \
  CASE(F_PRED_CLOSED, "closed") \
  CASE(F_PRED_OPEN, "open") \
  CASE(F_PRED_ISPRIN, "prin") \
  CASE(F_PRED_ISINT, "int") \
  CASE(F_PRED_ISSTR, "str") \
  CASE(F_PRED_ISBYTES, "bytes") \
  CASE(F_PRED_ISTLIST, "list") \
  CASE(F_PRED_ISTSET, "set") \
  CASE(F_TERM_APPLY, "apply") \
  CASE(F_TERM_PLUS, "plus") \
  CASE(F_TERM_MINUS, "minus") \
  CASE(F_TERM_SIZE, "size") \
  CASE(F_TERM_UNION, "union") \
  CASE(F_TERM_JOIN, "join") \
  CASE(F_TERM_DER, "der") \
  CASE(F_TERM_PEM, "pem") \
  CASE(F_TERM_CSUB, "csub") \
  CASE(F_TERM_OSUB, "osub") \
  CASE(F_TERM_TLIST, "tlist") \
  CASE(F_TERM_TSET, "tset") \
  CASE(F_TERM_DIGRP, "digrp") \
  CASE(F_TERM_CIGRP, "cigrp")


static char *tag_ast2der(int tag) {
#define CASE(a, b) case a: return b;
	switch(tag) {
		CASES
		CASE(F_TERM_INT, NULL) // encode as Integer
		CASE(F_TERM_STR, NULL) // encode as AsciiString
		CASE(F_TERM_BYTES, NULL) // encode as OctetString
		CASE(F_LIST_NONE, NULL) // never used (encoded as part of encapsulating object)
		CASE(F_LIST_CONS, NULL) // never used (encoded as part of encapsulating object)
		CASE(F_STMT_TRUE, NULL) // encode as printable "true"
		CASE(F_STMT_FALSE, NULL) // encode as printable "false"
		default: return NULL; // error
	}
#undef CASE
}

static int tag_der2ast(char *tag, int len) {
#define CASE(a, b) if (len == strlen(b) && !strncmp(tag, b, len)) return a;
	CASES
#undef CASE
	return 0; // error
}

#undef CASES


static int form_encode(unsigned char *buf, int len, Form *f, struct keylist *keytable);

static int list_encode(char *buf, int len, Form *f, struct keylist *keytable) {
	int written = 0;
	switch(f->tag & F_ARITY_MASK) {
		case F_IS_EMPTY: return 0; // done
		case F_IS_BINARY:
			written += list_encode(buf, len-written, f->right, keytable);
			written += form_encode(buf, len-written, f->left, keytable);
			return written;
		default:
			return -1;
	}
}

// everything is written backwards, from the end of the buffer forwards
static int form_encode(unsigned char *buf, int len, Form *f, struct keylist *keytable) {
	int bodylen = 0;
	int sublen = 0;

	char *tag = tag_ast2der(f->tag);

	if (tag) {
		// normal cases
		switch (f->tag & F_ARITY_MASK) {

			case F_IS_TERNARY:
				bodylen += sublen = form_encode(buf, len-bodylen, f->mid, keytable);
				if (sublen < 0) return -1; 
				// fall through
			case F_IS_BINARY:
				bodylen += sublen = form_encode(buf, len-bodylen, f->right, keytable);
				if (sublen < 0) return -1; 
				// fall through
			case F_IS_UNARY:
				bodylen += sublen = form_encode(buf, len-bodylen, f->left, keytable);
				if (sublen < 0) return -1; 
				break;

			case F_IS_VALUE:
				bodylen = der_integer_encode(buf, len, f->value);
				break;

			case F_IS_DATA:
				assert(f->len < 0); // should be a string
				bodylen = der_ascii_encode(buf, len, f->data);
				break;

			default: return -1;
		}
		if (bodylen < 0) return -1; 
		return bodylen + sequence_start(buf, len-bodylen, bodylen, tag);
	} else {
		// special cases
		switch (f->tag) {
			case F_TERM_INT:
				return der_integer_encode(buf, len, f->value);
			case F_TERM_BYTES:
				if (keytable && f->len > 50) {
				    char pref[20];
				    sprintf(pref, "%%%d", leaf_compact(keytable, f));
				    bodylen += sublen = der_ascii_encode(buf, len-bodylen, pref);
				    if (sublen < 0) return -1; 
				    return bodylen + sequence_start(buf, len-bodylen, bodylen, tag_ast2der(F_TERM_PREF));
				} else {
				  return der_octets_encode(buf, len, f->data, f->len);
				}
			case F_TERM_STR:
				if (keytable && strlen(f->data) > 50) {
				    char pref[20];
				    sprintf(pref, "%%%d", leaf_compact(keytable, f));
				    bodylen += sublen = der_ascii_encode(buf, len-bodylen, pref);
				    if (sublen < 0) return -1; 
				    return bodylen + sequence_start(buf, len-bodylen, bodylen, tag_ast2der(F_TERM_PREF));
				} else {
				  return der_ascii_encode(buf, len, f->data);
				}
			case F_STMT_TRUE:
				return der_printable_encode(buf, len, "true");
			case F_STMT_FALSE:
				return der_printable_encode(buf, len, "false");

			case F_LIST_CONS:
			case F_LIST_NONE:
				return list_encode(buf, len, f, keytable);

			default: return -1;
		}
	}
}

static int form_and_keys_encode(char *buf, int len, Form *f, struct keylist *keytable) {
	int bodylen = 0;
	int sublen = 0;

	bodylen += sublen = form_encode(buf, len, f, keytable);
	if (sublen < 0) return -1;

	int i, n = PointerVector_len(&keytable->vec);
	for (i = n-1; i >= 0; i--) {
	  Form *f = PointerVector_nth(&keytable->vec, i);
	  bodylen += sublen = form_encode(buf, len-bodylen, f, NULL);
	  if (sublen < 0) return -1;
	}

	return bodylen + sequence_start(buf, len-bodylen, bodylen, "formula");
}

Formula *form_to_der(Form *f) {
	if (!f)
		return NULL;

	struct keylist keytable;
	PointerVector_init(&keytable.vec, 16, POINTERVECTOR_ORDER_PRESERVING); // der*
	keytable.bytes_hash = hash_new_vlen(16, (Hash_VarLenFunction*)array_buflen); // (int, bytes) --> int 
	keytable.str_hash = hash_new_vlen(16, hash_strlen); // pem --> int 
	int len = form_and_keys_encode(0, 0, f, &keytable);
	assert(len > 0);
	unsigned char *buf = nxcompat_alloc(len);
	int written = form_and_keys_encode(buf, len, f, &keytable);
	assert(written == len && der_msglen(buf) == len);
	hash_destroy(keytable.bytes_hash);
	hash_destroy(keytable.str_hash);
	PointerVector_dealloc(&keytable.vec);
	return (Formula *)buf;
}

#ifndef __NEXUSKERNEL__
char *form_to_pem(Form *f) {
	Formula *der = form_to_der(f);
	if (!der) return NULL;
	unsigned char *pem = der_to_pem(der->body);
	nxcompat_free(der);
	return pem;
}
#endif // __NEXUSKERNEL__


static Form *form_decode(unsigned char **der, unsigned char *end, struct keyrefs *keyrefs);

static Form *list_decode(unsigned char **der, unsigned char *end, struct keyrefs *keyrefs) {
	if (*der < end) {
		Form *head = form_decode(der, end, keyrefs);
		if (!head) FAILRETURN(NULL, "formula list head is invalid\n");
		Form *tail = list_decode(der, end, keyrefs);
		if (!tail) FAILRETURN(NULL, "formula list tail is invalid\n");
		return form_new(F_LIST_CONS, head, 0, tail);
	} else if (*der == end) {
		return form_new(F_LIST_NONE, 0, 0, 0);
	} else {
		FAILRETURN(NULL, "formula list is missing body (negative length)\n");
	}
}

static int integer_decode(unsigned char **der, unsigned char *end, int *val) {
	int asntag = der_unwrap(der, end, &end);
	if (asntag != DER_ASN1_INTEGER) return -1;

	return der_integer_demangle(der, end, val);
}

static char *ascii_decode(unsigned char **der, unsigned char *end) {
	int asntag = der_unwrap(der, end, &end);
	if (asntag != DER_ASN1_ASCIISTRING) FAILRETURN(NULL, "expected ASCIISTRING in formula\n");

	return der_ascii_demangle(der, end);
}

// this modifies the start pointer to just after the consumed bytes
static Form *form_decode(unsigned char **der, unsigned char *end, struct keyrefs *keyrefs) {
	int asntag = der_unwrap(der, end, &end);
	if (asntag <= 0) FAILRETURN(NULL, "expected der tag in formula\n");

	char *str;
	int val;
	int len = end - *der;

	switch(asntag) {
		case DER_ASN1_INTEGER:
			if (der_integer_demangle(der, end, &val)) FAILRETURN(NULL, "bad integer encoding in formula\n");
			return form_newval(F_TERM_INT, val);

		case DER_ASN1_PRINTABLESTRING:
			if (len == 4 && !strncmp(*der, "true", 4)) {
				*der = end;
				return form_new(F_STMT_TRUE, 0, 0, 0);
			}
			if (len == 5 && !strncmp(*der, "false", 5)) {
				*der = end;
				return form_new(F_STMT_FALSE, 0, 0, 0);
			}
			FAILRETURN(NULL, "expected \"true\" or \"false\" in formula\n");
		
		case DER_ASN1_ASCIISTRING:
			str = der_ascii_demangle((unsigned char **)der, end);
			if (!str) FAILRETURN(NULL, "ASCIISTRING missing body in formula\n");
			return form_newdata(F_TERM_STR, str, -1);
			
		case DER_ASN1_OCTETSTRING:
			str = der_octets_demangle((unsigned char **)der, end, &len);
			if (!str) FAILRETURN(NULL, "OCTETSTRING missing body in formula\n");
			return form_newdata(F_TERM_BYTES, str, len);

		case DER_ASN1_SEQUENCE:
			{
				// next element better be a PrintableString containing the string_tag
				unsigned char *endstr;
				if (der_unwrap(der, end, &endstr) != DER_ASN1_PRINTABLESTRING)
					FAILRETURN(NULL, "formula type tag missing\n");
				int tag = tag_der2ast(*der, endstr - *der);
				if (!tag) FAILRETURN(NULL, "formula type tag unrecognized\n");
				*der = endstr;

				int val;
				unsigned char *keyder;
				int subcount = 0;
				Form *left = NULL, *right = NULL, *mid = NULL;
				switch (tag & F_ARITY_MASK) {
					case F_IS_TERNARY: subcount++; // fall through
					case F_IS_BINARY: subcount++; // fall through
					case F_IS_UNARY: subcount++; // fall through
					case F_IS_EMPTY:
						if (subcount >= 1) {
							if (tag == F_TERM_TLIST || tag == F_TERM_TSET)
								left = list_decode(der, end, keyrefs);
							else
								left = form_decode(der, end, keyrefs);
							if (!left) FAILRETURN(NULL, "formula left was mangled\n");
						}
						if (subcount >= 2) {
							if (tag == F_TERM_APPLY)
								right = list_decode(der, end, keyrefs);
							else
								right = form_decode(der, end, keyrefs);
							if (!right) FAILRETURN(NULL, "formula right was mangled\n");
						}
						if (subcount == 3) {
							mid = form_decode(der, end, keyrefs);
							if (!mid) FAILRETURN(NULL, "formula middle was mangled\n");
						}
						if (*der != end) FAILRETURN(NULL, "formula contained too many elements in SEQUENCE\n");
						return form_new(tag, left, mid, right);

					case F_IS_VALUE:
						if (integer_decode(der, end, &val)) FAILRETURN(NULL, "formula integer was mangled\n");
						return form_newval(tag, val);

					case F_IS_DATA:
						str = ascii_decode(der, end);
						if (!str || *der != end) FAILRETURN(NULL, "formula data was mangled or missing\n");
						if (keyrefs && tag == F_TERM_PREF) {
						  int val = 0;
						  // der decoding does not yet handle named parameters
						  if (sscanf(str, "%%%d", &val) != 1) {
						    return form_newdata(F_TERM_PREF, str, -1);
						  }
						  nxcompat_free(str);
						  if (val < 0 || val >= PointerVector_len(&keyrefs->vec))
						    FAILRETURN(NULL, "formula has invalid parameter name\n"); 
						  keyder = PointerVector_nth(&keyrefs->vec, val);
						  len = der_msglen(keyder);
						  if (len <= 0) FAILRETURN(NULL, "formula parameter is bad\n");
						  PointerVector_set_nth(&keyrefs->ref, val, 
						      1+PointerVector_nth(&keyrefs->ref, val));
						  return form_decode(&keyder, keyder+len, NULL);
						}
						return form_newdata(tag, str, -1);

					default:
						FAILRETURN(NULL, "formula unhandled tag: %08x\n", tag);
				}
			}

		default:
			FAILRETURN(NULL, "formula unhandled asn1 tag: %08x\n", asntag);
	}
}

Form *form_and_keys_decode(unsigned char **der, unsigned char *end)
{
	int asntag = der_unwrap(der, end, &end);
	if (asntag != DER_ASN1_SEQUENCE)
	  FAILRETURN(NULL, "der formula does not start with SEQUENCE tag\n");

	unsigned char *endstr;
	if (der_unwrap(der, end, &endstr) != DER_ASN1_PRINTABLESTRING)
	  FAILRETURN(NULL, "der formula sequence does not start with PRINTABLESTRING\n");

	int len = endstr - *der;
	if (len != strlen("formula") || strncmp(*der, "formula", len))
	  FAILRETURN(NULL, "der formula sequence does not start with \"formula\"\n");
	*der = endstr;

	struct keyrefs keys;
	PointerVector_init(&keys.vec, 16, POINTERVECTOR_ORDER_PRESERVING);
	PointerVector_init(&keys.ref, 16, POINTERVECTOR_ORDER_PRESERVING);

	for (endstr = *der + der_msglen(*der); endstr < end; endstr = *der + der_msglen(*der)) {
	  PointerVector_append(&keys.vec, *der);
	  PointerVector_append(&keys.ref, 0);
	  *der = endstr;
	}
	Form *f = form_decode(der, end, &keys);
	if (!f) {
	  FAILRETURN(NULL, "der formula did not decode\n");
	}
	if (*der != end) {
	      form_free(f);
	      FAILRETURN(NULL, "der formula has trailing junk (%d bytes)\n", end - *der);
	}

	// check to make sure all keys were referenced
	int nunref = 0;
	int i, n = PointerVector_len(&keys.ref); 
	for (i = 0; i < n; i++) {
	  if (!PointerVector_nth(&keys.ref, i)) 
	    nunref++;
	}
	PointerVector_dealloc(&keys.vec);
	PointerVector_dealloc(&keys.ref);
	if (nunref) {
	  form_free(f);
	  FAILRETURN(NULL, "der formula contains %d unreferenced keys\n", nunref);
	}
	return f;
}

Form *form_from_der(Formula *der) {
	int len = der_msglen(der->body);
	unsigned char *derstart = der->body;
	unsigned char *derend = derstart + len;

	Form *f = form_and_keys_decode(&derstart, derend);
	return f;
}

#ifndef __NEXUSKERNEL__
Form *form_from_pem(char *pem) {
	Formula *der = (Formula *)der_from_pem(pem);
	if (!der)
		return NULL;

	Form *f = form_from_der(der);
	nxcompat_free(der);
	return f;
}
#endif // __NEXUSKERNEL__


// return the type of expression f, after checking children for consistency
int form_check_type(Form *f) {

	if (!f) return 0;

	// check children first
	int left = 0, right = 0, mid = 0;
	switch (f->tag & F_ARITY_MASK) {
		case F_IS_TERNARY:
			mid = form_check_type(f->mid);
			if (!mid) return 0;
			// fall through
		case F_IS_BINARY:
			right = form_check_type(f->right);
			if (!right) return 0;
			// fall through
		case F_IS_UNARY:
			left = form_check_type(f->left);
			if (!left) return 0;
			break;
		default: break;
	}
	// check self
	switch (f->tag) {
		case F_STMT_AND:
		case F_STMT_OR:
		case F_STMT_IMP:
		case F_STMT_IFF:
			return (F_ISSTMT(left) && F_ISSTMT(right)) ? F_TYPE_STMT : 0;
		case F_STMT_SAYS:
			return (F_ISTERM(left) && F_ISSTMT(right)) ? F_TYPE_STMT : 0;
		case F_PRED_EQ:
		case F_PRED_NE:
		case F_PRED_GE:
		case F_PRED_LE:
		case F_PRED_GT:
		case F_PRED_LT:
		case F_PRED_IN:
			return (F_ISTERM(left) && F_ISTERM(right)) ? F_TYPE_PRED : 0;
		case F_STMT_SFOR:
			return (F_ISTERM(left) && F_ISTERM(right)) ? F_TYPE_STMT : 0;
		case F_STMT_SFORON:
			return (F_ISTERM(left) && F_ISTERM(right) &&
			    F_ISTERM(mid) && f->right->tag == F_TERM_STR) ? F_TYPE_STMT : 0;
		case F_STMT_NOT:
			return (F_ISSTMT(left)) ? F_TYPE_STMT : 0;
		case F_STMT_TRUE:
		case F_STMT_FALSE:
			return F_TYPE_STMT;
		case F_STMT_FORALL:
		case F_STMT_EXISTS:
			return (F_ISTERM(left) && f->left->tag == F_TERM_QVAR &&
			    F_ISSTMT(right)) ? F_TYPE_STMT : 0;
		case F_STMT_PREF:
			return F_TYPE_STMT;

		case F_PRED_CLOSED:
		case F_PRED_OPEN:
		case F_PRED_ISPRIN:
		case F_PRED_ISINT:
		case F_PRED_ISSTR:
		case F_PRED_ISBYTES:
		case F_PRED_ISTLIST:
		case F_PRED_ISTSET:
			return (F_ISTERM(left)) ? F_TYPE_PRED : 0;

		case F_TERM_APPLY:
			return (F_ISTERM(left) && f->left->tag == F_TERM_SVAR &&
			    F_ISLIST(right)) ? F_TYPE_TERM : 0;
		case F_TERM_PLUS:
		case F_TERM_MINUS:
		case F_TERM_UNION:
		case F_TERM_JOIN:
		case F_TERM_CSUB:
		case F_TERM_OSUB:
			return (F_ISTERM(left) && F_ISTERM(right)) ? F_TYPE_TERM : 0;
		case F_TERM_SIZE:
		case F_TERM_PEM:
		case F_TERM_DER:
			return (F_ISTERM(left)) ? F_TYPE_TERM : 0;
		case F_TERM_INT:
		case F_TERM_STR:
		case F_TERM_BYTES:
		case F_TERM_SVAR:
		case F_TERM_QVAR:
		case F_TERM_PREF:
			return F_TYPE_TERM;
		case F_TERM_TLIST:
		case F_TERM_TSET:
			return (F_ISLIST(left)) ? F_TYPE_TERM : 0;
		case F_TERM_DIGRP:
		case F_TERM_CIGRP:
			return (F_ISTERM(left) && f->left->tag == F_TERM_QVAR &&
			    F_ISSTMT(right)) ? F_TYPE_TERM : 0;

		case F_LIST_NONE:
			return F_TYPE_LIST;
		case F_LIST_CONS:
			return (F_ISLIST(right) && left != 0) ? F_TYPE_LIST : 0;
		default:
			return 0;
	}
}

// Check a formula to ensure it is will formed.
// Returns non-zero if f is a well-formed statement.
int form_is_proper(Form *f) {
	int top = form_check_type(f);
	return F_ISSTMT(top);
}

static void find_free_qvars(Form *f, HashTable *freevars)
{
  if (f->tag == F_TERM_QVAR) {
    hash_insert(freevars, f->data, (void *)1);
  } else {
    switch (f->tag & F_ARITY_MASK) {
      case F_IS_TERNARY: find_free_qvars(f->mid, freevars);
	/* fall through */
      case F_IS_BINARY: find_free_qvars(f->right, freevars);
	/* fall through */
      case F_IS_UNARY: find_free_qvars(f->left, freevars);
	/* fall through */
      default:
	 break;
    }
    if (f->tag == F_STMT_FORALL || f->tag == F_STMT_EXISTS)
      hash_delete(freevars, f->left->data);
  }
}

HashTable *form_free_qvars(Form *f)
{
  HashTable *freevars = hash_new_vlen(16, hash_strlen);
  find_free_qvars(f, freevars);
  return freevars;
}

/** Replace all instances of parameter varname with the formula repl */
static int replace_node(Form *f, char *varname, Form *repl, HashTable *avoidvars) {
  int varsubtype = (varname[0] == '%' ? F_SUBTYPE_PREF :
		      (varname[0] == '$' ? F_SUBTYPE_QVAR : 0));
  assert(varsubtype);
		      
  if ((f->tag & F_SUBTYPE_MASK) == varsubtype && f->len == -1 && !strcmp(f->data, varname)) {
    if ((F_ISTERM(repl->tag) && F_ISTERM(f->tag))
	|| (F_ISSTMT(repl->tag) && F_ISSTMT(f->tag))) {
      Form *dup = form_dup(repl);
      nxcompat_free(f->data);
      *f = *dup;
      return 1;
    }
    return -1;
  }
  // todo: capture avoidance in group lambda expressions too
  if (f->tag == F_STMT_FORALL || f->tag == F_STMT_EXISTS) {
    assert(f->left->tag == F_TERM_QVAR);
    // todo: allow PREFs as the variable? e.g. (forall %x : ...)
    if (varsubtype == F_SUBTYPE_QVAR && !strcmp(f->left->data, varname))
      return 0; // replacing [$x/repl] in (forall $x : ...) is a no-op
    int uses = replace_node(f->right, varname, repl, avoidvars);
    if (uses && avoidvars && hash_findItem(avoidvars, f->left->data)) {
      return -1; // replacing [%x/...$y...] in (forall $y : ...$x...) would be a capture error
    }
    return uses;
  }
  int uses = 0, u;
  switch (f->tag & F_ARITY_MASK) {
    case F_IS_TERNARY:
      uses += u = replace_node(f->mid, varname, repl, avoidvars);
      if (u < 0) return u;
      /* fall through */
    case F_IS_BINARY:
      uses += u = replace_node(f->right, varname, repl, avoidvars);
      if (u < 0) return u;
      /* fall through */
    case F_IS_UNARY:
      uses += u = replace_node(f->left, varname, repl, avoidvars);
      if (u < 0) return u;
      /* fall through */
    default:
      return uses;
  }
}

// Replace free qvar occurrences (F_TERM_QVAR nodes) with given term.
// Return number of times replacement is made.
// This function fails, returning a negative value and leaving f in an unknown
// state, if any of the substitutions would capture a free variable in the
// replacement term.  For example, replacing $x with ($y-1) in
//    ($x > 0 implies forall $y : pow($x, $y) > 0) // a true statement
// would successfully replace the first occurrence to obtain the partial result
//    ($y-1 > 0 implies forall $y : pow($x, $y) > 0)
// but will then fail, leaving a corrupt partial result
//    ($y-1 > 0 implies forall $y : pow($y+1, $y) > 0) // a false statement
// because the free variable $y in the replacement text got captured.
int form_replace_qvar(Form *f, char *qname, Form *repl) {
  HashTable *freevars = hash_new_vlen(4, hash_strlen);
  find_free_qvars(repl, freevars);
  int ret = replace_node(f, qname, repl, freevars);
  hash_destroy(freevars);
  return ret;
}

// Replace term-valued parameter references (F_TERM_PREF nodes) with given term,
// or stmt-valued parameter references (F_STMT_PREF nodes) with a given stmt.
// Return number of times replacement is made.
// This function fails, returning a negative value and leaving f in an unknown
// state, if any of the substitutions would capture a free variable in the
// replacement term.
int form_replace_param(Form *f, char *pname, Form *repl) {
  HashTable *freevars = hash_new_vlen(4, hash_strlen);
  find_free_qvars(repl, freevars);
  int ret = replace_node(f, pname, repl, freevars);
  hash_destroy(freevars);
  return ret;
}

// Replace term-valued parameter references (F_TERM_PREF nodes) with given term,
// or stmt-valued parameter references (F_STMT_PREF nodes) with a given stmt.
// Return number of times replacement is made.
// This function blindly replaces all occurences of the parameter reference
// with the given replacement, regardless of if the resulting substitution will
// capture free variables in the replacement term.
int form_set_param_blind(Form *f, char *pname, Form *repl) {
  return replace_node(f, pname, repl, NULL);
}

/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

static struct replace_stat * replace_nodes(Form *f, HashTable *infos);

struct replace_info {
  int idx;
  char *varname;
  Form *repl;
  HashTable *freevars;
};

struct replace_stat {
  int num_replaced;
  struct replace_info *info;
};

/** subroutine of replace_nodes: replace certain strings */
static struct replace_stat *
__replace_nodes_pref(Form *f, HashTable *infos, int ilen)
{
	struct replace_info *info;
	struct replace_stat *used;
	Form *dup;

	assert(f->len == -1);
	info = hash_findItem(infos, f->data);
	if (!info)
		return nxcompat_calloc(ilen, sizeof(struct replace_stat));

	// avoid bad substitution
	if (!((F_ISTERM(info->repl->tag) && F_ISTERM(f->tag)) || 
	      (F_ISSTMT(info->repl->tag) && F_ISSTMT(f->tag))))
		return NULL; 

	// create a replacement Form and overwrite the existing one
	dup = form_dup(info->repl);
	assert(f->data && !f->left && !f->mid && !f->right);
	nxcompat_free(f->data);
	memcpy(f, dup, sizeof(Form));
	nxcompat_free(dup);

	// update results
	assert(info->idx >= 0 && info->idx < ilen);
	used = nxcompat_calloc(ilen, sizeof(struct replace_stat));
	used[info->idx].info = info;
	used[info->idx].num_replaced = 1;
	return used;
}

/** subroutine of replace_nodes */
static struct replace_stat *
__replace_nodes_quantifier(Form *f, HashTable *infos, int ilen)
{
	struct replace_stat *used;
	int i;

	// todo: what happens with PREF as the variable? e.g. (forall %x : ...)
	assert(f->left->tag == F_TERM_QVAR);
	
	// replace children
	used = replace_nodes(f->right, infos);
	if (!used) 
		return NULL;

	// make sure that f->left is not among the variables used
	for (i = 0; i < ilen; i++) {
		if (used[i].num_replaced > 0 && hash_findItem(used[i].info->freevars, f->left->data)) {
			nxcompat_free(used);
			return NULL; // replacing [%x/...$y...] in (forall $y : ...$x...) would be a capture error
		}
	}
	
	return used;
}

/** Replace all occurrences in f of entries in table infos */
static struct replace_stat *
replace_nodes(Form *f, HashTable *infos) 
{
  struct replace_stat *used1, *used2, *used3;
  int i, n = hash_numEntries(infos);

  if ((f->tag == F_STMT_PREF || f->tag == F_TERM_PREF || f->tag == F_TERM_QVAR))
	  return __replace_nodes_pref(f, infos, n);

  // todo: capture avoidance in group lambda expressions too
  if (f->tag == F_STMT_FORALL || f->tag == F_STMT_EXISTS) 
	  return __replace_nodes_quantifier(f, infos, n);

  used1 = NULL;
  used2 = NULL;
  used3 = NULL;

  // traverse children
  switch (f->tag & F_ARITY_MASK) {
    case F_IS_TERNARY:
      used3 = replace_nodes(f->mid, infos);
    case F_IS_BINARY:
      used2 = replace_nodes(f->right, infos);
    case F_IS_UNARY:
      used1 = replace_nodes(f->left, infos);
      break;
    default:
      return nxcompat_calloc(n, sizeof(struct replace_stat));
  }

  // coalesce returned structures
  if (used2) {
    for (i = 0; i < n; i++) {
      used1[i].num_replaced += used2[i].num_replaced;
      used1[i].info = (used1[i].info ? used1[i].info : used2[i].info);
    }
    nxcompat_free(used2);
  }
  if (used3) {
    for (i = 0; i < n; i++) {
      used1[i].num_replaced += used3[i].num_replaced;
      used1[i].info = (used1[i].info ? used1[i].info : used3[i].info);
    }
    nxcompat_free(used3);
  }

  return used1;

cleanup_err:
  if (used3)
	  nxcompat_free(used3);
  if (used2)
	  nxcompat_free(used2);
  if (used1)
	  nxcompat_free(used1);
  return NULL;
}

int 
form_replace_all(Form *f, struct HashTable *replacements /* varname -> repl */) 
{
	struct HashTable *infos;
	struct replace_stat *used;
	int i, t, n;

	/** create a replacement table entry for each entry in replacements */
	int create_info_from_replacement(void *entry, void *unused) {
	  struct replace_info *info;
	  Form *repl;
	  char *varname;
	  
	  varname = hash_entryToKey(entry);
	  repl = hash_entryToItem(entry);
	  
	  info = nxcompat_calloc(1, sizeof(struct replace_info));
	  info->idx = hash_numEntries(infos);
	  info->varname = varname;
	  info->repl = repl;
	  info->freevars = hash_new_vlen(4, hash_strlen);
	  find_free_qvars(repl, info->freevars);
	  hash_insert(infos, varname, info);
	  return 0;
	}

	/** cleanup 'infos' table state */
	int destroy_info(void *entry, void *unused) {
		struct replace_info *info;
		
		info = hash_entryToItem(entry);
		hash_destroy(info->freevars);
		nxcompat_free(info);
		return 0;
	}

	if (!hash_numEntries(replacements))
		return 0;

	// create replacement table 'infos'
	infos = hash_new_vlen(4, hash_strlen);
	hash_iterateEntries(replacements, &create_info_from_replacement, NULL);

	// replace all nodes in f
	used = replace_nodes(f, infos);

	// cleanup
	hash_iterateEntries(infos, &destroy_info, NULL);
	hash_destroy(infos);

	if (!used)
		return -1;

	// calculate number of replacements
	n = hash_numEntries(replacements);
	t = 0;
	for (i = 0; i < n; i++)
		t += used[i].num_replaced;
	
	nxcompat_free(used);
	return t;
}

/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

#define unify_result(msg, res, f1, f2, map) res

int form_unify_params(Form *f, Form *pat, struct HashTable *map)
{
  if (pat->tag == F_TERM_PREF || pat->tag == F_STMT_PREF) {
    assert(pat->len == -1);
    Form *r = (Form *)hash_findItem(map, pat->data);
    if (r) {
      // metavar f is already unified
      return unify_result("form_unify_params", form_cmp(f, r), f, r, map);
    } else {
      // check level, set replacement
      if (F_ISSTMT(f->tag) != F_ISSTMT(pat->tag))
	return unify_result("form_unify_params", 1, f, pat, map);
      hash_insert(map, pat->data, form_dup(f));
      return unify_result("form_unify_params", 0, f, pat, map);
    }
  }
  // f is not a metavar
  if (f->tag != pat->tag)
    return unify_result("form_unify_params", 1, f, pat, map);
  switch (f->tag & F_ARITY_MASK) {
    case F_IS_TERNARY:
      if (!f->mid != !pat->mid) return unify_result("form_unify_params", 1, f, pat, map);
      if (f->mid && form_unify_params(f->mid, pat->mid, map)) return 1;
      // fall through
    case F_IS_BINARY:
      if (!f->right != !pat->right) return unify_result("form_unify_params", 1, f, pat, map);
      if (f->right && form_unify_params(f->right, pat->right, map)) return 1;
      // fall through
    case F_IS_UNARY:
      if (!f->left != !pat->left) return unify_result("form_unify_params", 1, f, pat, map);
      if (f->left && form_unify_params(f->left, pat->left, map)) return 1;
      return unify_result("form_unify_params", 0, f, pat, map);
    case F_IS_EMPTY:
      return unify_result("form_unify_params", 0, f, pat, map);
    case F_IS_VALUE:
      return unify_result("form_unify_params", f->value != pat->value, f, pat, map);
    case F_IS_DATA:
      if (f->len != pat->len) return unify_result("form_unify_params", 1, f, pat, map);
      if (f->len == 0)
	return unify_result("form_unify_params", 0, f, pat, map);
      else if (f->len < 0)
	return unify_result("form_unify_params", strcmp(f->data, pat->data), f, pat, map);
      else
	return unify_result("form_unify_params", memcmp(f->data, pat->data, f->len), f, pat, map);
    default:
      return unify_result("form_unify_params", 1, f, pat, map); 
  }
}
#undef unify_result

