#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "odf_sign.h"

char *odf_namespaces =
    "xmlns:chart=\"urn:oasis:names:tc:opendocument:xmlns:chart:1.0\" "
    "xmlns:dc=\"http://purl.org/dc/elements/1.1/\" "
    "xmlns:dom=\"http://www.w3.org/2001/xml-events\" "
    "xmlns:dr3d=\"urn:oasis:names:tc:opendocument:xmlns:dr3d:1.0\" "
    "xmlns:draw=\"urn:oasis:names:tc:opendocument:xmlns:drawing:1.0\" "
    "xmlns:fo=\"urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0\" "
    "xmlns:form=\"urn:oasis:names:tc:opendocument:xmlns:form:1.0\" "
    "xmlns:math=\"http://www.w3.org/1998/Math/MathML\" "
    "xmlns:meta=\"urn:oasis:names:tc:opendocument:xmlns:meta:1.0\" "
    "xmlns:number=\"urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0\" "
    "xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" "
    "xmlns:ooo=\"http://openoffice.org/2004/office\" "
    "xmlns:oooc=\"http://openoffice.org/2004/calc\" "
    "xmlns:ooow=\"http://openoffice.org/2004/writer\" "
    "xmlns:script=\"urn:oasis:names:tc:opendocument:xmlns:script:1.0\" "
    "xmlns:style=\"urn:oasis:names:tc:opendocument:xmlns:style:1.0\" "
    "xmlns:svg=\"urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0\" "
    "xmlns:table=\"urn:oasis:names:tc:opendocument:xmlns:table:1.0\" "
    "xmlns:text=\"urn:oasis:names:tc:opendocument:xmlns:text:1.0\" "
    "xmlns:xforms=\"http://www.w3.org/2002/xforms\" "
    "xmlns:xlink=\"http://www.w3.org/1999/xlink\" "
    "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
    "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
    "office:version=\"1.0\"";

char *docbook_doctype =
  "article PUBLIC "
  "\"-//OASIS//DTD DocBook XML V4.1.2//EN\" "
  "\"http://www.oasis-open.org/docbook/xml/4.1.2/docbookx.dtd\"";

int descend(char **xml, char *end, struct xn **res);

void *fail(char *msg) {
  printf("fail: %s\n", msg);
  exit(1);
  return NULL;
}


// visit - read a tag, parse contents, read end tag; or read cdata
struct xn *visit(char **xml, char *end)
{
  if (*xml >= end)
    return NULL;
  if ((*xml)[0] == '<') {
    if ((*xml)[1] == '/')
      return NULL; // fail("unexpected closing tag");
    if ((*xml) + 2 >= end)
      return fail("unexpected end of stream");
    if ((*xml)[1] == '>')
      return fail("empty tag");
    // find closing angle brace
    char *tag = *xml + 1;
    char *tagend = NULL;
    *xml += 2;
    while (**xml != '>' && *xml < end) {
      if (**xml == ' ' && !tagend) tagend = *xml;
      (*xml)++;
    }
    if (**xml != '>')
      return fail("tag missing end");
    if (!tagend) tagend = *xml;
    char *argend = *xml;
    if ((*xml)[-1] == '/') {
      argend--;
      tagend--;
    }
    struct xn *xn = malloc(sizeof(struct xn));
    memset(xn, 0, sizeof(struct xn));
    xn->tag = malloc(tagend - tag + 1);
    memcpy(xn->tag, tag, tagend - tag);
    xn->tag[tagend - tag] = '\0';
    if (argend - tagend > 1) {
      xn->arg = malloc(argend - tagend - 1 + 1);
      memcpy(xn->arg, tagend + 1, argend - tagend - 1);
      xn->arg[argend - tagend - 1] = '\0';
    }
    (*xml)++;
    if ((*xml)[-2] == '/') {
      return xn;
    }
    if (descend(xml, end, &xn->son)) {
      xn_free(xn);
      return fail("malformed contents");
    }
    if (tag[0] == '!') {
      return xn;
    }
    if (((*xml)[0] != '<') ||
      ((*xml)[1] != '/') ||
	strncmp(*xml+2, tag, tagend-tag) ||
	(*xml)[2+tagend-tag] != '>') {
      xn_free(xn);
      return fail("missing close tag");
    }
    *xml += 3 + tagend-tag;
    return xn;
  } else {
    // cdata
    char *cdata = *xml;
    while (**xml != '<' && *xml < end) (*xml)++;
    struct xn *xn = malloc(sizeof(struct xn));
    memset(xn, 0, sizeof(struct xn));
    xn->arg = malloc(*xml - cdata + 1);
    memcpy(xn->arg, cdata, *xml - cdata);
    xn->arg[*xml - cdata] = '\0';
    return xn;
  }
}

// descend - read a sequence of nodes and construct a list; stop at unexpected close tag
int descend(char **xml, char *end, struct xn **res)
{
  *res = visit(xml, end);
  while (*res) {
    res = &(*res)->sib;
    *res = visit(xml, end);
  }
  return 0;
}

#define FAIL(msg...) do { printf(msg); printf("\n"); if (xn) xn_free(xn); return NULL; } while (0)
struct xn *odf_parse(char *xml)
{
  //printf("decoding: %.50s\n", xml);
  struct xn *xn = xn_parse(xml);
  if (!xn || !xn->tag || !xn->arg ||
      strcmp(xn->tag, "office:document-content") ||
      strcmp(xn->arg, odf_namespaces) || !xn->son || xn->sib)
    FAIL("not a suitable openoffice document");

  // look for the "office:body" node
  struct xn *body = xn->son;
  while (body && (!body->tag || strcmp(body->tag, "office:body"))) {
    struct xn *dead = body;
    body = body->sib;
    dead->sib = NULL;
    xn_free(dead);
  }
  xn->son = body;
  if (body && body->sib) {
    xn_free(body->sib);
    body->sib = NULL;
  }
  if (!body) FAIL("document missing body");

  struct xn *dead = xn;
  xn = body;
  dead->son = NULL;
  xn_free(dead);

  return xn;
}
#undef FAIL

void xn_free(struct xn *xn) {
  // todo
}

int xn_tostring1(char *buf, int len, struct xn *xn, int canonical)
{
  int out = 0;
  static int indent = 0;
  int i;
  for (; xn; xn = xn->sib) {
    if (!xn->tag) {
      out += snprintf(buf+out, (len<out?0:len-out), "%s", xn->arg);
    } else {
      if (!canonical) {
	for (i = 0; i < indent; i++) out += snprintf(buf+out, (len<out?0:len-out), " ");
      }
      out += snprintf(buf+out, (len<out?0:len-out), "<%s", xn->tag);
      if (xn->arg) out += snprintf(buf+out, (len<out?0:len-out), " %s", xn->arg);
      if (canonical) {
	out += snprintf(buf+out, (len<out?0:len-out), ">");
	if (xn->son) out += xn_tostring1(buf+out, len-out, xn->son, canonical);
	out += snprintf(buf+out, (len<out?0:len-out), "</%s>", xn->tag);
      } else {
	if (xn->son) { 
	  out += snprintf(buf+out, (len<out?0:len-out), ">");
	  if (xn->son->tag) out += snprintf(buf+out, (len<out?0:len-out), "\n");
	  indent++;
	  out += xn_tostring1(buf+out, len-out, xn->son, canonical);
	  indent--;
	  for (i = 0; i < indent; i++) out += snprintf(buf+out, (len<out?0:len-out), " ");
	  out += snprintf(buf+out, (len<out?0:len-out), "</%s>\n", xn->tag);
	} else {
	  out += snprintf(buf+out, (len<out?0:len-out), "/>\n");
	}
      }
    }
  }
  return out;
}

char *xn_tostring(struct xn *xn, int canonical)
{
  int len = xn_tostring1(NULL, 0, xn, canonical) + 1;
  if (len <= 0) return NULL;
  char *buf = malloc(len+1);
  int len2 = xn_tostring1(buf, len+1, xn, canonical) + 1;
  assert(len == len2);
  return buf;
}

void xn_print(struct xn *xn, int canonical)
{
  char *str = xn_tostring(xn, canonical);
  printf("%s%s", str, (canonical?"":"\n"));
  free(str);
}

struct xn *xn_dup(struct xn *xn) {
  if (!xn) return NULL;
  struct xn *x = malloc(sizeof(struct xn));
  memset(x, 0, sizeof(struct xn));
  if (xn->tag) x->tag = strdup(xn->tag);
  if (xn->arg) x->arg = strdup(xn->arg);
  if (xn->sib) x->sib = xn_dup(xn->sib);
  if (xn->son) x->son = xn_dup(xn->son);
  x->s = xn->s;
  x->e = xn->e;
  return x;
}

static char *simple_text(struct xn *xn) {
  if (xn && xn->tag && !strcmp(xn->tag, "text:p")
      && xn->son && !xn->son->sib && !xn->son->tag)
    return xn->son->arg;
  return NULL;
}

int xq_fill(struct xq *xq, struct xn *xn) {

#define FAIL(msg...) do { printf(msg); printf("\n"); return 1; } while (0)

      char *att_header = "Nexus Attribution Service attests to the following source:";
      if (!(xn && xn->tag && !strcmp(xn->tag, "office:annotation")
	  && xn->son && xn->son->sib && xn->son->sib->tag && !strcmp(xn->son->sib->tag, "text:p")
	  && xn->son->sib->son && !xn->son->sib->son->tag
	  && !strncmp(xn->son->sib->son->arg, att_header, strlen(att_header))
	  && !xn->son->sib->son->sib)) {
	FAIL("malformed quote attribution: bad structure\n");
      }

      struct xn *x = xn->son->sib->sib;

      char *line = simple_text(x);
      if (!line || strcmp(line, "Source document:"))
	FAIL("malformed quote attribution: missing source information");

      line = simple_text(x = x->sib);
      if (!line || strncmp(line, " hash=", strlen(" hash=")))
	FAIL("malformed quote attribution: missing source hash");
      line +=strlen(" hash=");
      if (strlen(line) >= sizeof(xq->dochash))
	FAIL("malformed quote attribution: too big source hash");
      strcpy(xq->dochash, line);

      line = simple_text(x = x->sib);
      if (!line || strncmp(line, " author=", strlen(" author=")))
	FAIL("malformed quote attribution: missing source author");
      line +=strlen(" hash=");
      if (strlen(line) >= sizeof(xq->author))
	FAIL("malformed quote attribution: too big source author");
      strcpy(xq->author, line);

      line = simple_text(x = x->sib);
      if (!line || strncmp(line, " published at=", strlen(" published at=")))
	FAIL("malformed quote attribution: missing source publishing date");
      line +=strlen(" hash=");
      if (strlen(line) >= sizeof(xq->date))
	FAIL("malformed quote attribution: too big source publishing date");
      strcpy(xq->date, line);

      line = simple_text(x = x->sib);
      if (!line || strncmp(line, "Restrictions:", strlen("Restrictions:")))
	FAIL("malformed quote attribution: missing source restrictions");

      line = simple_text(x->sib);
      char *restrictions = xq->restrictions;
      while (line && line[0] == ' ') {
	if (strlen(line) + strlen(xq->restrictions) >= sizeof(xq->restrictions))
	  FAIL("malformed quote attribution: too many restrictions");
	strcat(xq->restrictions, line+1);
	strcat(xq->restrictions, "\n");
	line = simple_text((x = x->sib)->sib);
      }

      line = simple_text(x = x->sib);
      if (!line || strncmp(line, "Quoted text:", strlen("Quoted text:")))
	FAIL("malformed quote attribution: missing original quoted text");

      line = simple_text(x = x->sib);
      if (!line)
	FAIL("malformed quote attribution: missing original quoted text body");
      xq->originaltext = strdup(line);

      if (x->sib)
	FAIL("malformed quote attribution: junk at and");
#undef FAIL

      return 0;
}

void pull_annotations(PointerVector *v, struct xn **xn) {
  while(*xn) {
    if ((*xn)->tag && !strcmp((*xn)->tag, "office:annotation")) {
      PointerVector_append(v, *xn);
      *xn = (*xn)->sib;
      continue;
    }
    if ((*xn)->son) pull_annotations(v, &(*xn)->son);
    xn = &((*xn)->sib);
  }
}

// find top-level quotes: (draw:frame (draw:text-box ...))
void xq_find(PointerVector *vq, struct xn *xn) {
  for ( ; xn; xn = xn->sib) {
    if (xn->tag
	&& !strcmp(xn->tag, "draw:frame") 
	&& xn->son
	&& !xn->son->sib 
	&& xn->son->tag 
	&& !strcmp(xn->son->tag, "draw:text-box")
	&& xn->son->son) {
      struct xq *xq = malloc(sizeof(struct xq));
      memset(xq, 0, sizeof(struct xq));
      xq->body = xn_dup(xn->son->son);

      PointerVector v;
      PointerVector_init(&v, 4, POINTERVECTOR_ORDER_PRESERVING);
      pull_annotations(&v, &xq->body);
      if (!xq->body)
	//oops: pulled the body itself
	continue;
      int n = PointerVector_len(&v);
      struct xn *ann = NULL;
      if (n > 0) {
	  xq->attested = 1;
	  ann = PointerVector_nth(&v, 0);
      }
      if (n > 1)
	  xq->malformed = 1;
      PointerVector_dealloc(&v);

      if (ann) xq_fill(xq, ann);
      if (xq->body->sib) {
	struct xn *x, *a;
	for (x = xq->body; x->sib->sib; x = x->sib);
	// does it look like an attribution?
	a = x->sib;
	if (a->tag && !strcmp(a->tag, "text:p") && a->son && !a->son->tag && !strncmp(a->son->arg, "-- ", 3)) {
	  xq->attrib = x->sib;
	  x->sib = NULL;
	}
      }

      PointerVector_append(vq, xq);
    } else {
      if (xn->son) xq_find(vq, xn->son);
    }
  }
}

void xq_print(struct xq *xq) {
  printf("quote:");
  printf(" (%sattested)%s\n", xq->attested ? "" : "not ", xq->malformed ? " (malformed)" : "");
  if (xq->attested) {
    printf(" hash=%s\n", xq->dochash);
    printf(" author=%s\n", xq->author);
    printf(" published at=%s\n", xq->date);
    printf(" restrictions: %s\n", xq->restrictions);
    printf(" attribution: "); if (xq->attrib) { xn_print(xq->attrib, 1); } printf("\n");
    printf(" originaltext: %s\n", xq->originaltext ? xq->originaltext : "");
  }
  printf(" body: "); xn_print(xq->body, 1); printf("\n");
}

void xq_free(struct xq *xq) {

}

int xn_text0(struct xn *xn, char *txt, int s) {
  xn->s = s;
  if (xn->son) {
    xn->e = xn_text0(xn->son, txt, s);
  } else if (!xn->tag) {
    xn->e = s + strlen(xn->arg);
    if (txt) strcpy(txt+s, xn->arg);
  } else {
    xn->e = s;
  }
  if (xn->tag && !strcmp(xn->tag, "text:p")) {
    xn->e += 1;
    if (txt) strcpy(txt+xn->e-1, "\n");
  }
  return (xn->sib ? xn_text0(xn->sib, txt, xn->e) : xn->e);
}

char *xn_text(struct xn *xn) {
  int e = xn_text0(xn, NULL, 0);
  char *txt = malloc(e+1);
  xn_text0(xn, txt, 0);
  return txt;
}

int xn_cmp(struct xn *a, struct xn *b)
{
  /* printf("a:\n");
  xn_print(a, 0);
  printf("\nb:\n");
  xn_print(b, 0);
  printf("\n"); */

  if (!a && !b) return 0; // both null
  if (!a || !b) return 1; // one null
  if (!a->tag) {
    if (a->tag || strcmp(a->arg, b->arg)) return 1; // mismatch strings
    return xn_cmp(a->sib, b->sib);
  } else {
    if (a->arg)
      if (!b->arg || strcmp(a->arg, b->arg)) return 1; // mismatch args
    return xn_cmp(a->son, b->son) || xn_cmp(a->sib, b->sib);
  }
}

void xn_trim(struct xn **xnp, int s, int e)
{
  // todo: leaks
  struct xn *xn = *xnp;
  while(xn && xn->e <= s) {
    xn = xn->sib;
    *xnp = xn;
  }
  if (!xn)
    return;
  if (xn->s >= e) {
    *xnp = NULL;
    return;
  }
  if (!xn->tag) {
    int chop = xn->e - e;
    if (chop > 0) {
      // delete a suffix of chars
      xn->arg[xn->e - xn->s - chop] = '\0';
    }
    chop = s - xn->s;
    if (chop > 0) {
      // delete a prefix of chars
      char *x = malloc(strlen(xn->arg)+1-chop);
      strcpy(x, xn->arg+chop);
      free(xn->arg);
      xn->arg = x;
    }
  } else if (xn->son) {
    xn_trim(&xn->son, s, e);
  }
  if (xn->sib) {
    xn_trim(&xn->sib, s, e);
  }
}

int xq_match(struct xq *xq, struct xn *xn)
{
  if (xn && xn->tag && !strcmp(xn->tag, "office:body")) xn = xn->son;
  if (xn && xn->tag && !strcmp(xn->tag, "office:text")) xn = xn->son;
  if (!xn) return -1;
  return xn_match(xq->body, xn);
}

// todo: caller make sure hashes match: xq->hash == doc->content_digest
int xn_match(struct xn *xq, struct xn *xn)
{
  char *src = xn_text(xn);
  char *ex = xn_text(xq);
  int n = strlen(ex);
  if (n > 0 && ex[n-1] == '\n') ex[--n] = '\0';

  printf("searching for: %s\namong: %s\n", ex, src);

  char *match = strstr(src, ex);
  while (match) {
    int pos = match - src;
    // see if we can fit the tree here
    struct xn *t = xn_dup(xn);
    xn_trim(&t, pos, pos+n);
    if (!xn_cmp(t, xq))
      return pos;
    else
      printf("false hit at position %d\n", pos);
    match = strstr(match+1, ex);
  }

  return -1;
}

#define FAIL(msg...) do { printf(msg); printf("\n"); if (xn) xn_free(xn); return NULL; } while (0)
struct xn *docbook_parse(char *xml)
{
  struct xn *xn = xn_parse(xml);
  if (!xn || !xn->tag || !xn->arg ||
      strcmp(xn->tag, "!DOCTYPE") ||
      strcmp(xn->arg, docbook_doctype) ||
      !xn->son || xn->sib ||
      !xn->son->tag || xn->son->arg || xn->son->sib ||
      strcmp(xn->son->tag, "article"))
    FAIL("not a suitable docbook document");

  // return the article node
  struct xn *body = xn->son;
  struct xn *dead = xn;
  xn = body;
  dead->son = NULL;
  xn_free(dead);

  return xn;
}
#undef FAIL

#define FAIL(msg...) do { printf(msg); printf("\n"); if (xn) xn_free(xn); return NULL; } while (0)
struct xn *xn_parse(char *xml) {
  char *p = xml;
  char *e = xml + strlen(xml);
  struct xn *xn = visit(&p, e);
  if (!xn || p != e)
    FAIL("malformed or non-canonical xml");
  return xn;
}
#undef FAIL
