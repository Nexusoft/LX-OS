#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pxslt.h"
#include "odf_sign.h"

int sec_level, list_level;

int odf2docbook_printone(char *buf, int len, struct xn *xn);
int odf2docbook_print(char *buf, int len, struct xn *xn) {
  int i, out = 0;
  for (; xn; xn = xn->sib) {
    out += odf2docbook_printone(buf+out, len-out, xn);
  }
  return out;
}

int odf2docbook_printone(char *buf, int len, struct xn *xn) {
  int out = 0;
  if (!xn->tag) {
    out += snprintf(buf+out, (len<out?0:len-out), "%s", xn->arg);
  }
  else if (!strcmp(xn->tag, "office:body")) {
    //out += snprintf(buf+out, (len<out?0:len-out), "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    out += snprintf(buf+out, (len<out?0:len-out), "<!DOCTYPE article PUBLIC \"-//OASIS//DTD DocBook XML V4.1.2//EN\" \"http://www.oasis-open.org/docbook/xml/4.1.2/docbookx.dtd\">");
    out += snprintf(buf+out, (len<out?0:len-out), "<article>");
    sec_level = list_level = 0;
    out += odf2docbook_print(buf+out, len-out, xn->son);
    while (0 < sec_level) {
      out += snprintf(buf+out, (len<out?0:len-out), "</Section>");
      sec_level--;
    }
    out += snprintf(buf+out, (len<out?0:len-out), "</article>");
  }
  else if (!strcmp(xn->tag, "text:p")) {
    if (!xn->son) out += snprintf(buf+out, (len<out?0:len-out), "<para/>");
    else {
      out += snprintf(buf+out, (len<out?0:len-out), "<para>");
      out += odf2docbook_print(buf+out, len-out, xn->son);
      out += snprintf(buf+out, (len<out?0:len-out), "</para>");
    }
  }
  else if (!strcmp(xn->tag, "text:h")) {
    int lvl = 1;
    sscanf(xn->arg, "text:outline-level=\"%d\"", &lvl);
    while (lvl <= sec_level) {
      out += snprintf(buf+out, (len<out?0:len-out), "</Section>");
      sec_level--;
    }
    while (lvl > sec_level) {
      out += snprintf(buf+out, (len<out?0:len-out), "<Section>");
      sec_level++;
    }
    out += snprintf(buf+out, (len<out?0:len-out), "<Title>");
    out += odf2docbook_print(buf+out, len-out, xn->son);
    out += snprintf(buf+out, (len<out?0:len-out), "</Title>");
  }
  else if (!strcmp(xn->tag, "text:list")) {
    out += snprintf(buf+out, (len<out?0:len-out), "<ItemizedList>");
    out += odf2docbook_print(buf+out, len-out, xn->son);
    out += snprintf(buf+out, (len<out?0:len-out), "</ItemizedList>");
  }
  else if (!strcmp(xn->tag, "text:list-item")) {
    out += snprintf(buf+out, (len<out?0:len-out), "<ListItem>");
    out += odf2docbook_print(buf+out, len-out, xn->son);
    out += snprintf(buf+out, (len<out?0:len-out), "</ListItem>");
  }
  else if (!strcmp(xn->tag, "dc:date")) {
    out += snprintf(buf+out, (len<out?0:len-out), "<para>");
    out += odf2docbook_print(buf+out, len-out, xn->son);
    out += snprintf(buf+out, (len<out?0:len-out), "</para>");
  }
  else if (!strcmp(xn->tag, "draw:frame") && xn->son && !strcmp(xn->son->tag, "draw:text-box") && !xn->son->sib) {
    struct xn *xx = xn->son->son;
    for (; xx && xx->sib; xx = xx->sib);
    if (!strcmp(xx->tag, "text:p") && !xx->son->tag && !strncmp(xx->son->arg, "-- ", 3)) {
      // xx is last line in frame; its last child might be an annotation
      struct xn *xy = xx->son;
      for (; xy && xy->sib; xy = xy->sib);
      if (xy && xy->tag && !strcmp(xy->tag, "office:annotation")) {
	// smells like a TruDoc blockquote annotation
	out += snprintf(buf+out, (len<out?0:len-out), "<BlockQuote>");
	out += snprintf(buf+out, (len<out?0:len-out), "<Attribution>");
	out += snprintf(buf+out, (len<out?0:len-out), "%s", xx->son->arg + 3);
	out += snprintf(buf+out, (len<out?0:len-out), "</Attribution>");
	out += snprintf(buf+out, (len<out?0:len-out), "<Comment>");
	out += odf2docbook_print(buf+out, len-out, xy);
	out += snprintf(buf+out, (len<out?0:len-out), "</Comment>");
	xx = xn->son->son;
	for (; xx && xx->sib; xx = xx->sib) {
	  out += odf2docbook_printone(buf+out, len-out, xx);
	}
	out += snprintf(buf+out, (len<out?0:len-out), "</BlockQuote>");
      }
      else {
	// smells like a non-TruDoc blockquote
	out += snprintf(buf+out, (len<out?0:len-out), "<BlockQuote>");
	out += snprintf(buf+out, (len<out?0:len-out), "<Attribution>");
	out += odf2docbook_print(buf+out, len-out, xx);
	out += snprintf(buf+out, (len<out?0:len-out), "</Attribution>");
	xx = xn->son->son;
	for (; xx && xx->sib; xx = xx->sib) {
	  out += odf2docbook_printone(buf+out, len-out, xx);
	}
	out += snprintf(buf+out, (len<out?0:len-out), "</BlockQuote>");
      }
    }
    else {
      // smells like a non-quote
      out += odf2docbook_print(buf+out, len-out, xn->son);
    }
  }
  else {
    out += odf2docbook_print(buf+out, len-out, xn->son);
  }
  return out;
}

static char *odf2docbook(char *odf)
{
  struct xn *xn = odf_parse(odf);
  if (!xn) return NULL;
  int len = odf2docbook_print(NULL, 0, xn) + 1;
  if (len <= 0) return NULL;
  char *buf = malloc(len+1);
  odf2docbook_print(buf, len, xn);
  buf[len] = '\0';
  return buf;
}

char *pxslt(char *stylesheet, char *xml)
{
  if (!strcmp(stylesheet, "<odf2docbook>"))
    return odf2docbook(xml);
  return NULL;
}

