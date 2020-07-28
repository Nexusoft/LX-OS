#ifndef _NEXUS_STRINGBUFFER_H_
#define _NEXUS_STRINGBUFFER_H_

//// Self-expanding string buffer

struct StringBuffer {
  char *data;
  int data_len;
  int space_len;
};

StringBuffer *StringBuffer_new(int initial_len);
void StringBuffer_destroy(StringBuffer *sb);

void SB_cat(StringBuffer *sb, const char *src);

const char *SB_c_str(StringBuffer *sb);

// todo: SB_printf(StringBuffer *, char *format, ...)

void SB_printf(StringBuffer *, char *format, ...);

#endif
