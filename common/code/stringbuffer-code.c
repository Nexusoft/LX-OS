
// note: this code exists in both userspace and kernelspace
// do not use any includes in this file (to keep the dependency
// checking easy)

// String buffer

StringBuffer *StringBuffer_new(int initial_len) {
  StringBuffer *sb = nxcompat_alloc(sizeof(*sb));
  sb->data = nxcompat_alloc(initial_len);
  sb->data[0] = '\0';
  sb->data_len = 1;
  sb->space_len = initial_len;
  return sb;
}

void StringBuffer_destroy(StringBuffer *sb) {
  nxcompat_free(sb->data);
  nxcompat_free(sb);
}

void SB_cat(StringBuffer *sb, const char *src) {
  if(sb->space_len - sb->data_len < strlen(src)) {
    int new_len = sb->space_len + strlen(src);
    char *new_buf = nxcompat_alloc(new_len);
    memcpy(new_buf, sb->data, sb->data_len);
    nxcompat_free(sb->data);
    sb->data = new_buf;
    sb->space_len = new_len;
  }
  // overwrite existing null terminator
  strcpy(sb->data + sb->data_len - 1, src);
  sb->data_len += strlen(src);
}

const char *SB_c_str(StringBuffer *sb) {
  return sb->data;
}

void SB_printf(StringBuffer *sb, char *format, ...) {
#define BUFSIZE (4096)
  char *buf = nxcompat_alloc(BUFSIZE);
  va_list args;
  va_start(args, format);
  vsnprintf(buf, BUFSIZE, format, args);
  va_end(args);
  if(strlen(format) == BUFSIZE - 1) {
    printf("Warning: SB_printf() buf overflow!\n");
  }
  SB_cat(sb, buf);
  nxcompat_free(buf);
}
