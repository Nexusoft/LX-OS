#ifndef FILEBUFFER_H_SHIELD
#define FILEBUFFER_H_SHIELD

class FileBuffer {
 public:
  FileBuffer(char *name, int _size);
  FileBuffer(int _f, int _size);
  FileBuffer(unsigned int host, unsigned short port, int _size);
  ~FileBuffer();
  
  void reset();
  void prefetch();
  int get(void *bytes, int len);
  void skip(int len);
  int at_eof();
  int read_cnt();
  
 private:
  unsigned char *buffer;
  unsigned char *altbuffer;
  int read_size;
  int altread_size;
  int size;
  int ptr;
  int f;
  int cnt;
  
  unsigned int ip;
  unsigned int port;
  
  void swap();
};

#endif
