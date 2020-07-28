#include <iostream>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "../include/util/filebuffer.h"

FileBuffer::FileBuffer(char *name, int _size){
  f = open(name, O_RDONLY);
  size = _size;
  buffer = new unsigned char[size];
  altbuffer = new unsigned char[size];
  read_size = altread_size = ptr = 0;
  cnt = 0;
}
FileBuffer::FileBuffer(int _f, int _size){
  f = _f;
  size = _size;
  buffer = new unsigned char[size];
  altbuffer = new unsigned char[size];
  read_size = altread_size = ptr = 0;
  cnt = 0;
}
FileBuffer::FileBuffer(unsigned int host, unsigned short port, int _size){
  int sock;
  int err;
  sockaddr_in saddr;
  size = _size;
  cnt = 0;
  buffer = new unsigned char[size];
  altbuffer = new unsigned char[size];
  read_size = altread_size = ptr = 0;
  f = -1;

  memset(&saddr, 0, sizeof(struct sockaddr_in));
    
  sock = socket(PF_INET, SOCK_STREAM, 0);
  if(sock < 0){
    return;
  }

  saddr.sin_port = htons(port);
  saddr.sin_addr.s_addr = host;
  saddr.sin_family = AF_INET;
  if((err = connect(sock, (struct sockaddr *)&saddr, sizeof(sockaddr_in))) < 0){
    perror("error!\n");
    printf("Uh, oh: %08x:%d (%d)\n", host, port, errno);
    close(sock);
    return;
  }

  f = sock;
}
FileBuffer::~FileBuffer(){
  close(f);
}

void FileBuffer::reset(){
  cnt = 0;
  read_size = altread_size = ptr = 0;
  if(f >= 0){
    lseek(f, 0, SEEK_SET);
  }
}
void FileBuffer::prefetch(){
  if(altread_size != 0){
    //printf("%d,%d,%d,%d,%p,%p\n", size, altread_size, read_size, ptr, buffer, altbuffer);
    //assert(0);
    return;
  }
  altread_size = read(f, altbuffer, size);
  if(altread_size == 0){
    altread_size = -1; //signal an error when we reach the end.
  }
}
void FileBuffer::swap(){
  unsigned char *tmp = buffer;
  
  read_size = altread_size;
  buffer = altbuffer;
  altbuffer = tmp;
  ptr = altread_size = 0;
}
int FileBuffer::get(void *bytes, int len){
  int totread = 0, maxread;
  if(f < 0) return 0;
  while(len > 0){
    if(read_size < 0) return read_size;
    
    maxread = read_size - ptr;
    if(maxread > 0){
      if(maxread > len){
        maxread = len;
      }
      memcpy(bytes, buffer+ptr, maxread);
      ptr += maxread;
      bytes = &(((char *)bytes)[maxread]);
      totread += maxread;
      len -= maxread;
    } else {
      prefetch();
      swap();
    }
  }
  cnt += totread;
  return totread;
}
void FileBuffer::skip(int len){
  int maxread;
  cnt += len;
  while(len > 0){
    if(read_size < 0) return;
    
    maxread = read_size - ptr;
    if(maxread > 0){
      if(maxread > len){
        maxread = len;
      }
      ptr += maxread;
      len -= maxread;
    } else {
      prefetch();
      swap();
    }
  }
}
int FileBuffer::read_cnt(){
  return cnt;
}
int FileBuffer::at_eof(){
  return (f < 0) || (read_size < 0);
}
