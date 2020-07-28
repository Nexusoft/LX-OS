#include <string>
#include <iostream>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifndef NOT_NEXUS
extern "C" {
#include <compat/Profile.interface.h>
extern int writefile(char *filename, char *buffer, int size);
}
#endif

std::string int2str(int num){
  char ret_c[11];
  std::string ret_s;
  sprintf(ret_c, "%d", num);
  
  ret_s = ret_c;
  return ret_s;
}

std::string ip2str(unsigned int ip){
  return "" + int2str((ip >> 24)&0xFF) + "." + int2str((ip >> 16)&0xFF) + "." + int2str((ip >> 8)&0xFF) + "." + int2str((ip >> 0)&0xFF);
}

std::string filter_host_port_pair(unsigned int ip, unsigned int port){
  return "((src host " + ip2str(ip) + ")&&(src port " + int2str(port) + "))||\n\t((dst host " + ip2str(ip) + ")&&(dst port " + int2str(port) + "))";
}

#ifndef NOT_NEXUS
struct timeval start_profile(int profiler){
  struct timeval now;
  Profile_Enable(profiler);
  gettimeofday(&now, NULL);
  return now;
}
unsigned int stop_profile(struct timeval start){
  struct timeval now;
  unsigned int delta;

  gettimeofday(&now, NULL);
  
  Profile_Enable(0);

  delta = now.tv_sec - start.tv_sec;
  delta *= 1000 * 1000;
  delta += now.tv_usec;
  delta -= start.tv_usec;
  return delta;
}

// 16 megs should be enough
#define PROFILE_SIZE (16 * 1000 * 1000)
unsigned int write_profile(char *fname){
  char *data = (char *)malloc(PROFILE_SIZE);
  int len;
  len = Profile_ReadSamples((unsigned char *)data);
  assert(len < PROFILE_SIZE);
  FILE *f = fopen(fname, "w+");
  assert(f);
  fwrite(data, sizeof(char), len, f);
  fclose(f);
  return len;
}
#else
struct timeval start_profile(){
  struct timeval now;
  gettimeofday(&now, NULL);
  return now;
}
unsigned int stop_profile(struct timeval start){
  struct timeval now;
  unsigned int delta;
  gettimeofday(&now, NULL);
  delta = now.tv_sec - start.tv_sec;
  delta *= 1000 * 1000;
  delta += now.tv_usec;
  delta -= start.tv_usec;
  return delta;
}
#endif //NOT_NEXUS

void *offset(void *ptr, int off){
  return (void *)&(((char *)ptr)[off]);
}

void fwrite_ip(int i, int swaporder, FILE *f){
 if(swaporder){
    i = ntohl(i);
  }
  fprintf(f, "%d.%d.%d.%d", (i >> (24))&0xff, (i >> (16))&0xff, (i >> (8))&0xff, (i)&0xff);
}
void print_ip(int i, int swaporder){
  fwrite_ip(i, swaporder, stdout);
}
