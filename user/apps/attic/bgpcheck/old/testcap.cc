#include <iostream>
extern "C" {
#include <nexus/Net.interface.h>
}
int main(int argc, char **argv){
  char packet_data[1600];
  int len;
  Net_Router_Enable(1);
  printf("Welcome to TCPCap!\n");

  printf("foo: %d\n", malloc(1024));

    len = Net_Router_Recv(packet_data, sizeof(packet_data), 1);
    printf("Got a packet: len = %d\n", len);
}
