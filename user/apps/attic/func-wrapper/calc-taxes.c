#include "WrapStream.interface.h"
#include "calc-taxes.h"
#include <nexus/LabelStore.interface.h>
#include <nexus/formula.h>
#include <nexus/vkey.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define TRANSFERLEN (1024)

double _sum_vector[SUM_VECTOR_LEN] = {
  SUM_COEFFICIENTS
};

double *sum_vector = &_sum_vector[0];
int g_wrap_stream_port_num;

int main(int argc, char **argv) {
  if(argc < 2) {
    printf("Usage: calc-taxes <wrap channel #>\n");
    printf("Args: %d\n", argc);
    int i;
    for(i=0; i < argc; i++) {
      printf("[%d] = %s\n", i, argv[i]);
    }
    exit(-1);
  }
  // Label self
  FSID store;
  char *store_name = "public_labels";
  FSID hashcred_id;
  SignedFormula *hashcred;
  int cred_len;
  printf("Creating Label Store (%s)... ", store_name);
  store = LabelStore_Store_Create(store_name);

  hashcred_id = LabelStore_Nexus_Label(store, 1, "hashcred", NULL, NULL);
  if (!FSID_isValid(hashcred_id)) { printf("error building hashcred\n"); exit(1); }
  hashcred = malloc(4096);
  cred_len = LabelStore_Label_Externalize(hashcred_id, (char *)hashcred, 4096, NULL);
  if(cred_len > 4096) { printf("formula too long!\n"); exit(-1); }

  g_wrap_stream_port_num = atoi(argv[1]);
  printf("Connecting to %d\n", g_wrap_stream_port_num);
  WrapStream_clientInit();
  printf("Going functional\n");

  struct VarLen desc;
  desc.data = hashcred;
  desc.len = cred_len;
  if(WrapStream_Make_Functional(desc) != 0) {
    printf("Could not go to functional mode\n");
    return -1;
  }
  printf("back from functional\n");
  int pos = 0;

  struct Header header;
  struct VarLen vlen;
  vlen.data = &header;
  vlen.len = sizeof(header);
  printf("Receiving\n");
  int err;
  if((err = WrapStream_Recv(vlen)) != vlen.len) {
    printf("error reading header (%d,%d)\n", err, vlen.len);
    exit(-1);
  }
  int tot_size = header.count * sizeof(double);
  double *data = malloc(tot_size);

  while(pos < tot_size) {
    struct VarLen vlen;
    vlen.data = (char *)data + pos;
    vlen.len = MIN(tot_size - pos, TRANSFERLEN);
    int result = WrapStream_Recv(vlen);
    if(result < 0) {
      printf("Error receiving from wrapstream\n");
      exit(-1);
    }
    pos += result;
  }

  double response = 0;

  printf("Calculating, count = %d\n", header.count);
  response = calculate_taxes(data, header.count);

  header.count = 1;
  vlen.data = &header;
  vlen.len = sizeof(header);
  WrapStream_Send(vlen);

  vlen.data = &response;
  vlen.len = sizeof(response);
  printf("Sending response %lf\n", response);
  WrapStream_Send(vlen);
  printf("Calling done\n");
  WrapStream_Done();
  return 0;
}
