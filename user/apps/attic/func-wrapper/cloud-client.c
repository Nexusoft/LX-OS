#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <nexus/util.h>
#include "ssl.h"
#include "cloud.h"

int main(int argc, char **argv) {
  if(argc < 5) {
    printf("Usage: tax-client <server ip> <server port> <executable> <args>\n");
    exit(-1);
  }

  uint32_t server_addr = ntohl(inet_addr(argv[1]));
  short server_port = atoi(argv[2]);
  char *exec_fname = argv[3];
  char *exec_args = argv[4];
  int exec_len;

  char full_exec_fname[128];
  sprintf(full_exec_fname, "/nfs/%s", exec_fname);

  unsigned char *exec_file = read_file(full_exec_fname, &exec_len);
  if(exec_file == NULL) {
    printf("Could not open executable %s\n", exec_fname);
    exit(-1);
  }

  SSL *data_ssl = ssl_connect(server_addr, server_port);
  
  if(verify_ssl_labels(data_ssl) != 0) {
    printf("Could not verify labels on ssl connection!\n");
  }
  // Check the server hash

  {
    char hash_val[20];
    Form *nsk_ign;
    Form *launcher_ipd_ign;
    if(parse_boothash(hashcred, &nsk_ign, &launcher_ipd_ign, hash_val) != 0) {
      printf("Error: could not parse wrapper hash\n");
      return -1;
    }
    if(auth_data_hash_check(hash_val, "cloud-launcher")) {
      printf("bad hash\n");
      printf("%s\n", form_to_pretty(form_from_der(signedform_get_formula(hashcred)), 1000));
      return -1;
    }
  }
  printf("Verified cloud server, sending program\n");
  struct CloudStartHeader hdr;
  hdr.exec_len = exec_len;
  strcpy(hdr.exec_name, exec_fname);
  hdr.arg_len = strlen(exec_args) + 1;
  strcpy(hdr.arg, exec_args);

  ssl_send_all(data_ssl, &hdr, sizeof(hdr));
  ssl_send_all(data_ssl, exec_file, exec_len);

#define PING() printf("(%d)\n", __LINE__)
  printf("Verifying scheduling attestations\n");
  // Receive schedule attestation label
  SignedFormula *child_hashcred = recv_label(data_ssl);
PING();
  SignedFormula *child_schedlabel = recv_label(data_ssl);
PING();
  {
    Form *this_nsk = NULL;
    Form *job_ipd = NULL;
    char hash_val[20];
    
    if(parse_boothash(child_hashcred, &this_nsk, &job_ipd, hash_val) != 0) {
      printf("Couldn't parse boot hash label\n");
      exit(-1);
    }
    if(form_cmp(this_nsk, nsk) != 0) {
      printf("NSK mismatch!\n");
      exit(-1);
    }
    if(auth_data_hash_check(hash_val, exec_fname) != 0) {
      printf("Hash did not match executable\n");
      exit(-1);
    }
    Form *thread_info = NULL;
    if(form_scan(form_from_der(signedform_get_formula(child_schedlabel)),
	      "%{term} says SchedState(%{term}) = %{term}",
	      &this_nsk, &job_ipd, &thread_info) != 0) {
      printf("Couldn't parse boot hash label\n");
      exit(-1);
    }

    if(form_scan(form_from_der(signedform_get_formula(child_schedlabel)),
		 "%{term} says SchedState(%{term}) = %{term}",
		 &this_nsk, &job_ipd, &thread_info) != 0) {
      printf("Couldn't parse boot hash label\n");
      exit(-1);
    }
    printf("Thread info: %s\n", form_to_pretty(thread_info, 80));

    // Count # of threads with interval reservations
    Form *curr;
    int found_numerator = -1;
    for(curr = thread_info->left; curr->tag != F_LIST_NONE; curr = curr->right) {
      int thread_num;
      int numerator;
      if(form_scan(curr->left, "SchedStateInfo(%{int}, \"Interval\",%{int})",
		   &thread_num, &numerator) == 0) {
	printf("Got interval thread %d with numerator %d\n", thread_num, numerator);
	found_numerator = numerator;
	break;
      } else if(form_scan(curr->left, "SchedStateInfo(%{int}, \"RoundRobin\")",
			  &thread_num) == 0) {
	// Round Robin, do nothing
	printf("Got RR thread %d\n", thread_num);
      } else {
	printf("Unknown sched state!\n");
      }
    }
    if(found_numerator != 100) {
      printf("Interval scheduler: wrong parameters!\n");
      exit(-1);
    }
    printf("Scheduler labels verified\n");
  }
    // program results are output to NFS
  return 0;
}
