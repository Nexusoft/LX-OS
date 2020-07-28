#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <unistd.h>
#include <nexus/formula.h>
#include <nexus/util.h>

#include "calc-taxes.h"
#include "ssl.h"

#define DATA_LEN (1000)
#define USE_TCP (0)

static SSL *data_ssl;
int data_ssl_sock = -1;
int dbg = 1;

double _sum_vector[SUM_VECTOR_LEN] = {
  SUM_COEFFICIENTS
};

double *sum_vector = &_sum_vector[0];

static int send_all(int fd, const void *data, int len) {
  const char *databuf = data;
  int totalwrite = 0, numwrite = 0;

  if(dbg)printf("writing...");
  while(totalwrite < len){
    if(USE_TCP) {
      numwrite = write(fd, databuf + totalwrite, len - totalwrite);
    } else {
      assert(data_ssl_sock == fd);
      numwrite = SSL_write(data_ssl, databuf + totalwrite, len - totalwrite);
    }
    if(numwrite <= 0){
      printf("couldn't get data from file; got %d so far\n", totalwrite);
      return -1;
    }
    totalwrite += numwrite;
  }
  if(dbg)printf("done writing\n");
  assert(totalwrite == len);
  return totalwrite;
}

static int recv_all(int fd, void *data, int len) {
  char *databuf = data;
  int totalread = 0, numread = 0;

  if(dbg)printf("reading...");
  while(totalread < len){
    if(USE_TCP) {
      numread = read(fd, databuf + totalread, len - totalread);
    } else {
      assert(data_ssl_sock == fd);
      numread = SSL_read(data_ssl, databuf + totalread, len - totalread);
    }
    if(numread <= 0){
      printf("couldn't get data from file; got %d so far\n", totalread);
      return -1;
    }
    totalread += numread;
  }
  if(dbg)printf("done reading\n");
  assert(totalread == len);
  return totalread;
}

static int verify_labels(int sock) {
  SignedFormula *nsk_label = recv_label(data_ssl);
  SignedFormula *sslkey_binding = recv_label(data_ssl);
  SignedFormula *hashcred = recv_label(data_ssl);
  SignedFormula *child_label = recv_label(data_ssl);
  if( !(nsk_label != NULL && sslkey_binding != NULL && hashcred != NULL &&
	child_label != NULL) ) {
    printf("Label signature verification failed\n");
    exit(-1);
  }

  // General: Verify that all NSK keys are identical
  // 1: Veify that signer CA key and PCRs are valid
#define CHECK_NSK()					\
    if(form_cmp(this_nsk, nsk) != 0) {			\
      printf("label did not match nsk\n");		\
      printf("%s\n", form_to_pretty(this_nsk, 1000));	\
      printf("%s\n", form_to_pretty(nsk, 1000));	\
      return -1;					\
    }

  Form *nexusca;
  Form *nsk;
  Form *pcrs;
  Form *wrapper_ipd_prin;
  Form *tax_engine_ipd_prin;

  printf("Verifying NSK key\n");
  form_scan(form_from_der(signedform_get_formula(nsk_label)),
	    "der(%{term}) says pcrs(der(%{term})) = %{term}",
	    &nexusca, &nsk, &pcrs);
  if(form_cmp(nexusca, auth_data.nexusca) != 0) {
    printf("CA mismatch\n");
    return -1;
  }
  if(form_cmp(pcrs, auth_data.pcrs) != 0) {
    printf("PCR mismatch\n");
    return -1;
  }

  // 2: SSL connection == SSL binding key
  printf("Verifying ssl key\n");
  {
    Form *this_nsk = NULL;
    Form *ipd_prin0 = NULL, *ipd_prin1 = NULL;
    Form *stmt = NULL;
    Form *ssl_key = NULL;
    if(form_scan(form_from_der(signedform_get_formula(sslkey_binding)),
		 "der(%{term}) says %{Stmt}",
		 &this_nsk, &stmt) != 0) {
      printf("could not parse certificate label\n");
      return -1;
    }
    if(form_scan(stmt, "%{term} says %{term} speaksfor %{term}", 
		 &ipd_prin0, &ssl_key, &ipd_prin1) != 0) {
      printf("could not parse certificate label\n");
      return -1;
    }
    wrapper_ipd_prin = ipd_prin0;

    CHECK_NSK();
    if(form_cmp(ipd_prin0, ipd_prin1) != 0) {
      printf("malformed SSL delegation\n");
      return -1;
    }
    assert(!USE_TCP);
    X509 *peer_cert = SSL_get_peer_certificate(data_ssl);
    unsigned char *key = (unsigned char *)der_key_from_cert(peer_cert);
    Form *computed_ssl_key = term_fmt("der(%{bytes})", key, der_msglen(key));
    free(key);
    if(form_cmp(ssl_key, computed_ssl_key) != 0) {
      printf("ssl key mismatch\n");
      printf("%s\n", form_to_pretty(ssl_key, 1000));
      printf("%s\n", form_to_pretty(computed_ssl_key, 1000));
      return -1;
    }
    form_free(computed_ssl_key);
  }
  // 3: Verify boothash #1 = SSL endpoint, and boothash #1 = wrapper
  {
    printf("Verifying that boothash#1 corresponds to SSL endpoint\n");
    Form *this_nsk = NULL;
    Form *this_wrapper_ipd = NULL;
    char hash_val[20];
    if(parse_boothash(hashcred, &this_nsk, &this_wrapper_ipd, hash_val) != 0) {
      printf("Error: could not parse wrapper hash\n");
      return -1;
    }
    if(form_cmp(this_nsk, nsk) != 0) {
      printf("Error: nsk mismatch\n");
      return -1;
    }
    if(form_cmp(this_wrapper_ipd, wrapper_ipd_prin) != 0) {
      printf("Error: ipd mismatch\n");
      return -1;
    }
    if(auth_data_hash_check(hash_val, "exec-func")) {
      printf("bad hash\n");
      printf("%s\n", form_to_pretty(form_from_der(signedform_get_formula(hashcred)), 1000));
      return -1;
    }
  }
  // 4: Verify  tax engine hash
  {
    printf("Verifying that boothash#2 corresponds to tax engine\n");
    Form *this_nsk = NULL;
    char hash_val[20];
    if(parse_boothash(child_label, &this_nsk, &tax_engine_ipd_prin, hash_val) != 0) {
      printf("Error: could not parse wrapper hash\n");
      return -1;
    }
    if(form_cmp(this_nsk, nsk) != 0) {
      printf("Error: nsk mismatch\n");
      return -1;
    }
    if(auth_data_hash_check(hash_val, "calc-taxes")) {
      printf("bad hash\n");
      return -1;
    }
  }
  printf("Passed all checks\n");
  return 0;
}

int main(int argc, char **argv) {
  if(argc < 3) {
    printf("Usage: tax-client <server ip> <server port>\n");
    exit(-1);
  }

  load_auth_data();

  int server_addr = ntohl(inet_addr(argv[1]));
  short server_port = atoi(argv[2]);
  int err;
  struct sockaddr_in addr, dest;
  int sock = socket(PF_INET, SOCK_STREAM, 0);
  int i;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = 0; // any port
  err = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
  assert(err == 0);
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = htonl(server_addr);
  dest.sin_port = htons(server_port);

  err = connect(sock, (struct sockaddr *)&dest, sizeof(dest));
  if(err != 0) {
    printf("Could not connect to server!\n");
    exit(-1);
  }
  if(!USE_TCP) {
    ssl_init();
    data_ssl_sock = sock;
    data_ssl = SSL_new(client_ctx);
    SSL_set_fd(data_ssl, sock);
    SSL_connect(data_ssl);
  }
  printf("Connected\n");

  printf("Waiting for labels\n");
  if(verify_labels(sock) != 0) {
    printf("Refusing to send data to server\n");
    exit(-1);
  }

  printf("Sending data\n");

  struct Header header;
  header.count = DATA_LEN;
  double data[DATA_LEN];
  for(i=0; i < DATA_LEN; i++) {
    data[i] = (1000.0 * rand()) / (RAND_MAX+1.0);
  }
  send_all(sock, &header, sizeof(header));
  send_all(sock, data, sizeof(data));

  printf("Waiting for data\n");
  recv_all(sock, &header, sizeof(header));
  printf("header.count = %d\n", header.count);
  assert(header.count == 1);
  double result;
  recv_all(sock, &result, sizeof(result));
  printf("Got result %lf\n", result);
  double check_val = calculate_taxes(data, DATA_LEN);
  if(check_val == result) {
    printf("Answer matched local analysis\n");
    exit(0);
  } else {
    printf("Answer did not match local analysis\n");
    exit(-1);
  }
}
