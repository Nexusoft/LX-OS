#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

#include <asm/types.h>
#include <nexus/timing.h>
#include <nexus/Profile.interface.h>

#include <assert.h>
#include <nexus/debug.h>
#include <nexus/guard.h>
#include "../spamfree/SpamFreeAttestationService.interface.h"
#include "Keyboard_CounterRM.interface.h"

//#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_printf(...) 

int do_profile = 0; // collect stats
int skip_signature = 0; // skip signature generation
int require_signature = 0; // require signature generation
int export_labels = 0; // use signed, exported labels
int automated = 0; // skip user interaction
int num_times = 1; // auto-repeat count

//#define NUM_REPEATED_RUNS (10)
//#define NUM_REPEATED_RUNS (100)
#define NUM_REPEATED_RUNS (1)

//#define NO_SMTP

const char *email_config_fname = "/nfs/email-demo.cfg";
const char *from = "ashieh@cs.cornell.edu";
const char *from_addr = "ashieh@cs.cornell.edu";
const char *localdomain = "sbox2.cs.cornell.edu";

char server_addr[4] = { 128, 84, 227, 11}; // alan's smtp server
//const char server_addr[4] = { 128, 84, 154, 42}; // sysserve

char *fgets_chomp(char *data, int max_len, FILE *file) {
  char *rv = fgets(data, max_len, file);
  if(data[strlen(data) - 1] == '\n') {
    data[strlen(data) - 1] = '\0';
  }
  return rv;
}

char *sign_email(char *body);
void send_email(char *recipients[], int num_recipients, char *subject, char *body);

struct Stat { __u64 total, sign, send; };

int main(int argc, char **argv){
  global_debug_level = DEBUG_LEVEL_INFO;
  gdb_init_remote(0, 0);

  int ac = argc - 1;
  char **av = argv+1;
  while (ac > 0) {
    if (!strcmp(av[0], "-nosign")) {
      skip_signature = 1;
      printf("skipping signature\n");
    } else if (!strcmp(av[0], "-auto") && ac > 1) {
      num_times = atoi(av[1]);
      ac--; av++;
      automated = 1;
      printf("skipping user interaction, sending %d emails\n", num_times);
    } else if (!strcmp(av[0], "-profile")) {
      do_profile = 1;
      printf("profiling\n");
    } else if (!strcmp(av[0], "-exportlabels")) {
      export_labels = 1;
    } else if (!strcmp(av[0], "-sign")) {
      require_signature = 1;
    } else {
      printf("unrecognized option: %s\n", av[0]);
      return -1;
    }
    ac--; av++;
  }

  printf("using exported labels? %s\n", export_labels ? "yes" : "no" );

  int stats_size = sizeof(struct Stat) * num_times;
  struct Stat *stats = malloc(stats_size);
  memset(stats, 0, stats_size);

  int size;
  int i;

  int outer_index;
  if(do_profile) 
    Profile_Enable(1);

  for(outer_index = 0; outer_index < num_times; outer_index++) {
    __u64 start_time = rdtsc64();
    char **recipients;
    char *automated_recipients_default[] =
      //    { "ashieh@cs.cornell.edu", "egs@cs.cornell.edu", "djwill@cs.cornell.edu" };
      //{ "ashieh@cs.cornell.edu", "djwill@cs.cornell.edu", "ashieh@systems.cs.cornell.edu" };
      // { "ashieh@systems.cs.cornell.edu" };
    { "ashieh@athens.systems.cs.cornell.edu" };
    int num_recipients = 0;
    int num_auto_recipients = sizeof(automated_recipients_default) / sizeof(automated_recipients_default[0]);
    char **automated_recipients = automated_recipients_default;

    //{ "ashieh@cs.cornell.edu", "egs@cs.cornell.edu" };
    char *body;
    char *automated_body = "This message was automatically generated.";
    char *subject;
    char automated_subject[300];
    sprintf(automated_subject, "Test Message %d, options:", outer_index+1);
    int i;
    for (i = 1; i < argc; i++) {
      sprintf(automated_subject + strlen(automated_subject), " %s", argv[i]);
    }

    // Process configuration file
    int fd = open(email_config_fname, O_RDONLY);
    if (fd >= 0) {
      char name[100], val[100];
      char buf[2048];
      for (;;) {
	int i = 0;
	do {
	  int j = read(fd, buf+i, 1);
	  if (j <= 0) break;
	  //printf("read %c\n", buf[i]);
	  i += j;
	} while (buf[i-1] != '\n');
	if (i > 1) {
	  if (buf[i-1] == '\n') buf[i-1] = '\0';
	  else buf[i] = '\0';
	  if (sscanf(buf, "%s = %s", name, val) == 2) {
	    if (!strcmp(name, "server_addr")) {
	      unsigned int addr = inet_addr(val);
	      memcpy(server_addr, &addr, sizeof(addr));
	      printf("server_addr: %u.%u.%u.%u\n", server_addr[0] & 0xff, server_addr[1] & 0xff,
		  server_addr[2] & 0xff, server_addr[3] & 0xff);
	    } else if (!strcmp(name, "auto_rcpt")) {
	      automated_recipients = malloc(sizeof(char *) * 1);
	      automated_recipients[0] = strdup(val);
	      num_auto_recipients = 1;
	      printf("auto_rcpt: %s\n", val);
	    } else {
	      printf("config file: unknown option: %s\n", name);
	      exit(1);
	    }
	  } else {
	    printf("config file: bad line: %s\n", buf);
	    exit(1);
	  }
	} else if (i < 0) {
	  printf("config file: read error\n");
	  exit(1);
	  break;
	} else if (i == 0) {
	  printf("config file: done\n");
	  break;
	}
      }
      close(fd);
    } else {
      printf("config file %s missing: using defaults instead\n", email_config_fname);
    }

    if(automated) {
      recipients = automated_recipients;
      num_recipients = num_auto_recipients;
      body = automated_body;
      subject = automated_subject;
    } else {
#define LINE_LENGTH (1024)
      char line[LINE_LENGTH];
      char email_buffer[4096] = "", *tmp = email_buffer;
      printf("To (only one allowed) [%s]: ", automated_recipients[0]);
      fgets_chomp(line, LINE_LENGTH, stdin);
#if 1
      recipients = malloc(1 * sizeof(char*));
      recipients[0] = strdup(line);
      num_recipients = 1;
      if (strlen(line) == 0) 
	recipients[0] = strdup(automated_recipients[0]);
#else
      printf("Since the shift key doesn't work, I'm forcing recipients to the automated list\n");
      recipients = automated_recipients;
      num_recipients = 1;
#endif
      // printf("sending to %s\n", recipients[0]);
      printf("Subject [%s]: ", automated_subject);
      fgets_chomp(line, LINE_LENGTH, stdin);
      subject = strdup(line);
      if (strlen(subject) == 0)
	subject = strdup(automated_subject);
      printf("Body (end with . on its own line):\n");
      while(1) {
	fgets_chomp(line, LINE_LENGTH, stdin);
	if(strcmp(line, ".") == 0) {
	  *tmp++ = '\0';
	  break;
	}
	strcpy(tmp, line);
	tmp += strlen(tmp);
	*tmp++ = '\n';
      }
      body = strdup(email_buffer);
      // printf("subject = '%s' body = '%s', email_buffer = '%s'\n", subject, body, email_buffer);
    }

    printf("about to sign...\n");
    __u64 pre_sign_time = rdtsc64();
    char *sbody = (skip_signature ? NULL : sign_email(body));
    if (require_signature) {
      if (!sbody) {
	printf("could not get signature... failing\n");
	exit(1);
      } else {
	printf("could not get signature... sending unsigned email instead\n");
      }
    }
    if (!sbody) {
      skip_signature = 1;
      sbody = body;
    }

    printf("about to send...\n");

    __u64 pre_email_time = rdtsc64();
    send_email(recipients, num_recipients, subject, sbody);

    __u64 end_time = rdtsc64();

    stats[outer_index].total = end_time - start_time;
    stats[outer_index].sign = pre_email_time - pre_sign_time;
    stats[outer_index].send = end_time - pre_email_time;
  }

  if(do_profile) {
    Profile_Enable(0);
    writefile("email.output", stats, stats_size);
    Profile_Dump("email.profile");
  }

  // exit(0); // alan: this panics: email's commoncallctx gets freed, then
  // tcpmgr tries to write stuff to the old channel and dies in
  // P(commoncallctx->callee_sema)
  return 0;
}

enum SMTP_Class { SMTP_FULL, SMTP_INTERMEDIATE };

void wait_for_smtp_ok(int fd, enum SMTP_Class class) {
  char buf[4096];
  int pos = 0;
  char classchar;
  switch(class) {
    case SMTP_FULL:
      classchar = '2';
      break;
    case SMTP_INTERMEDIATE:
      classchar = '3';
      break;
    default:
      assert(0);
  }
  int j = 0;
  printf("recv: ");
  while(1) {
    int len = recv(fd, buf+pos, 4096 - pos, 0);
    if(len <= 0) continue;
    pos += len;
    while (j < pos) {
      char c = buf[j++];
      if (c >= ' ' && c <= '~')
	printf("%c", c);
      else
	printf("\\%d", (int)(c & 0xff));
    }
    // Scan what we've seen
    buf[pos] = 0;
    if(buf[0] == classchar) {
      int i;
      for(i=0; i < pos-1; i++) {
	if(buf[i] == '\r' && buf[i+1] == '\n') {
	  buf[i] = '\0';
	  // printf("got %s\n", buf);
	  goto done;
	}
      }
    }
  }
done:
  printf("recv: done\n");
  return;
}

#ifdef NO_SMTP
#define wait_for_smtp_ok(f,m) do { } while (0)
#define send(f,c,l,t) printf("%*s", l, c)
#endif

void send_smtp_command(int fd, char *cmd, int len, enum SMTP_Class messageclass) {
  char cmd_buf[8192];
  memcpy(cmd_buf, cmd, len);
  memcpy(cmd_buf + len, "\r\n", 2);
  send(fd, cmd_buf, len + 2, 0);
  wait_for_smtp_ok(fd, messageclass);
}


char *sign_email(char *body) {
  if (skip_signature) return NULL;

  char *buf = malloc(16*1024);
  struct VarLen email_body = {.data = body, .len = strlen(body)+1};
  struct VarLen signed_email = {.data = buf, .len = 16*1024};

  // get credentials from our wrapper
  // we can ask for signed, exported formulas, or for references to labels

  IPD_ID me = IPC_GetMyIPD_ID();
  Keyboard_CounterRM_SelectTarget(me);

  printf("about to get nonce\n");
  int nonce = SpamFreeAttestationService_GetNonce(0);
  if (nonce <= 0) {
    printf("get nonce failed (%d %d)\n", __ipcResultCode, nonce);
    return NULL;
  }
  printf("nonce = %d\n", nonce);

  printf("about to get num lines required\n");
  int numlines_required = SpamFreeAttestationService_GetNumLinesRequired(0);
  if (numlines_required < 0) {
    printf("get num lines required failed (%d %d)\n", __ipcResultCode, numlines_required);
    return NULL;
  }
  printf("numlines_required = %d\n", numlines_required);

  int sfas_id = SpamFreeAttestationService_GetName(0);
  if (sfas_id <= 0) {
    printf("get sfas name failed (%d %d)\n", __ipcResultCode, sfas_id);
    return NULL;
  }
  printf("sfas_id = %d\n", sfas_id);

  Form *ntstmt;
  Formula *ntstmtder;
  Formula *hashcredder;
  Cred *ntcredcred, *hashcredcred;

  unsigned char hashcred[4000], ntcred[4000];
  struct VarLen vl_hashcred = {
    .data = hashcred,
    .len = 4000,
  }, vl_ntcred = {
    .data = ntcred,
    .len = 4000,
  };

  int res = Keyboard_CounterRM_GetWrapperHashCredential(vl_hashcred, export_labels);
  if(__ipcResultCode != 0 || res < 0) {
    printf("failed GetWrapperHashCredential (%d %d)\n", __ipcResultCode, res);
    return NULL;
  }

  res = Keyboard_CounterRM_GetNumTypedCredential(nonce, vl_ntcred, export_labels);
  if(__ipcResultCode != 0 || res < 0) {
    printf("failed GetNumTypedCredential (%d %d)\n", __ipcResultCode, res);
    return NULL;
  }

  unsigned char namebuf[4096];

  if (export_labels) {
    writefile("hashcred.der", hashcred, der_msglen(hashcred));
    // debug: check credentials
    SignedFormula *sf = (SignedFormula *)hashcred;
    if (signedform_verify(sf) < 0) {
      printf("hashcred did not verify\n"); 
      return NULL;
    }

    writefile("ntcred.der", ntcred, der_msglen(ntcred));
    sf = (SignedFormula *)ntcred;
    if (signedform_verify(sf) < 0) {
      printf("ntcred did not verify\n"); 
      return NULL;
    }

    hashcredder = signedform_get_formula((SignedFormula *)hashcred);
    ntstmtder = signedform_get_formula((SignedFormula *)ntcred);

    ntcredcred = new_cred_signed((SignedFormula *)ntcred);
    hashcredcred = new_cred_signed((SignedFormula *)hashcred);
  } else {

    FSID label = *(FSID *)hashcred;
    hashcredcred = new_cred_label(label);
    int len = LabelStore_Label_Read(label, hashcred, 4000, NULL);
    if (len <= 0) return NULL;
    printf("read %d bytes for hashcred\n", len);

    label = *(FSID *)ntcred;
    ntcredcred = new_cred_label(label);
    len = LabelStore_Label_Read(label, ntcred, 4000, NULL);
    if (len <= 0) return NULL;
    printf("read %d bytes for ntcred\n", len);

    ntstmtder = (Formula *)ntcred;

    // modify hashcred by adding (sfas) nsk on it

    printf("Getting name for sfas ipd %d...\n", sfas_id);
    len = LabelStore_Get_IPD_Name(sfas_id, namebuf, sizeof(namebuf), NULL);
    printf("done: got %d bytes\n", len);
    if (len <= 0) { printf("error\n"); return NULL; }
    Form *sfas = form_from_der((Formula *)namebuf);
    if (!sfas) { printf("error\n"); return NULL; }
    char *sfas_namestr = form_to_pretty(sfas, 0);
    printf("sfas_name = %s\n", sfas_namestr);
    assert(sfas->tag == F_TERM_CSUB && sfas->left->tag == F_TERM_DER);

    hashcredder = form_to_der(form_fmt("%{term} says %{Stmt/der}", form_dup(sfas->left), hashcred));
  }

  char *pretty = form_to_pretty(form_from_der(hashcredder), 80);
  printf("hashcred = %s\n", pretty);
  free(pretty);

  ntstmt = form_from_der(ntstmtder);
  pretty = form_to_pretty(ntstmt, 80);
  printf("ntcred = %s\n", pretty);
  free(pretty);

  int my_id = IPC_GetMyIPD_ID();
  printf("Getting name for own ipd %d...\n", my_id);
  int len = LabelStore_Get_IPD_Name(my_id, namebuf, sizeof(namebuf), NULL);
  printf("done: got %d bytes\n", len);
  if (len <= 0) { printf("error\n"); return NULL; }
  Form *self = form_from_der((Formula *)namebuf);
  if (!self) { printf("error\n"); return NULL; }
  char *self_namestr = form_to_pretty(self, 0);
  printf("self_name = %s\n", self_namestr);

  assert(self->tag == F_TERM_CSUB);
  assert(self->left->tag == F_TERM_DER);
  Form *nsk = form_dup(self->left);

  printf("Getting name for sfas ipd %d...\n", sfas_id);
  len = LabelStore_Get_IPD_Name(sfas_id, namebuf, sizeof(namebuf), NULL);
  printf("done: got %d bytes\n", len);
  if (len <= 0) { printf("error\n"); return NULL; }
  Form *sfas = form_from_der((Formula *)namebuf);
  if (!sfas) { printf("error\n"); return NULL; }
  char *sfas_namestr = form_to_pretty(sfas, 0);
  printf("sfas_name = %s\n", sfas_namestr);

  assert(ntstmt->tag == F_STMT_SAYS);
  assert(ntstmt->right->tag == F_PRED_EQ);
  assert(ntstmt->right->right->tag == F_TERM_INT);
  int numlines = ntstmt->right->right->value;
  printf("numlinestyped = %d\n", numlines);

  // todo: proof language has changed -- this isn't going to work any more
  _Grounds *pg = malloc(sizeof(_Grounds));
  pg->hints = "leaf 0; leaf 1; leaf 4; replace_eq_some 5; leaf 2; leaf 3; andi; andi; andi;";
  pg->argc = 6;
  pg->args = malloc(pg->argc * sizeof(Formula *));
  pg->args[0] = form_to_der(form_fmt("%{term} says AttestToNonSpamness() = 1", self));
  pg->args[1] = ntstmtder;
  pg->args[2] = hashcredder;
  pg->args[3] = form_to_der(form_fmt("%{term} says IsFreshNonce(%{int}) = 1", sfas, nonce));
  pg->args[4] = form_to_der(form_fmt("%{term} says %{int} >= %{int}", ntstmt->left, numlines, numlines_required));
  Form *ntp = form_dup(ntstmt);
  ntp->right->right->value = numlines_required;
  ntp->right->tag = F_PRED_GE;
  pg->args[5] = form_to_der(ntp);
  pg->numleaves = 2;
  pg->leaves = malloc(pg->numleaves * sizeof(Cred *));
  pg->leaves[0] = ntcredcred;
  pg->leaves[1] = hashcredcred;

  struct VarLen upg;
  upg.data = grounds_serialize(pg, &upg.len);
  writefile("upg.bin", upg.data, upg.len);

  printf("calling attest... body is %d bytes, grounds is %d bytes\n",
      strlen(email_body.data), upg.len);
  if (SpamFreeAttestationService_AttestToNonSpamness(email_body, signed_email, upg) != 0) {
    printf("can't sign... \n");
    return NULL;
  }
  printf("back from attest... body is %d bytes now\n", strlen(signed_email.data));
  char c = buf[200];
  buf[200] = '\0';
  printf("msg (%d bytes):\n%s\n", strlen(buf), buf);
  buf[200] = c;

  return buf;
}

void send_email(char *recipients[], int num_recipients, char *subject, char *body) {
  int fd = socket(PF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  int err;

  // printf("got socket %d\n", fd);

  addr.sin_addr.s_addr = 0;
  addr.sin_port = 0;
  err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));

  struct sockaddr_in dest;
  // char server_addr[4] = { 128, 84, 98, 19};
  dest.sin_family = AF_INET;
  memcpy(&dest.sin_addr.s_addr, server_addr, 4);
  dest.sin_port = htons(25);

  printf("Connecting to e-mail server & sending message\n");
#ifndef NO_SMTP
  err = connect(fd, (struct sockaddr *)&dest, sizeof(dest));
  dbg_printf("Connected to SMTP server\n");
#else
  dbg_printf("Not connecting to SMTP server: output would have been like so...\n");
#endif

  // Start SMTP processing
  wait_for_smtp_ok(fd, SMTP_FULL);
  static char *cmdbuf;
  cmdbuf = malloc(100 + strlen(localdomain));
  sprintf(cmdbuf, "HELO %s", localdomain);
  send_smtp_command(fd, cmdbuf, strlen(cmdbuf), SMTP_FULL);
  free(cmdbuf);

  cmdbuf = malloc(100+ strlen(from_addr));
  sprintf(cmdbuf, "MAIL FROM: <%s>", from_addr);
  send_smtp_command(fd, cmdbuf, strlen(cmdbuf), SMTP_FULL);
  free(cmdbuf);

  int i;
  for(i=0; i < num_recipients; i++) {
    cmdbuf = malloc(100 + strlen(recipients[i]));
    sprintf(cmdbuf, "RCPT TO: <%s>", recipients[i]);
    send_smtp_command(fd, cmdbuf, strlen(cmdbuf), SMTP_FULL);
    free(cmdbuf);
  }

  cmdbuf = malloc(10);
  sprintf(cmdbuf, "DATA");
  send_smtp_command(fd, cmdbuf, strlen(cmdbuf), SMTP_INTERMEDIATE);
  free(cmdbuf);

  static char *tobuf;
  int tobuf_len = 0;

  for(i=0; i < num_recipients; i++) {
    tobuf_len += strlen(recipients[i]) + 5;
  }
  tobuf = malloc(tobuf_len);
  tobuf[0] = 0;
  for(i=0; i < num_recipients; i++) {
    sprintf(tobuf + strlen(tobuf), "%s%s", recipients[i],
	i != num_recipients - 1 ? ", " : "");
  }

  char *header_format = "From: %s\n"
    "User-Agent: Nexus\n"
    "To: %s\n"
    "Subject: %s\n";
  cmdbuf = malloc(strlen(from) + tobuf_len + strlen(header_format) + strlen(subject) + 20);
  sprintf(cmdbuf,
      header_format,
      from, tobuf, subject);
  send(fd, cmdbuf, strlen(cmdbuf), 0);
  free(tobuf);
  free(cmdbuf);

  send(fd, body, strlen(body), 0);

  char *EOM = "\r\n.";
  send_smtp_command(fd, EOM, strlen(EOM), SMTP_FULL);
  printf("Done: %s e-mail has been sent\n", skip_signature ? "unsigned" : "signed");
  close(fd);
}
