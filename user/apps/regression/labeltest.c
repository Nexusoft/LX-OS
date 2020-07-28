#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <nexus/LabelStore.interface.h>
#include <nexus/der.h>
#include <nexus/guard.h>
#include <nexus/namespace.h>
#include <nexus/debug.h>
#include <assert.h>

#define CHECK(c) { \
  if (!(c)) { \
    printf("ls_enum_test failed: %s line %d\n", __FILE__, __LINE__); \
    exit(1); \
  } \
}

int main(int argc, char **argv){
  char *store_name1 = "Test_Store";
  char *store_name2 = "Dest_Store";
  char *formula1 = "bool:IAmTheGreatest";
  char *formula2 = "bool:IAmTheGreatest imp (str:WhoIs(\"TheGreatest\") = \"Me\")";
  
  char *mylabel_path = NULL;
  char *mylabel = NULL;

  printf("Creating Label Store 1 (%s)... ", store_name1);
  FSID store1 = LabelStore_Store_Create(store_name1);
  CHECK(FSID_isValid(store1));
  printf("done\n");

  printf("Creating a statement (%s)... ", formula1);
  Form *f = term_from_pretty(formula1);
  CHECK(f);
  printf("done\n");

  printf("Serializing it ... ");
  Formula *der = form_to_der(f);
  form_free(f);
  CHECK(der);
  printf("done: %d bytes\n", der_msglen(der->body));

  printf("Adding it to labelstore... ");
  FSID label1 = LabelStore_Label_Create(store1, "label1", der, NULL);
  CHECK(FSID_isValid(label1));
  printf("done\n");

  int i;
  _Grounds pg0;
  for (i = 0; i < 4; i++) {
    _Policy *policy = NULL;
    _Grounds *pg = NULL;
    if (i == 1) {
      printf("Setting read policy goal 'false' (allow no one to access)\n");
      Form *f = form_from_pretty("false");
      assert(f);
      policy = (_Policy *)form_to_der(f);
      assert(policy);
    } else if (i == 2) {
      printf("Setting read policy goal to 'true' (allow anyone access)\n");
      Form *f = form_from_pretty("true");
      assert(f);
      policy = (_Policy *)form_to_der(f);
    } else if (i == 3) {
      printf("Setting grounds to be 'true'\n");
      pg = &pg0;
      pg->hints = "true;";
      pg->argc = 0;
      pg->numleaves = 0;
    }
    
    if (policy) {
      Form *f = form_from_der(&policy->gf);
      assert(f);
      char *s = form_to_pretty(f, 0);
      assert(s);
      printf("  policy goal = %s\n", s);
      free(s);
      form_free(f);
      if (LabelStore_Store_Set_Policy(store1, OP_LS_READ, policy, NULL) != 0) {
	CHECK(0);
      }
    }

    printf("Reading it back out... ");
    char buf[4096];
    int len;
    len = LabelStore_Label_Read(label1, buf, sizeof(buf), pg);
    if (len <= 0) { printf("error (%d)\n", len); continue; }
    printf("done: got %d bytes\n", len);

    printf("Unserializing it... ");
    f = form_from_der((Formula *)buf);
    CHECK(f);
    printf("done\n");

    char *s = form_to_pretty(f, 0);
    printf("got: %s\n", s);
    free(s);
    free(f);
  }

  char buf[4096];
  int len;
  char *s;

  // create another label store
  printf("Creating Label Store 2 (%s)... ", store_name2);
  FSID store2 = LabelStore_Store_Create(store_name2);
  CHECK(FSID_isValid(store2));
  printf("done\n");

  // ask nexus to label us
  printf("Asking for a label from nexus...\n");
  FSID label3 = LabelStore_Nexus_Label(store2, 1, "myhash", NULL, NULL);
  CHECK(FSID_isValid(label3));

  printf("Reading it back out... ");
  len = LabelStore_Label_Read(label3, buf, sizeof(buf), NULL);
  CHECK(len > 0);
  printf("done: got %d bytes\n", len);

  printf("Unserializing it... ");
  Form *nlabel = form_from_der((Formula *)buf);
  CHECK(nlabel);
  s = form_to_pretty(nlabel, 0);
  printf("got: %s\n", s);
  free(s);
  
  // get the name of some other ipd
  int target_ipd_id = 10;
  printf("Getting name for ipd %d...\n", target_ipd_id);
  len = LabelStore_Get_IPD_Name(target_ipd_id, buf, sizeof(buf), NULL);
  printf("done: got %d bytes\n", len);
  if (len <= 0) { printf("error\n"); exit(1); }
  Form *target = form_from_der((Formula *)buf);
  if (!target) { printf("error\n"); exit(1); }
  s = form_to_pretty(target, 0);
  printf("got: %s\n", s);
  free(s);

  // make a new statement about that ipd
  printf("Making a new statement...\n");
  Form *stmt = form_fmt("Disposition(%{term}) = \"Pleasant\"", target);
  form_printf("got: %s\n", form_s(stmt));

  printf("Serializing it ... ");
  der = form_to_der(stmt);
  CHECK(der);
  if (!der) { printf("error\n"); exit(1); }
  printf("done: %d bytes\n", der_msglen(der->body));
  form_free(stmt);

  printf("Adding it to labelstore 2... ");
  FSID label2 = LabelStore_Label_Create(store2, "label2", der, NULL);
  CHECK(FSID_isValid(label2));
  printf("done\n");

  printf("success\n");
  return 0;
}
