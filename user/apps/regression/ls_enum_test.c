#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <nexus/LabelStore.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/debug.h>

#define CHECK(c) { \
  if (!(c)) { \
    printf("ls_enum_test failed: %s line %d\n", __FILE__, __LINE__); \
    exit(1); \
  } \
}

int main(int argc, char **argv){
  /* set up label store and put hash in there */
  FSID store = LabelStore_Store_Create("store");
  CHECK(FSID_isValid(store));

  FSID label1 = LabelStore_Nexus_Label(store, 1, "label1", NULL, NULL);
  CHECK(FSID_isValid(label1));

  FSID label2 = LabelStore_Nexus_Label(store, 1, "label2", NULL, NULL);
  CHECK(FSID_isValid(label2));

  FSID label3 = LabelStore_Nexus_Label(store, 1, "label3", NULL, NULL);
  CHECK(FSID_isValid(label3));

  FSID label4 = LabelStore_Nexus_Label(store, LABELTYPE_SCHEDULER, "label4", NULL, NULL);
  CHECK(FSID_isValid(label4));

  char lsname[200];
  sprintf(lsname, "/ipds/%d/labels/store/", IPC_GetMyIPD_ID());
  labelstore_enumerate_print(lsname);

  unsigned char myhash[4096];
  int len = LabelStore_Label_Read(label1, myhash, 4096, NULL); 
  CHECK(len > 0);

  /* get my hash */
  Form *hashform = form_from_der((Formula *)myhash);
  printf("Tag = %d (%d)\n", hashform->tag, F_PRED_EQ);
  printf("Left.Tag = %d (%d)\n", hashform->left->tag, F_TERM_DER);
  printf("Right.Tag = %d (%d)\n", hashform->right->tag, F_TERM_BYTES);
  CHECK(hashform->tag == F_STMT_SAYS);
  CHECK(hashform->right->tag == F_PRED_EQ);
  CHECK(hashform->right->right->tag == F_TERM_BYTES);
  CHECK(hashform->right->right->len == 20);

#define PING() printf("<<%d>>", __LINE__)
  unsigned char longname[4096];
PING();
  int longnamelen = LabelStore_Get_IPD_Name(IPC_GetMyIPD_ID(), longname, 4096, NULL);
PING();

// Form *stmt = form_fmt("%{term/der} says BootHash(%{term/der}) = %{term}", form_to_der(hashform->left), longname, hashform->right->right);
 Form *stmt = form_fmt("%{term} says BootHash(%{term}) = %{term}", hashform->left, form_from_der((Formula *)longname), hashform->right->right);
 printf("stmt= %p\n", stmt);
PING();
 printf("%s\n", form_to_pretty(stmt, 80));

  Formula *tomatch = form_to_der(stmt);
PING();

  if(!labelstore_enumerate_match(lsname, tomatch)){
    printf("NO MATCH: test failed\n");
    printf("failure");
    exit(1);
  }
PING();

  printf("MATCH SUCCESSFUL!\n");
PING();

  form_free(hashform);
PING();
  form_free(stmt);
PING();
  free(tomatch);

  printf("success");

  return 0;
}
