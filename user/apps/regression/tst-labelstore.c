#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <nexus/LabelStore.interface.h>

double doubleTime(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec * 1e-6;
}

int main(int argc, char **argv) {
  int test_mode;
  int count;
  if(argc < 3) {
    printf("Usage: tst-labelstore <testmode> <count>\n");
    exit(-1);
  }
  test_mode = atoi(argv[1]);
  count = atoi(argv[2]);
  FSID store = LabelStore_Store_Create("store");
  int i, outer;
#define NUM_OUTER (10)  
  double data[NUM_OUTER];
  FILE *ofstream;
  char fname[128];
  sprintf(fname, "/nfs/labelstore-%d.dat", test_mode);
  ofstream = fopen(fname, "w");
  for(outer = 0; outer < NUM_OUTER; outer++) {
    double start_time;
    switch(test_mode) {
    case 0: { // label generation
      printf("Generating labels\n");
      start_time = doubleTime();
      for(i=0; i < count; i++) {
	char labelname[64];
	sprintf(labelname, "label-%d", i);
	FSID label = LabelStore_Nexus_Label(store, LABELTYPE_BOOTHASH, labelname, NULL, NULL);
      }
      break;
    }
    case 1: { // Externalize label
      printf("Externalizing labels\n");
#define MAX_FORMULA_LEN (16384)
      FSID label = LabelStore_Nexus_Label(store, LABELTYPE_BOOTHASH, "label", NULL, NULL);
      char *data = malloc(MAX_FORMULA_LEN);
      start_time = doubleTime();
      for(i=0; i < count; i++) {
	int cred_len = LabelStore_Label_Externalize(label, (char *)data, 4096, NULL);
	assert(cred_len > 0);
      }
      break;
    }
    case 2: {
      printf("Internalizing (i.e. verifying) labels\n");
      FSID label = LabelStore_Nexus_Label(store, LABELTYPE_BOOTHASH, "label", NULL, NULL);
      char *data = malloc(MAX_FORMULA_LEN);
      int cred_len = LabelStore_Label_Externalize(label, (char *)data, 4096, NULL);
      start_time = doubleTime();
      assert(cred_len > 0);
      for(i=0; i < count; i++) {
	SignedFormula *f = (SignedFormula *)data;
	if(signedform_verify(f) != 0) {
	  printf("verification failed?\n");
	  exit(-1);
	}
      }
      break;
    }
    default:
      printf("Unknown mode %d!\n", test_mode);
      exit(-1);
    }
    double end_time = doubleTime();
    struct Data {
      int count;
      double interval;
    } data;
    data.count = count;
    data.interval = end_time - start_time;
    fwrite(&data, sizeof(data), 1, ofstream);
    printf("Wrote %d\n", outer);
  }
  fclose(ofstream);
  exit(0);
}
