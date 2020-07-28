#include <nexus/Thread.interface.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <nexus/LabelStore.interface.h>

struct ThreadInfo {
  int sched_policy;
  int interval;
  pthread_t tid;
  int counter;
};

typedef struct ThreadInfo ThreadInfo;

#define SLEEP_LEN (10)

static void *full_cpu(void *ctx) {
  ThreadInfo *my_info = (ThreadInfo *)ctx;
  if(my_info->sched_policy == SCHEDTYPE_INTERVAL) {
    struct SchedTypeInfo_Interval info;
    info.numerator = my_info->interval;
    int err = Thread_SetSchedPolicy(my_info->sched_policy, &info);
    assert(err == 0);
  }
  while(1) {
    my_info->counter++;
  }
}

int main(int argc, char **argv) {
  if(argc < 2) {
    printf("Usage: tst-sched <# RR threads>\n");
    exit(-1);
  }
  int count;
  count = atoi(argv[1]);
  assert(count >= 0);
  int reservations[3] = { 100, 200, 400 };
  int i;
  ThreadInfo *thread_info = calloc(count + 3, sizeof(ThreadInfo));
  printf("Forking %d\n", count);
  for(i=0; i < count; i++) {
    thread_info[i].sched_policy = SCHEDTYPE_ROUNDROBIN;
    pthread_create(&thread_info[i].tid, NULL, full_cpu, &thread_info[i]);
    printf("F");
  }
  for(i=0; i < 3; i++) {
    int index = count + i;
    thread_info[index].sched_policy = SCHEDTYPE_INTERVAL;
    thread_info[index].interval = reservations[i];
    pthread_create(&thread_info[index].tid, NULL, full_cpu, &thread_info[index]);
    printf("I");
  }
  printf("\n");

  printf("sleeping\n");
  sleep(SLEEP_LEN);
  FILE *fp = fopen("/nfs/tst-sched.dat", "w");
  fprintf(fp, "num threads =  %d, slept %d\n", count, SLEEP_LEN);
  for(i=0; i < count + 3; i++) {
    printf("[%d]: %d\n", i, thread_info[i].counter);
    fprintf(fp, "[%d]: %d\n", i, thread_info[i].counter);
  }
  fsync(fp);
  fclose(fp);

  printf("emitting label\n");
  FSID store = LabelStore_Store_Create("store");
  FSID label = LabelStore_Nexus_Label(store, LABELTYPE_SCHEDULER, "schedinfo", NULL, NULL);
#define MAX_FORMULA_LEN (16384)
  char *data = malloc(MAX_FORMULA_LEN);
  int len = LabelStore_Label_Read(label, data, MAX_FORMULA_LEN, NULL); 
  assert(len > 0 && len < MAX_FORMULA_LEN);

  printf("writing label to nfs\n");
  FILE *form_fp = fopen("/nfs/formula.der", "w");
  fwrite(data, 1, len, form_fp);
  fsync(form_fp);
  fclose(form_fp);

  printf("converting from der (len = %d)\n", len);
  Form *f = form_from_der((Formula *)data);
  printf("printing label\n");
  printf("label is %s\n", form_to_pretty(f, 80));
   
  exit(0);
}
