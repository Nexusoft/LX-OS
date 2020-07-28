#include <nexus/Thread.interface.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <nexus/LabelStore.interface.h>
#include "Cloud.interface.h"

struct ThreadInfo {
  int sched_policy;
  int interval;
  pthread_t tid;
  int counter;
};

typedef struct ThreadInfo ThreadInfo;

int g_cloud_port_num;

#define SLEEP_LEN (10)
int thread_start_count = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static void *full_cpu(void *ctx) {
  ThreadInfo *my_info = (ThreadInfo *)ctx;
  if(my_info->sched_policy == SCHEDTYPE_INTERVAL) {
    struct SchedTypeInfo_Interval info;
    info.numerator = my_info->interval;
    int err = Thread_SetSchedPolicy(my_info->sched_policy, &info);
    assert(err == 0);
  }
  pthread_mutex_lock(&mutex);
  thread_start_count++;
  pthread_mutex_unlock(&mutex);
  while(1) {
    my_info->counter++;
  }
}

int main(int argc, char **argv) {
  if(argc < 3) {
    printf("Usage: cpu-job <port #> <# RR threads>\n");
    exit(-1);
  }

  printf("Creating label store\n");
  FSID store = LabelStore_Store_Create("store");

  g_cloud_port_num = atoi(argv[1]);
  int thread_count;
  thread_count = atoi(argv[2]);
  assert(thread_count >= 0);

  Cloud_clientInit();

#define NUM_RESERVATIONS (1)
  int reservations[NUM_RESERVATIONS] = { 100 };
  int i;
  ThreadInfo *thread_info = calloc(thread_count + NUM_RESERVATIONS, sizeof(ThreadInfo));
  printf("Forking %d\n", thread_count);
  for(i=0; i < thread_count; i++) {
    thread_info[i].sched_policy = SCHEDTYPE_ROUNDROBIN;
    pthread_create(&thread_info[i].tid, NULL, full_cpu, &thread_info[i]);
    printf("F");
  }
  for(i=0; i < NUM_RESERVATIONS; i++) {
    int index = thread_count + i;
    thread_info[index].sched_policy = SCHEDTYPE_INTERVAL;
    thread_info[index].interval = reservations[i];
    pthread_create(&thread_info[index].tid, NULL, full_cpu, &thread_info[index]);
    printf("I");
  }
  printf("\n");

  // Wait for all threads to start
  while(1) {
    pthread_mutex_lock(&mutex);
    int curr_count = thread_start_count;
    pthread_mutex_unlock(&mutex);
    if( curr_count == thread_count + NUM_RESERVATIONS ) {
      break;
    }
  }

  // Send Hash
  // Send Sched info
  FSID boot_label = LabelStore_Nexus_Label(store, LABELTYPE_BOOTHASH, "boothash", NULL, NULL);
  FSID sched_label = LabelStore_Nexus_Label(store, LABELTYPE_SCHEDULER, "schedinfo", NULL, NULL);
  SignedFormula *hashcred = malloc(4096);
  int boot_len = 
    LabelStore_Label_Externalize(boot_label, (char *)hashcred, 4096, NULL);
  int sched_len = 
    LabelStore_Label_Externalize(sched_label, ((char *)hashcred) + boot_len, 4096 - boot_len, NULL);
  assert(boot_len < 4096 && sched_len < 4096 - boot_len);

  struct VarLen vlen;
  vlen.data = hashcred;
  vlen.len = boot_len + sched_len;
  printf("Calling cloud, port num is %d\n", g_cloud_port_num);
  Cloud_ProcessStarted(2, vlen);

  printf("sleeping\n");
  sleep(SLEEP_LEN);
  FILE *fp = fopen("/nfs/cpu-job.dat", "w");
  fprintf(fp, "num threads =  %d, slept %d\n", thread_count, SLEEP_LEN);
  for(i=0; i < thread_count + NUM_RESERVATIONS; i++) {
    printf("[%d]: %d\n", i, thread_info[i].counter);
    fprintf(fp, "[%d]: %d\n", i, thread_info[i].counter);
  }
  fsync(fileno(fp));
  fclose(fp);

  fp = fopen("/nfs/cpu-job.labels", "w");
  fwrite(vlen.data, vlen.len, 1, fp);
  fsync(fileno(fp));
  fclose(fp);

  exit(0);
}
