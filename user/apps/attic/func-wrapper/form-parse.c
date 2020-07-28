#include <sys/time.h>
#include <stdio.h>
#include <nexus/formula.h>
#include <nexus/util.h>
#include <nexus/timing.h>

// form-parse is a dumping ground for testing Form * parsing code

extern struct Timing *verify_timing;

double doubleTime(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec * 1e-6;
}

int main(int argc, char **argv) {
  verify_timing = timing_new_anon(10);
  int label_len;
  unsigned char *label_buf = read_file("/nfs/cpu-job.labels", &label_len);
  SignedFormula *hash = (SignedFormula *) label_buf;
  SignedFormula *sched_label = (SignedFormula *)
    ((char *)label_buf + der_msglen(label_buf));
  Form *this_nsk = NULL;
  Form *job_ipd = NULL;
  Form *thread_info = NULL;

#if 0
  if(form_scan(form_from_der(signedform_get_formula(sched_label)),
	       "%{term} says SchedState(%{term}) = %{term}",
	       &this_nsk, &job_ipd, &thread_info) != 0) {
    printf("Couldn't parse boot hash label\n");
    exit(-1);
  }
  printf("Thread info: %s\n", form_to_pretty(thread_info, 80));

  // Count # of threads with interval reservations
  Form *curr;
  for(curr = thread_info->left; curr->tag != F_LIST_NONE; curr = curr->right) {
    int thread_num;
    int numerator;
    if(form_scan(curr->left, "SchedStateInfo(%{int}, \"Interval\",%{int})",
		 &thread_num, &numerator) == 0) {
      printf("Got interval thread %d with numerator %d\n", thread_num, numerator);
    } else if(form_scan(curr->left, "SchedStateInfo(%{int}, \"RoundRobin\")",
			&thread_num) == 0) {
      // Round Robin, do nothing
      printf("Got RR thread %d\n", thread_num);
    } else {
      printf("Unknown sched state!\n");
    }
  }
  return 0;
#else
  // Do a lot of signature verification
  int outer;
  int tot_count = 0;
  for(outer=0; outer < 2; outer++) {
    int i;
    double start_time = doubleTime();
    int count = 10000;
    for(i=0; i < count; i++) {
      if(signedform_verify(hash) != 0) {
	printf("Verification failed\n");
	exit(-1);
      }
      tot_count++;
    }
    double end_time = doubleTime();
    printf("Count = %d, total = %lf, avg = %lf\n", count, end_time - start_time, 
	   (end_time - start_time) / count);
  }
  __u64 data[20];
  int i;
  int num_intervals = timing_getData(verify_timing, data);
  assert(num_intervals <= 20);
  for(i=0; i < num_intervals; i++) {
    printf("[%d]: %lld (%lf)\n", i, data[i], data[i] / (double)tot_count);
  }
  return 0;
#endif
}
