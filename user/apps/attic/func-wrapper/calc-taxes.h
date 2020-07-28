#ifndef _CALC_TAXES_H_
#define _CALC_TAXES_H_

// Packet format:
// int length; // # of ints
// double vals[length];

struct Header {
  int count;
};

#define SUM_VECTOR_LEN (16)

#define SUM_COEFFICIENTS \
  .5, .75, .25, 1,	 \
    .5, .75, .25, 1,	 \
    .5, .75, .25, 1,	 \
    .5, .75, .25, 1,

static inline 
double calculate_taxes(double *data, int len) {
  int i;
  double response = 0;
  extern double *sum_vector;
  for(i=0; i < len; i++) {
    response += sum_vector[i % SUM_VECTOR_LEN] * data[i];
  }
  return response;
}

#endif // _CALC_TAXES_H_
