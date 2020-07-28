#ifndef _NQ_UTIL_H_
#define _NQ_UTIL_H_


#ifdef __cplusplus

#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <stdio.h>

extern "C" {
  unsigned int SuperFastHash (const char * data, int len);
};

typedef std::vector<unsigned char>::const_iterator CharVector_Iterator;

template <class T> 
static inline std::vector<T> 
  filter_vector(const std::vector<T> &input, bool (*pred)(const T &) ) {
  std::vector<T> result;
  size_t i;
  for(i=0; i < input.size(); i++) {
    if(pred(input[i])) {
      result.push_back(input[i]);
    }
  }
  return result;
}

// Marshall / unmarshall utility functions
template <class T>
static inline T *vector_as_ptr(std::vector<T> &v) {
  // STL standard requires vector to be contiguous
  return v.empty() ? NULL : &v[0];
}

// Marshall / unmarshall utility functions
template <class T>
static inline const T *vector_as_ptr(const std::vector<T> &v) {
  // STL standard requires vector to be contiguous
  return v.empty() ? NULL : &v[0];
}

template <class T>
static inline std::vector<T> *array_as_vector(const T data[], size_t len) {
  std::vector<T> *rv = new std::vector<T>(len);
  size_t i;
  for(i=0; i < len; i++) {
    (*rv)[i] = data[i];
  }
  return rv;
}

template <class T>
static inline void vector_set(std::vector<T> &v, const T data[], size_t len) {
  v.clear();
  v.reserve(len);
  size_t i;
  for(i=0; i < len; i++) {
    v[i] = data[i];
  }
}

static inline void vector_push(std::vector<unsigned char> &v, const unsigned char *as_char, size_t len) {
  size_t i;
  for(i=0; i < len; i++) {
    v.push_back(as_char[i]);
  }
}

template <class T>
static inline void vector_push(std::vector<unsigned char> &v, const T &val) {
  const unsigned char *as_char = (const unsigned char *)&val;
  vector_push(v, as_char, sizeof(val));
}

template <class T>
static inline std::string to_string(const T &v) {
  std::stringstream s;
  s << v;
  return s.str();
}

static inline std::string itos(int i)	// convert int to string
{
  return to_string(i);
}

static inline std::string utos(unsigned int i)	// convert int to string
{
  return to_string(i);
}

static inline std::string dtos(double d)
{
  return to_string(d);
}

template <class T> T max(const T &a, const T &b) {
  return (a > b)? a : b;
}

std::string get_line(CharVector_Iterator &curr, const CharVector_Iterator &end);

void write_int(std::ostream &os, int v);
int read_int(std::istream &is);
int read_int(CharVector_Iterator &curr, const CharVector_Iterator &end);

void split(const std::string& str, const std::string& delimiters, std::vector<std::string>& tokens);

void get_all_file_data(std::istream &is, std::vector<unsigned char> &output);

uint32_t resolve_ip(const std::string &str);
std::string gethostname(void);

std::string IP_Address_to_string(unsigned int addr);

class DataBuffer : public std::vector<unsigned char> {
 public:
  inline DataBuffer() {
    // nothing
  }
  inline DataBuffer(const unsigned char *data, int len) {
    vector_push(*this, data, len);
  }
};

extern "C" {
#endif // __cplusplus

void print_hex(unsigned char *c, int len);
void fprint_ip(FILE *fp, int i);
void print_ip(int i);

#define CONTAINER_OF(T,FIELD,VALUE) (T*)((char *)(VALUE)-(int)&((T*)0)->FIELD)
#define MIN(X,Y) ( ((X) < (Y)) ? (X) : (Y) )

#ifdef __cplusplus
}
#endif

#endif //  _NQ_UTIL_H_
