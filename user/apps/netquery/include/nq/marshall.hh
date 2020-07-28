#ifndef _MARSHALL_HH_
#define _MARSHALL_HH_

#include <nq/exceptions.hh>
#include <nq/transaction.hh>
#include <nq/util.hh>
#include <iostream>

// Standard definitions

template<class T> void file_marshall(const T &val, std::ostream &os) {
  std::vector<unsigned char> buf;
  tspace_marshall(val, buf);
  os.write( (char *)vector_as_ptr(buf), buf.size() );
}

// Do not define tspace_marshall_size() for any variable-length object!
template<class T> int tspace_marshall_size(void) {
  return T::tspace_marshall_size();
}

// "ignored" argument fix up overload disambiguation
template<class T> 
inline T *tspace_unmarshall(const T *ignored, Transaction &transaction, 
			    CharVector_Iterator &curr, 
			    const CharVector_Iterator &end) 
  throw(NQ_Schema_Exception) {
  return T::tspace_unmarshall(transaction, curr, end);
}

template<> 
inline unsigned char *tspace_unmarshall(const unsigned char *ignored, Transaction &transaction, 
			    CharVector_Iterator &curr, 
			    const CharVector_Iterator &end) 
  throw(NQ_Schema_Exception) {
  if(end == curr) {
    throw NQ_Schema_Exception("out of space in vector<unsigned char>");
  }
  unsigned char *c = new unsigned char[1];
  *c = *curr++;
  return c;
}

template<class T> 
inline void tspace_marshall(const T &val, std::vector<unsigned char> &buf) {
  T::tspace_marshall(val, buf);
}

template<> 
inline void tspace_marshall(const unsigned char &val, std::vector<unsigned char> &buf) {
  buf.push_back(val);
}

// N.B. Only 32-bit long vectors are supported
template<class T>
std::vector<T> *
tspace_unmarshall(const std::vector<T> *ignored, Transaction &transaction,
		  CharVector_Iterator &curr, 
		  const CharVector_Iterator &end) 
  throw(NQ_Schema_Exception) {
  uint32_t *len = tspace_unmarshall((uint32_t *)NULL, transaction, curr, end);
  std::vector<T> *rv = new std::vector<T>(*len);
  size_t i;

  for(i=0; i < *len; i++) {
    (*rv)[i] = *tspace_unmarshall((T *)NULL, transaction, curr, end);
  }
  return rv;
}

template<class T>
void tspace_marshall(const std::vector<T> &val, std::vector<unsigned char> &buf) {
  size_t i;
  tspace_marshall((uint32_t)val.size(), buf);
  for(i=0; i < val.size(); i++) {
    tspace_marshall(val[i], buf);
  }
}

// Overrides

template<>
int32_t *tspace_unmarshall(const int32_t *ignored, Transaction &transaction, 
			   CharVector_Iterator &curr, 
			   const CharVector_Iterator &end)
  throw(NQ_Schema_Exception);
template<>
void tspace_marshall(const int32_t &val, std::vector<unsigned char> &buf);

template<> int tspace_marshall_size<int32_t>(void);

template<>
uint32_t *tspace_unmarshall(const uint32_t *ignored, Transaction &transaction, 
			    CharVector_Iterator &curr, 
			    const CharVector_Iterator &end)
  throw(NQ_Schema_Exception);
template<>
void tspace_marshall(const uint32_t &val, std::vector<unsigned char> &buf);

template<> 
int tspace_marshall_size<uint32_t>(void);

template<>
uint16_t *tspace_unmarshall(const uint16_t *ignored, Transaction &transaction, 
			    CharVector_Iterator &curr, 
			    const CharVector_Iterator &end)
  throw(NQ_Schema_Exception);
template<>
void tspace_marshall(const uint16_t &val, std::vector<unsigned char> &buf);

template<> 
int tspace_marshall_size<uint16_t>(void);


template<>
NQ_Tuple *tspace_unmarshall(const NQ_Tuple *ignored, Transaction &transaction, 
			    CharVector_Iterator &curr, 
			    const CharVector_Iterator &end) 
  throw(NQ_Schema_Exception);
template<> 
void tspace_marshall(const NQ_Tuple &val, std::vector<unsigned char> &buf);

template<> 
int tspace_marshall_size<NQ_Tuple>(void);

// for some reason, need both NQ_UUID and NQ_Tuple versions to link properly
template<> 
int tspace_marshall_size<NQ_UUID>(void);

template<>
std::string *tspace_unmarshall(const std::string *ignored, Transaction &transaction, 
			   CharVector_Iterator &curr, 
			   const CharVector_Iterator &end)
  throw(NQ_Schema_Exception);
template<>
void tspace_marshall(const std::string &val, std::vector<unsigned char> &buf);

template<>
NQ_Principal *tspace_unmarshall(const NQ_Principal *ignored, Transaction &transaction, 
			   CharVector_Iterator &curr, 
			   const CharVector_Iterator &end)
  throw(NQ_Schema_Exception);

template<>
void tspace_marshall(const NQ_Principal &val, std::vector<unsigned char> &buf);

template<> 
void tspace_marshall(const NQ_Attribute_Name &val, std::vector<unsigned char> &buf);
NQ_Attribute_Name *tspace_unmarshall(const NQ_Attribute_Name *ignored, Transaction &transaction, 
			    CharVector_Iterator &curr, 
			    const CharVector_Iterator &end) 
  throw(NQ_Schema_Exception);

template<> 
int tspace_marshall_size<NQ_Attribute_Name>(void);

// Helper functions for defining unmarshall 
template<class T>
inline T *unmarshall_flat_object(CharVector_Iterator &curr, 
			  const CharVector_Iterator &end)
  throw(NQ_Schema_Exception) {
  T *rv = (T *)new T;
  if( (size_t)(&*end - &*curr) < sizeof(*rv) ) {
    std::cerr << "len " << (&*end - &*curr) << " wanted " << sizeof(*rv) << "\n";
    throw NQ_Schema_Exception("Flat struct length mismatch!\n");
  }

  size_t i;
  for(i=0 ; i < sizeof(*rv) ; i++) {
    ((unsigned char *)rv)[i] = *curr;
    curr++;
  }
  return rv;
}

static inline void marshall_fixed_len(const void *data, size_t len, std::vector<unsigned char> &buf) {
  const unsigned char *d = (const unsigned char *)data;
  size_t i;
  for(i=0; i < len; i++) {
    buf.push_back(d[i]);
  }
}

template<class T>
inline void marshall_flat_object(const T &val, std::vector<unsigned char> &buf) {
  marshall_fixed_len(&val, sizeof(val), buf);
}

template<class T> void file_marshall_flat_object(const T &val, std::ostream &os) {
  std::vector<unsigned char> buf;
  marshall_flat_object(val, buf);
  os.write( (char *)vector_as_ptr(buf), buf.size() );
}

NQ_UUID load_tid_from_file(const std::string &fname);

#endif // _MARSHALL_HH_
