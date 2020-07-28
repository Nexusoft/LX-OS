#include <string>
#include <vector>
#include <iostream>
#include <nq/marshall.hh>
#include <nq/uuid.h>
#include <nq/attribute.hh>
#include <fstream>

// All integer should use types with defined types (e.g. int32_t)

using namespace std;

//////////
// int32_t
//////////

template<>
int32_t *tspace_unmarshall(const int32_t *ignored, Transaction &transaction, 
			   CharVector_Iterator &curr, 
			   const CharVector_Iterator &end)
  throw(NQ_Schema_Exception) {
  return unmarshall_flat_object<int32_t>(curr, end);
}
template<>
void tspace_marshall(const int32_t &val, vector<unsigned char> &buf) 
{
  marshall_flat_object<int32_t>(val, buf);
}

template<>
int tspace_marshall_size<int32_t>(void)
{
  return sizeof(int32_t);
}

//////////
// uint32_t
//////////

template<>
uint32_t *tspace_unmarshall(const uint32_t *ignored, Transaction &transaction, 
			    CharVector_Iterator &curr, 
			    const CharVector_Iterator &end) 
  throw(NQ_Schema_Exception) {
  return unmarshall_flat_object<uint32_t>(curr, end);
}

template<>
void tspace_marshall(const uint32_t &val, vector<unsigned char> &buf) 
{
  marshall_flat_object<uint32_t>(val, buf);
}

template<>
int tspace_marshall_size<uint32_t>(void)
{
  return sizeof(uint32_t);
}

//////////
// uint16_t
//////////

template<>
uint16_t *tspace_unmarshall(const uint16_t *ignored, Transaction &transaction, 
			    CharVector_Iterator &curr, 
			    const CharVector_Iterator &end) 
  throw(NQ_Schema_Exception) {
  return unmarshall_flat_object<uint16_t>(curr, end);
}

template<>
void tspace_marshall(const uint16_t &val, vector<unsigned char> &buf) 
{
  marshall_flat_object<uint16_t>(val, buf);
}

template<>
int tspace_marshall_size<uint16_t>(void)
{
  return sizeof(uint16_t);
}

//////////
// NQ_Tuple
//////////

template<>
NQ_Tuple *tspace_unmarshall(const NQ_Tuple *ignored, Transaction &transaction, 
			    CharVector_Iterator &curr, 
			    const CharVector_Iterator &end) 
  throw(NQ_Schema_Exception) {
  NQ_Tuple *tuple = unmarshall_flat_object<NQ_Tuple>(curr, end);
  // std::cerr << "Unmarshall tuple " << *tuple << "\n";
  return tuple;
}

template<>
void tspace_marshall(const NQ_Tuple &val, vector<unsigned char> &buf) 
{
  marshall_flat_object<NQ_Tuple>(val, buf);
}

template<> int tspace_marshall_size<NQ_Tuple>(void) {
  return sizeof(NQ_Tuple);
}

//////////
// string
//////////
template<>
string *tspace_unmarshall(const string *ignored, Transaction &transaction, 
			   CharVector_Iterator &curr, 
			   const CharVector_Iterator &end)
  throw(NQ_Schema_Exception) {
  // fprintf(stderr, "string marshalling is bogus\n");
  int32_t len = *tspace_unmarshall((int32_t *)0, transaction, curr, end);
  string *str = new string(curr, curr+len-1); // adjust for null terminator
  curr += len;
  return str;
}

template<>
void tspace_marshall(const string &val, vector<unsigned char> &buf) {
  //fprintf(stderr, "string marshalling is bogus\n");
  int32_t len = strlen(val.c_str()) + 1;
  tspace_marshall(len, buf);
  marshall_fixed_len(val.c_str(), len, buf);
}

//////
// Principals
//////

template<>
NQ_Principal *tspace_unmarshall(const NQ_Principal *ignored, Transaction &transaction, 
			   CharVector_Iterator &curr, 
			   const CharVector_Iterator &end)
  throw(NQ_Schema_Exception) {
  const unsigned char *data = &*curr;
  int len = end - curr;
  int read_len;
  NQ_Principal *p = NQ_Principal_import(const_cast<unsigned char *>(data), len, &read_len);
  // printf("BIO read len = %d\n", read_len);
  curr += read_len;
  return p;
}

template<>
void tspace_marshall(const NQ_Principal &val, std::vector<unsigned char> &buf) {
  unsigned char *data = NULL;
  int len = NQ_Principal_export(const_cast<NQ_Principal *>(&val), &data);
  for(int i=0; i < len; i++) {
    buf.push_back(data[i]);
  }
  free(data);
}

#if 0
template<> void tspace_marshall(const NQ_Tuple *val, vector<unsigned char> &buf) throw(NQ_Schema_Exception);
#endif

NQ_UUID load_tid_from_file(const string &fname) {
  ifstream ifs(fname.c_str());
  if(!ifs.good()) {
    cerr << "Could not open site tid!\n";
    exit(-1);
  }
  NQ_UUID rv;
  vector<unsigned char> all_data;

  get_all_file_data(ifs, all_data);
  CharVector_Iterator s = all_data.begin(), end = all_data.end();

  rv = *tspace_unmarshall(&rv, *(Transaction *)NULL, s, end);

  ifs.close();
  return rv;
}

//////
// Attribute names
//////

template<> 
void tspace_marshall(const NQ_Attribute_Name &val, std::vector<unsigned char> &buf) {
  tspace_marshall(*val.owner, buf);
  tspace_marshall((int32_t)val.type, buf);
  int32_t len = strlen(val.name)+1;
  tspace_marshall(len, buf);
  marshall_fixed_len(val.name, len, buf);
}

NQ_Attribute_Name *tspace_unmarshall(const NQ_Attribute_Name *ignored, Transaction &transaction, 
			    CharVector_Iterator &curr, 
			    const CharVector_Iterator &end) 
  throw(NQ_Schema_Exception) {
  NQ_Principal *p = tspace_unmarshall((NQ_Principal *)0, transaction, curr, end);
  int32_t type = *tspace_unmarshall((int32_t *)0, transaction, curr, end);
  int32_t len = *tspace_unmarshall((int32_t *)0, transaction, curr, end);
  // printf("len = %d, type = %d\n", len, type);
  char *name = new char[len];
  memcpy(name, &*curr, len);
  curr += len;
  NQ_Attribute_Name *attr = NQ_Attribute_Name_alloc(&p->home, (NQ_Attribute_Type)type, name);
  delete [] name;
  return attr;
}

#if 0
template<> 
int tspace_marshall_size<NQ_Attribute_Name>(void) {
  assert(0);
}
#endif
