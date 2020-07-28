// This file is for generic utility functions

#define __STDC_CONSTANT_MACROS
#include <stdint.h>
#include <string>
#include <iostream>
#include <ext/hash_map>
#include <netdb.h>
#include <nq/util.hh>

#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <nq/netquery.h>

#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((const uint8_t *)(d))[1] << UINT32_C(8))\
                      +((const uint8_t *)(d))[0])
#endif

#ifndef __NEXUS__
unsigned int SuperFastHash (const char * data, int len) {
unsigned int hash = len, tmp;
int rem;

    if (len <= 0 || data == NULL) return 0;

    rem = len & 3;
    len >>= 2;

    /* Main loop */
    for (;len > 0; len--) {
        hash  += get16bits (data);
        tmp    = (get16bits (data+2) << 11) ^ hash;
        hash   = (hash << 16) ^ tmp;
        data  += 2*sizeof (uint16_t);
        hash  += hash >> 11;
    }

    /* Handle end cases */
    switch (rem) {
        case 3: hash += get16bits (data);
                hash ^= hash << 16;
                hash ^= data[sizeof (uint16_t)] << 18;
                hash += hash >> 11;
                break;
        case 2: hash += get16bits (data);
                hash ^= hash << 11;
                hash += hash >> 17;
                break;
        case 1: hash += *data;
                hash ^= hash << 10;
                hash += hash >> 1;
    }

    /* Force "avalanching" of final 127 bits */
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 2;
    hash += hash >> 15;
    hash ^= hash << 10;

    return hash;
}
#endif // __NEXUS__

using namespace std;

string get_line(CharVector_Iterator &curr, const CharVector_Iterator &end) {
  string rv;
  for(; curr != end && *curr != '\n'; curr++) {
    rv += *curr;
  }
  if(curr != end && *curr == '\n') {
    curr++;
  }
  return rv;
}

void split(const string& str, const string& delimiters, vector<string>& tokens)
{
  // from http://www.oopweb.com/CPP/Documents/CPPHOWTO/Volume/C++Programming-HOWTO-7.html

  // Skip delimiters at beginning.
  string::size_type lastPos = str.find_first_not_of(delimiters, 0);
  // Find first "non-delimiter".
  string::size_type pos     = str.find_first_of(delimiters, lastPos);

  while (string::npos != pos || string::npos != lastPos)
    {
      // Found a token, add it to the vector.
      tokens.push_back(str.substr(lastPos, pos - lastPos));
      // Skip delimiters.  Note the "not_of"
      lastPos = str.find_first_not_of(delimiters, pos);
      // Find next "non-delimiter"
      pos = str.find_first_of(delimiters, lastPos);
    }
}

void get_all_file_data(istream &is, vector<unsigned char> &output) {
  while(1) {
    unsigned char c;
    is.read((char *)&c, 1);
    if(is.good()) {
      output.push_back(c);
    } else {
      break;
    }
  }
}

uint32_t resolve_ip(const string &str) {
  struct hostent *hostent = gethostbyname(str.c_str());
  if(hostent == NULL) {
    return 0;
  } else {
    return *(uint32_t *)hostent->h_addr;
  }
}
string gethostname(void) {
    char hostname[100];
    if(gethostname(hostname, sizeof(hostname)) == 0) {
      return string(hostname);
    } else {
      cerr << "could not get hostname?\n";
      exit(-1);
    }
}

void write_int(ostream &os, int v) {
  os.write((char*)&v, sizeof(v));
}

int read_int(istream &is) {
  int v;
  is.read((char*)&v, sizeof(v));
  return v;
}

int read_int(CharVector_Iterator &curr, const CharVector_Iterator &end) {
  if((size_t)(end - curr) < sizeof(int)) {
    throw "not enough space for int\n";
  }
  int val = *(int*)&*curr;
  curr += sizeof(int);
  return val;
}


struct ProcStat {
  ProcStat(int pid) : pid(pid) {
    reload();
  }

  FILE *input;

  uint64_t pid;
  char tcomm[PATH_MAX];
  char state;

  uint64_t ppid;
  uint64_t pgid;
  uint64_t sid;
  uint64_t tty_nr;
  uint64_t tty_pgrp;

  uint64_t flags;
  uint64_t min_flt;
  uint64_t cmin_flt;
  uint64_t maj_flt;
  uint64_t cmaj_flt;
  uint64_t utime;
  uint64_t stimev;

  uint64_t cutime;
  uint64_t cstime;
  uint64_t priority;
  uint64_t nicev;
  uint64_t num_threads;
  uint64_t it_real_value;

  unsigned long long start_time;

  uint64_t vsize;
  uint64_t rss;
  uint64_t rsslim;
  uint64_t start_code;
  uint64_t end_code;
  uint64_t start_stack;
  uint64_t esp;
  uint64_t eip;

  uint64_t pending;
  uint64_t blocked;
  uint64_t sigign;
  uint64_t sigcatch;
  uint64_t wchan;
  uint64_t zero1;
  uint64_t zero2;
  uint64_t exit_signal;
  uint64_t cpu;
  uint64_t rt_priority;
  uint64_t policy;

  long tickspersec;

  private:
  void readone(uint64_t *x) { fscanf(input, "%lld ", x); }
  void readunsigned(unsigned long long *x) { fscanf(input, "%llu ", x); }
  void readstr(char *x) {  fscanf(input, "%s ", x);}
  void readchar(char *x) {  fscanf(input, "%c ", x);}

#if 0
  void printone(char *name, uint64_t x) {  printf("%20s: %lld\n", name, x);}
  void printonex(char *name, uint64_t x) {  printf("%20s: %016llx\n", name, x);}
  void printunsigned(char *name, unsigned long long x) {  printf("%20s: %llu\n", name, x);}
  void printchar(char *name, char x) {  printf("%20s: %c\n", name, x);}
  void printstr(char *name, char *x) {  printf("%20s: %s\n", name, x);}
  void printtime(char *name, uint64_t x) {  printf("%20s: %f\n", name, (((double)x) / tickspersec));}
#endif

  void reload() {
    char pid_buf[80];
    sprintf(pid_buf, "/proc/%lld/stat", pid);
    input = fopen(pid_buf, "r");
    if(!input) {
      perror("open");
      return;
    }

    readone(&pid);
    readstr(tcomm);
    readchar(&state);
    readone(&ppid);
    readone(&pgid);
    readone(&sid);
    readone(&tty_nr);
    readone(&tty_pgrp);
    readone(&flags);
    readone(&min_flt);
    readone(&cmin_flt);
    readone(&maj_flt);
    readone(&cmaj_flt);
    readone(&utime);
    readone(&stimev);
    readone(&cutime);
    readone(&cstime);
    readone(&priority);
    readone(&nicev);
    readone(&num_threads);
    readone(&it_real_value);
    readunsigned(&start_time);
    readone(&vsize);
    readone(&rss);
    readone(&rsslim);
    readone(&start_code);
    readone(&end_code);
    readone(&start_stack);
    readone(&esp);
    readone(&eip);
    readone(&pending);
    readone(&blocked);
    readone(&sigign);
    readone(&sigcatch);
    readone(&wchan);
    readone(&zero1);
    readone(&zero2);
    readone(&exit_signal);
    readone(&cpu);
    readone(&rt_priority);
    readone(&policy);
  }
};

extern "C" uint64_t ProcStat_get_vsize(int pid) {
  ProcStat proc_stat(pid);
  return proc_stat.vsize;
}

