/** NexusOS: deprecated policy implementations 
 
    Only the guards and grounds in guard.h are used. This is here
    purely for informational reasons. It will go at some point. */

#ifndef _NEXUS_POLICY_H_
#define _NEXUS_POLICY_H_

#include <nexus/commontypedefs.h>
#include <nexus/formula.h>

#ifdef __NEXUSKERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

// Currently there are three versions of policies, grounds (aka proofs), and
// guards: the placeholder version, the production version, and the experimental version.

// Placeholder version:
//
// Policies are 4 bytes long, and always equal to POLITE_REQUESTORS_ONLY.
// Grounds are always 4 bytes long, and always equal to PRETTY_PLEASE. Neither
// of these invariants is enforced. There is no guard.

typedef int POLICY;
typedef int GROUNDS;
#define POLITE_REQUESTORS_ONLY 0xd00d1e
#define PRETTY_PLEASE 0xf100f
#define NULL_GROUNDS 0

#define guard_convinced(policy, grounds) (1)

// Production version:
//
// Policies are 4 bytes long. A very limited range of policies are supported:
// The zero policy goal allows no requests through. The all-ones policy goal lets all
// requests through. Any other policy goal, say the bytes 0xdeadbeef, will be
// considered satisfied if the requester submits the identical bytes as the
// grounds.
//
// Grounds are 4 bytes long, and are optional. If the policy is non-zero and not
// all ones, then the grounds must be provided, and their contents must equal
// the policy bytes in order to gain access. 
//
// The production guard is rather simple and unsurprisingly efficient.

struct Policy {
  int gf;
};

static inline int int_serialize(int x, char *buf, int *len) {
  if (*len < sizeof(int)) { *len = sizeof(int); return -1; }
  *len = sizeof(int);
  memcpy(buf, &x, sizeof(int)); // todo: fix byte order
  return 0;
}

static inline int int_deserialize(int *x, char *buf, int len) {
  if (len < sizeof(int)) return -1;
  memcpy(x, buf, sizeof(int)); // todo: fix byte order
  return 0;
}

static inline int Policy_len(Policy *pol) { return sizeof(int); }
static inline int Policy_serialize(Policy *pol, char *buf, int *len) { return int_serialize(pol->gf, buf, len); }
static inline int Policy_deserialize(Policy *pol, int *pollen, unsigned char *buf, int buflen) {
  if (*pollen < sizeof(Policy)) { *pollen = sizeof(Policy); return -1; }
  return int_deserialize(&pol->gf, (char *)buf, buflen);
}

struct Grounds {
  int deadbeef;
};

static inline int Grounds_len(Grounds *pg) { return sizeof(int); }
static inline int Grounds_serialize(Grounds *pg, char *buf, int *len) { return int_serialize(pg->deadbeef, buf, len); }
static inline int Grounds_deserialize(Grounds *pg, int *pglen, char *buf, int buflen) {
  if (*pglen < sizeof(Grounds)) { *pglen = sizeof(Grounds); return -1; }
  return int_deserialize(&pg->deadbeef, buf, buflen);
}

// entry point for evaluating policy goals in light of some grounds
static inline int Policy_check(Policy *p, Grounds *pg) {
  return (p->gf == -1 || (p->gf != 0 && pg && p->gf == pg->deadbeef));
}

// Experimental version: see guard.h

#endif //_NEXUS_POLICY_H_
