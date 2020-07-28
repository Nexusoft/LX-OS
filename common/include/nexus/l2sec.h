#ifndef _L2SEC_H_
#define _L2SEC_H_

// auth is computed over packet, including seqnum, excluding auth[16]
struct l2sechdr {
  unsigned int seqnum;
  unsigned char auth[16]; // enough space for hmac-128
} __attribute__((packed));

#define L2SEC_KEYLEN (16)
#define L2SEC_MACLEN (16)

enum SwitchCommand {
  KEYCHANGE = 1,
};

struct SwitchCommand_Keychange {
  int num_key_bytes;
  char key_data[0];
} __attribute__((packed));

#endif // _L2SEC_H_
