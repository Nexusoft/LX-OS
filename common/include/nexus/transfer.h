#ifndef TRANSFER_H_
#define TRANSFER_H_

#define MAX_TRANSFERDESCS (4)

#define IPC_READ 	0x1
#define IPC_WRITE	0x2
#define IPC_MAXSIZE	(1 << 16)

struct TransferDesc {
  int access; // XXX remove when IDLGEN stops expecting this
  // XXX simplify when IDLGEN stops expecting this
  union {
	  struct {
		unsigned int base;
		unsigned int length;
	  } direct;
  } u;
};

// XXX remove when IDLGEN stops generating it
#define DESCRIPTOR_START (0)

#endif // TRANSFER_H_

