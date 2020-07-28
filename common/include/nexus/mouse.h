#ifndef _NEXUS_MOUSE_H_
#define _NEXUS_MOUSE_H_

enum MouseProto {
  MPROT_DEFAULT,
  MPROT_IMPS2,
  MPROT_EXPPS2,
  
  // add if needed
  MPROT_LAST,
};

struct MouseEvent {
  short dx;
  short dy;
  short dz;
  unsigned char buttons;
} __attribute__((packed));

#endif // _NEXUS_MOUSE_H_
