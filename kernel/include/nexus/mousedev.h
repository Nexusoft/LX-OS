#ifndef _NEXUS_MOUSEDEV_H_
#define _NEXUS_MOUSEDEV_H_
#include <nexus/mouse.h>

NexusOpenDevice *mouse_new(NexusDevice *nd, IPD *ipd);
int mouse_setProtocol(NexusOpenDevice *nod, enum MouseProto proto);
void mouse_focus(NexusOpenDevice *nod, int focus);

int mouse_poll(NexusOpenDevice *nod);
int mouse_read(NexusOpenDevice *nod,
	       struct MouseEvent *dest, int max_num_events);

void mouse_handleScancode(unsigned char scancode);

// Any functions that expects psaux ACK Nexus layer must call
// mouse_parse_disable() to prevent the bytes from being captured by
// the event parser
void mouse_parse_disable(void);
void mouse_parse_enable(void);

// nd_set_protocol() requires parse disabled
int nd_set_protocol(NexusDevice *nd, enum MouseProto proto);
int nd_GetDeviceID(NexusDevice *nd);

// Debugging
void mouse_dump_log(void);

// Functions below are from Linux layer
void psaux_set_default_params(void);

#endif // _NEXUS_MOUSEDEV_H_
