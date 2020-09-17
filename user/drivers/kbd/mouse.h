#ifndef _NEXUS_MOUSEDEV_H_
#define _NEXUS_MOUSEDEV_H_
#include <nexus/mouse.h>

int mousedev_write(const char *data, int count);

int nd_set_protocol(enum MouseProto proto);
int nd_GetDeviceID(void);

void mouse_handleScancode(unsigned char scancode);

// Functions below are from Linux layer
void psaux_set_default_params(void);

#endif // _NEXUS_MOUSEDEV_H_

