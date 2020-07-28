#ifndef __UDEVICE_H__
#define __UDEVICE_H__

/* Nexus device types */
typedef enum DeviceType{
	DEVICE_NONE = 0,
	DEVICE_AUDIO = 1,
	DEVICE_VIDEO,
	DEVICE_KEYBOARD,
	DEVICE_NETWORK,
	DEVICE_TPM,
	DEVICE_MOUSE,
	NUM_DEVICE_TYPES, /* last */
}DeviceType;

#endif
