#ifndef _NEXUS_INITRD_H_
#define _NEXUS_INITRD_H_

extern long initrd_start, initrd_size;

// this struct meshes with 'tar' the header blocks found in our initrd
struct InitRD_File {
	char name[100]; // guaranteed null terminated
	char mode[8];
	char owner_id[8];
	char group_id[8];
	char file_size[12];
	char mtime[12];
	char checksum[8];
	char link[1];
	char link_name[100];
	// remainder overwrites USTAR extension data, which is not needed
	char *data;					// pointer to data
	int len;					// file length
	struct InitRD_File *next;	// next initrd file header block
} __attribute__((packed));

void init_initrd(void);

struct InitRD_File *initrd_first(void);

struct InitRD_File *initrd_find(const char *name);

#endif
