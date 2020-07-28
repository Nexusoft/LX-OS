#ifndef _JUKEBOX_H_
#define _JUKEBOX_H_

int jukebox_read(IPD_ID ipd_id, Call_Handle call_handle,
		      FSID target_node, int file_position,
		      /* __output__ */ struct VarLen dest, int count);

FSID jukebox_lookup(FSID parent_node, char *filename, int resolve_mounts);

#endif // _JUKEBOX_H_
