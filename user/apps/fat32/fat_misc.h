#ifndef __FAT_MISC_H__
#define __FAT_MISC_H__

#include "fat_defs.h"
#include "fat_opts.h"

//-----------------------------------------------------------------------------
// Defines
//-----------------------------------------------------------------------------
#define MAX_LONGFILENAME_ENTRIES	20
#define MAX_SFN_ENTRY_LENGTH		13

//-----------------------------------------------------------------------------
// Macros
//-----------------------------------------------------------------------------
// Little Endian
#if FATFS_IS_LITTLE_ENDIAN
	#define GET_32BIT_WORD(buffer, location)	( ((UINT32)buffer[location+3]<<24) + ((UINT32)buffer[location+2]<<16) + ((UINT32)buffer[location+1]<<8) + (UINT32)buffer[location+0] )
	#define GET_16BIT_WORD(buffer, location)	( ((UINT16)buffer[location+1]<<8) + (UINT16)buffer[location+0] )

	#define SET_32BIT_WORD(buffer, location, value)	{ buffer[location+0] = (BYTE)((value)&0xFF); \
													  buffer[location+1] = (BYTE)((value>>8)&0xFF); \
													  buffer[location+2] = (BYTE)((value>>16)&0xFF); \
													  buffer[location+3] = (BYTE)((value>>24)&0xFF); }

	#define SET_16BIT_WORD(buffer, location, value)	{ buffer[location+0] = (BYTE)((value)&0xFF); \
													  buffer[location+1] = (BYTE)((value>>8)&0xFF); }
// Big Endian
#else
	#define GET_32BIT_WORD(buffer, location)	( ((UINT32)buffer[location+0]<<24) + ((UINT32)buffer[location+1]<<16) + ((UINT32)buffer[location+2]<<8) + (UINT32)buffer[location+3] )
	#define GET_16BIT_WORD(buffer, location)	( ((UINT16)buffer[location+0]<<8) + (UINT16)buffer[location+1] )

	#define SET_32BIT_WORD(buffer, location, value)	{ buffer[location+3] = (BYTE)((value)&0xFF); \
													  buffer[location+2] = (BYTE)((value>>8)&0xFF); \
													  buffer[location+1] = (BYTE)((value>>16)&0xFF); \
													  buffer[location+0] = (BYTE)((value>>24)&0xFF); }

	#define SET_16BIT_WORD(buffer, location, value)	{ buffer[location+1] = (BYTE)((value)&0xFF); \
													  buffer[location+0] = (BYTE)((value>>8)&0xFF); }
#endif

//-----------------------------------------------------------------------------
// Structures
//-----------------------------------------------------------------------------
struct lfn_cache
{
	// Long File Name Structure (max 260 LFN length)
	unsigned char String[MAX_LONGFILENAME_ENTRIES][MAX_SFN_ENTRY_LENGTH];
	unsigned char no_of_strings;
};

//-----------------------------------------------------------------------------
// Prototypes
//-----------------------------------------------------------------------------
void	fatfs_lfn_cache_init(struct lfn_cache *lfn, int wipeTable);
void	fatfs_lfn_cache_entry(struct lfn_cache *lfn, unsigned char *entryBuffer);
char*	fatfs_lfn_cache_get(struct lfn_cache *lfn);
int		fatfs_entry_lfn_text(FAT32_ShortEntry *entry);
int		fatfs_entry_lfn_invalid(FAT32_ShortEntry *entry);
int		fatfs_entry_lfn_exists(struct lfn_cache *lfn, FAT32_ShortEntry *entry);
int		fatfs_entry_sfn_only(FAT32_ShortEntry *entry);
int		fatfs_entry_is_dir(FAT32_ShortEntry *entry);
int		fatfs_entry_is_file(FAT32_ShortEntry *entry);
int		fatfs_lfn_entries_required(char *filename);
void	fatfs_filename_to_lfn(char *filename, unsigned char *buffer, int entry, unsigned char sfnChk);
void	fatfs_sfn_create_entry(char *shortfilename, UINT32 size, UINT32 startCluster, FAT32_ShortEntry *entry, int dir);
int		fatfs_lfn_create_sfn(char *sfn_output, char *filename);
int		fatfs_lfn_generate_tail(char *sfn_output, char *sfn_input, UINT32 tailNum);

#endif
