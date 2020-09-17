#ifndef __FAT_ACCESS_H__
#define __FAT_ACCESS_H__

#include "fat_defs.h"
#include "fat_opts.h"
#include <malloc.h>
#include <assert.h>

//-----------------------------------------------------------------------------
// Defines
//-----------------------------------------------------------------------------
#define FAT_INIT_OK							0
#define FAT_INIT_MEDIA_ACCESS_ERROR					(-1)
#define FAT_INIT_INVALID_SECTOR_SIZE					(-2)	
#define FAT_INIT_INVALID_SIGNATURE					(-3)
#define FAT_INIT_ENDIAN_ERROR						(-4)
#define FAT_INIT_WRONG_FILESYS_TYPE					(-5)
#define FAT_INIT_WRONG_PARTITION_TYPE					(-6)
#define FAT_INIT_MEM_ALLOC          					(-7)

#define fatfs_sector_reader(fs, sc, off, t)	(fatfs_sectors_reader((fs), (sc), (off), 1, (t)))

#define fatfs_sector_writer(fs, sc, off, t)	(fatfs_sectors_writer((fs), (sc), (off), 1, (t)))

//-----------------------------------------------------------------------------
// Function Pointers
//-----------------------------------------------------------------------------
typedef int (*fn_diskio_read_sector) (UINT32 sector, unsigned char *buffer);
typedef int (*fn_diskio_write_sector)(UINT32 sector, unsigned char *buffer);
typedef int (*fn_diskio_read) (UINT32 sector, UINT32 len, unsigned char *buffer);
typedef int (*fn_diskio_write)(UINT32 sector, UINT32 len, unsigned char *buffer);

//-----------------------------------------------------------------------------
// Structures
//-----------------------------------------------------------------------------
struct disk_if
{
	// User supplied function pointers for disk IO
	fn_diskio_read		read_sectors;
	fn_diskio_write		write_sectors;
	fn_diskio_read_sector	read_sector;
	fn_diskio_write_sector	write_sector;
};

// Forward declaration
struct sector_buffer;

struct sector_buffer
{
	// Dynamically allocated and FAT_SECTOR_SIZE aligned
	unsigned char			*sector;
	UINT32				address; 
	int				dirty;

	// Next in chain of sector buffers
	struct sector_buffer		*next;
};

struct fatfs
{
	// Filesystem globals
	unsigned char				sectors_per_cluster;
	UINT32					cluster_begin_lba;
	UINT32					rootdir_first_cluster;
	UINT32					fat_begin_lba;
	UINT32					filenumber;
	UINT16					fs_info_sector;
	UINT32					lba_begin;
	UINT32					fat_sectors;
	UINT32					next_free_cluster;
	unsigned long long			total_bytes;

	// Disk/Media API
	struct disk_if				disk_io;

	// [Optional] Thread Safety
	void					(*fl_lock)(void);
	void					(*fl_unlock)(void);

	// Working buffer
	struct sector_buffer			currentsector;
	
	// FAT Buffer
	struct sector_buffer			*fat_buffer_head;
	struct sector_buffer			fat_buffers[FAT_BUFFERED_SECTORS];
};

//-----------------------------------------------------------------------------
// Prototypes
//-----------------------------------------------------------------------------
int		fatfs_init(struct fatfs *fs);
UINT32		fatfs_lba_of_cluster(struct fatfs *fs, UINT32 Cluster_Number);
int		fatfs_sectors_reader(struct fatfs *fs, UINT32 Startcluster, UINT32 offset, UINT32 len, unsigned char *target);
int		fatfs_sectors_writer(struct fatfs *fs, UINT32 Startcluster, UINT32 offset, UINT32 len, unsigned char *target);
void		fatfs_show_details(struct fatfs *fs);
UINT32		fatfs_get_root_cluster(struct fatfs *fs);
UINT32		fatfs_get_file_entry(struct fatfs *fs, UINT32 Cluster, char *nametofind, FAT32_ShortEntry *sfEntry);
int		fatfs_sfn_exists(struct fatfs *fs, UINT32 Cluster, char *shortname);
int		fatfs_update_file_length(struct fatfs *fs, UINT32 Cluster, char *shortname, UINT32 fileLength);
int		fatfs_mark_file_deleted(struct fatfs *fs, UINT32 Cluster, char *shortname);
void		fatfs_list_directory(struct fatfs *fs, UINT32 StartCluster);
char		*fatfs_get_directory_n(struct fatfs *fs, UINT32 StartCluster, unsigned long n);
int 		fatfs_is_directory(struct fatfs *fs, UINT32 StartCluster, const char *file_name);

#endif
