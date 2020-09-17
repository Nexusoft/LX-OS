//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//					        FAT32 File IO Library
//								    V2.5
// 	  							 Rob Riglar
//						    Copyright 2003 - 2010
//
//   					  Email: rob@robriglar.com
//
//								License: GPL
//   If you would like a version with a more permissive license for use in
//   closed source commercial applications please contact me for details.
//-----------------------------------------------------------------------------
//
// This file is part of FAT32 File IO Library.
//
// FAT32 File IO Library is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// FAT32 File IO Library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with FAT32 File IO Library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "fat_defs.h"
#include "fat_access.h"
#include "fat_table.h"
#include "fat_write.h"
#include "fat_misc.h"
#include "fat_string.h"
#include "fat_filelib.h"

//-----------------------------------------------------------------------------
// Locals
//-----------------------------------------------------------------------------
static FL_FILE			Files[FATFS_MAX_OPEN_FILES];
static int			Filelib_Init = 0;
static int			Filelib_Valid = 0;
static struct fatfs		Fs;
static FL_FILE*			Filelib_open_files = NULL;
static FL_FILE*			Filelib_free_files = NULL;


//-----------------------------------------------------------------------------
// Macros
//-----------------------------------------------------------------------------

// Macro for checking if file lib is initialised
#define CHECK_FL_INIT()		{ if (Filelib_Init==0) fl_init(); }

#define FL_LOCK(a)		do { if ((a)->fl_lock) (a)->fl_lock(); } while (0)
#define FL_UNLOCK(a)		do { if ((a)->fl_unlock) (a)->fl_unlock(); } while (0)

//-----------------------------------------------------------------------------
// Local Functions
//-----------------------------------------------------------------------------
static void				_fl_init(void);

//-----------------------------------------------------------------------------
// _allocate_file: Find a slot in the open files buffer for a new file
//-----------------------------------------------------------------------------
static FL_FILE* _allocate_file(void)
{
	// Allocate free file
	FL_FILE *file = Filelib_free_files;
	// Should always have enough file descriptors,
	// if this crashes it's not a bug see FATFS_MAX_OPEN_FILES
	assert(file);

	Filelib_free_files = file->next;

	// Add to open list
	file->next = Filelib_open_files;
	Filelib_open_files = file;

	return file;
}
//-----------------------------------------------------------------------------
// _check_file_open: Returns true if the file is already open
//-----------------------------------------------------------------------------
static int _check_file_open(FL_FILE* file)
{
	FL_FILE* openFile = Filelib_open_files;
	
	// Compare open files
	while (openFile)
	{
		// If not the current file 
		if (openFile != file)
		{
			// Compare path and name
			if ( (fatfs_compare_names(openFile->path,file->path)) && (fatfs_compare_names(openFile->filename,file->filename)) )
				return 1;
		}

		openFile = openFile->next;
	}

	return 0;
}
//-----------------------------------------------------------------------------
// _free_file: Free open file handle
//-----------------------------------------------------------------------------
static void _free_file(FL_FILE* file)
{
	FL_FILE* openFile = Filelib_open_files;
	FL_FILE* lastFile = NULL;
	
	// Remove from open list
	while (openFile)
	{
		// If the current file 
		if (openFile == file)
		{
			if (lastFile)
				lastFile->next = openFile->next;
			else
				Filelib_open_files = openFile->next;

			break;
		}

		lastFile = openFile;
		openFile = openFile->next;
	}

	// Add to free list
	file->next = Filelib_free_files;
	Filelib_free_files = file;
}

//-----------------------------------------------------------------------------
//								Low Level
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// _open_directory: Cycle through path string to find the start cluster
// address of the highest subdir.
//-----------------------------------------------------------------------------
static int _open_directory(char *path, unsigned long *pathCluster)
{
	int levels;
	int sublevel;
	char currentfolder[FATFS_MAX_LONG_FILENAME];
	FAT32_ShortEntry sfEntry;
	unsigned long startcluster;

	// Set starting cluster to root cluster
	startcluster = fatfs_get_root_cluster(&Fs);

	// Find number of levels
	levels = fatfs_total_path_levels(path);

	// Cycle through each level and get the start sector
	for (sublevel=0;sublevel<(levels+1);sublevel++) 
	{
		if (fatfs_get_substring(path, sublevel, currentfolder, sizeof(currentfolder)) == -1)
			return 0;

		// Find clusteraddress for folder (currentfolder) 
		if (fatfs_get_file_entry(&Fs, startcluster, currentfolder,&sfEntry))
			startcluster = (((unsigned long)sfEntry.FstClusHI)<<16) + sfEntry.FstClusLO;
		else
			return 0;
	}

	*pathCluster = startcluster;
	return 1;
}

#ifndef NONEXUS
unsigned long
fl_opendirectory(const char *filepath)
{
	unsigned long cluster;

	// special case: root dir
	if (!filepath || !strcmp(filepath, "/"))
		return fatfs_get_root_cluster(&Fs);
	
	if (_open_directory((char *) filepath, &cluster))
		return cluster;
	else
		return 0;
}
#endif

//-----------------------------------------------------------------------------
// _create_directory: Cycle through path string and create the end directory
//-----------------------------------------------------------------------------
static int _create_directory(char *path)
{
	FL_FILE* file; 
	FAT32_ShortEntry sfEntry;
	char shortFilename[11];
	int tailNum;
	int i;

	// Allocate a new file handle
	file = _allocate_file();
	if (!file)
		return 0;

	// Clear filename
	memset(file->path, '\0', sizeof(file->path));
	memset(file->filename, '\0', sizeof(file->filename));

	// Split full path into filename and directory path
	if (fatfs_split_path((char *)path, file->path, sizeof(file->path), file->filename, sizeof(file->filename)) == -1)
	{
		_free_file(file);
		return 0;
	}

	// Check if file already open
	if (_check_file_open(file))
	{
		_free_file(file);
		return 0;
	}

	// If file is in the root dir
	if (file->path[0] == 0)
		file->parentcluster = fatfs_get_root_cluster(&Fs);
	else
	{
		// Find parent directory start cluster
		if (!_open_directory(file->path, &file->parentcluster))
		{
			_free_file(file);
			return 0;
		}
	}

	// Check if same filename exists in directory
	if (fatfs_get_file_entry(&Fs, file->parentcluster, file->filename, &sfEntry) == 1)
	{
		_free_file(file);
		return 0;
	}

	file->startcluster = 0;

	// Create the file space for the folder (at least one clusters worth!)
	if (!fatfs_allocate_free_space(&Fs, 1, &file->startcluster, 1))
	{
		_free_file(file);
		return 0;
	}

	if (!file->file_data.sector) {
		file->file_data.sector = memalign(FAT_SECTOR_SIZE, FAT_SECTOR_SIZE);
		if (!file->file_data.sector) {
			_free_file(file);
			return 0;
		}
	}
	memset(file->file_data.sector, 0x00, FAT_SECTOR_SIZE);

	// Erase new directory cluster
	for (i=0;i<Fs.sectors_per_cluster;i++)
	{
		if (!fatfs_sector_writer(&Fs, file->startcluster, i, file->file_data.sector))
		{
			_free_file(file);
			return 0;
		}
	}

	// Generate a short filename & tail
	tailNum = 0;
	do 
	{
		// Create a standard short filename (without tail)
		fatfs_lfn_create_sfn(shortFilename, file->filename);

        // If second hit or more, generate a ~n tail		
		if (tailNum != 0)
			fatfs_lfn_generate_tail((char*)file->shortfilename, shortFilename, tailNum);
		// Try with no tail if first entry
		else
			memcpy(file->shortfilename, shortFilename, 11);

		// Check if entry exists already or not
		if (fatfs_sfn_exists(&Fs, file->parentcluster, (char*)file->shortfilename) == 0)
			break;

		tailNum++;
	}
	while (tailNum < 9999);

	// We reached the max number of duplicate short file names (unlikely!)
	if (tailNum == 9999)
	{
		// Delete allocated space
		fatfs_free_cluster_chain(&Fs, file->startcluster);

		_free_file(file);
		return 0;
	}

	// Add file to disk
	if (!fatfs_add_file_entry(&Fs, file->parentcluster, (char*)file->filename, (char*)file->shortfilename, file->startcluster, 0, 1))
	{
		// Delete allocated space
		fatfs_free_cluster_chain(&Fs, file->startcluster);

		_free_file(file);
		return 0;
	}

	// General
	file->filelength = 0;
	file->bytenum = 0;
	file->file_data.address = 0xFFFFFFFF;
	file->file_data.dirty = 0;
	file->filelength_changed = 0;
	
	fatfs_fat_purge(&Fs);

	_free_file(file);
	return 1;
}
//-----------------------------------------------------------------------------
// _open_file: Open a file for reading
//-----------------------------------------------------------------------------
static FL_FILE* _open_file(const char *path)
{
	FL_FILE* file; 
	FAT32_ShortEntry sfEntry;

	// Allocate a new file handle
	file = _allocate_file();
	if (!file)
		return NULL;

	// Clear filename
	memset(file->path, '\0', sizeof(file->path));
	memset(file->filename, '\0', sizeof(file->filename));

	// Split full path into filename and directory path
	if (fatfs_split_path((char*)path, file->path, sizeof(file->path), file->filename, sizeof(file->filename)) == -1)
	{
		_free_file(file);
		return NULL;
	}

	// Check if file already open
	if (_check_file_open(file))
	{
		_free_file(file);
		return NULL;
	}

	// If file is in the root dir
	if (file->path[0]==0)
		file->parentcluster = fatfs_get_root_cluster(&Fs);
	else
	{
		// Find parent directory start cluster
		if (!_open_directory(file->path, &file->parentcluster))
		{
			_free_file(file);
			return NULL;
		}
	}

	// Using dir cluster address search for filename
	if (fatfs_get_file_entry(&Fs, file->parentcluster, file->filename, &sfEntry))
	{
		// Initialise file details
		memcpy(file->shortfilename, sfEntry.Name, 11);
		file->filelength = sfEntry.FileSize;
		file->bytenum = 0;
		file->startcluster = (((unsigned long)sfEntry.FstClusHI)<<16) + sfEntry.FstClusLO;
		file->file_data.address = 0xFFFFFFFF;
		file->file_data.dirty = 0;
		file->filelength_changed = 0;
		if (!file->file_data.sector) {
			file->file_data.sector = memalign(FAT_SECTOR_SIZE, FAT_SECTOR_SIZE);
			if (!file->file_data.sector) {
				_free_file(file);
				return NULL;
			}
		}
		memset(file->file_data.sector, 0x00, FAT_SECTOR_SIZE);

		fatfs_fat_purge(&Fs);

		return file;
	}
	else
	{
		_free_file(file);
		return NULL;
	}
}
//-----------------------------------------------------------------------------
// _create_file: Create a new file
//-----------------------------------------------------------------------------
#ifdef FATFS_INC_WRITE_SUPPORT
static FL_FILE* _create_file(const char *filename)
{
	FL_FILE* file; 
	FAT32_ShortEntry sfEntry;
	char shortFilename[11];
	int tailNum;

	// Allocate a new file handle
	file = _allocate_file();
	if (!file)
		return NULL;

	// Clear filename
	memset(file->path, '\0', sizeof(file->path));
	memset(file->filename, '\0', sizeof(file->filename));

	// Split full path into filename and directory path
	if (fatfs_split_path((char*)filename, file->path, sizeof(file->path), file->filename, sizeof(file->filename)) == -1)
	{
		_free_file(file);
		return NULL;
	}

	// Check if file already open
	if (_check_file_open(file))
	{
		_free_file(file);
		return NULL;
	}

	// If file is in the root dir
	if (file->path[0] == 0)
		file->parentcluster = fatfs_get_root_cluster(&Fs);
	else
	{
		// Find parent directory start cluster
		if (!_open_directory(file->path, &file->parentcluster))
		{
			_free_file(file);
			return NULL;
		}
	}

	// Check if same filename exists in directory
	if (fatfs_get_file_entry(&Fs, file->parentcluster, file->filename,&sfEntry) == 1)
	{
		_free_file(file);
		return NULL;
	}

	file->startcluster = 0;

	// Create the file space for the file (at least one clusters worth!)
	if (!fatfs_allocate_free_space(&Fs, 1, &file->startcluster, 1))
	{
		_free_file(file);
		return NULL;
	}

	if (!file->file_data.sector) {
		file->file_data.sector = memalign(FAT_SECTOR_SIZE, FAT_SECTOR_SIZE);
		if (!file->file_data.sector) {
			_free_file(file);
			return NULL;
		}
	}
	memset(file->file_data.sector, 0x00, FAT_SECTOR_SIZE);

	// Generate a short filename & tail
	tailNum = 0;
	do 
	{
		// Create a standard short filename (without tail)
		fatfs_lfn_create_sfn(shortFilename, file->filename);

        // If second hit or more, generate a ~n tail		
		if (tailNum != 0)
			fatfs_lfn_generate_tail((char*)file->shortfilename, shortFilename, tailNum);
		// Try with no tail if first entry
		else
			memcpy(file->shortfilename, shortFilename, 11);

		// Check if entry exists already or not
		if (fatfs_sfn_exists(&Fs, file->parentcluster, (char*)file->shortfilename) == 0)
			break;

		tailNum++;
	}
	while (tailNum < 9999);

	// We reached the max number of duplicate short file names (unlikely!)
	if (tailNum == 9999)
	{
		// Delete allocated space
		fatfs_free_cluster_chain(&Fs, file->startcluster);

		_free_file(file);
		return NULL;
	}

	// Add file to disk
	if (!fatfs_add_file_entry(&Fs, file->parentcluster, (char*)file->filename, (char*)file->shortfilename, file->startcluster, 0, 0))
	{
		// Delete allocated space
		fatfs_free_cluster_chain(&Fs, file->startcluster);

		_free_file(file);
		return NULL;
	}

	// General
	file->filelength = 0;
	file->bytenum = 0;
	file->file_data.address = 0xFFFFFFFF;
	file->file_data.dirty = 0;
	file->filelength_changed = 0;
	
	fatfs_fat_purge(&Fs);

	return file;
}
#endif

//-----------------------------------------------------------------------------
//								External API
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// fl_init: Initialise library
//-----------------------------------------------------------------------------
void fl_init(void)
{	
	int i;

	// Add all file objects to free list
	for (i=0;i<FATFS_MAX_OPEN_FILES;i++)
	{
		Files[i].next = Filelib_free_files;
		Filelib_free_files = &Files[i];
	}

	Filelib_Init = 1;
}
//-----------------------------------------------------------------------------
// fl_attach_locks: 
//-----------------------------------------------------------------------------
void fl_attach_locks(struct fatfs *fs, void (*lock)(void), void (*unlock)(void))
{
	fs->fl_lock = lock;
	fs->fl_unlock = unlock;
}

// MUST HAVE BEEN CHECKED
static int read_sector(UINT32 sector, unsigned char *buffer)
{
	return Fs.disk_io.read_sectors(sector, 1, buffer);	
}
static int write_sector(UINT32 sector, unsigned char *buffer)
{
	return Fs.disk_io.write_sectors(sector, 1, buffer);	
}

//-----------------------------------------------------------------------------
// fl_attach_media: 
//-----------------------------------------------------------------------------
int fl_attach_media(fn_diskio_read rd, fn_diskio_write wr)
{
	int res;

	// If first call to library, initialise
	CHECK_FL_INIT();

	Fs.disk_io.read_sectors = rd;
	Fs.disk_io.write_sectors = wr;
	Fs.disk_io.read_sector = read_sector;
	Fs.disk_io.write_sector = write_sector;

	// Initialise FAT parameters
	if ((res = fatfs_init(&Fs)) != FAT_INIT_OK)
	{
		FAT_PRINTF(("FAT_FS: Error could not load FAT details (%d)!\r\n", res));
		return res;
	}

	Filelib_Valid = 1;
	return FAT_INIT_OK;
}
//-----------------------------------------------------------------------------
// fl_shutdown: Call before shutting down system
//-----------------------------------------------------------------------------
void fl_shutdown(void)
{
	// If first call to library, initialise
	CHECK_FL_INIT();

	FL_LOCK(&Fs);
	fatfs_fat_purge(&Fs);
	FL_UNLOCK(&Fs);
}
//-----------------------------------------------------------------------------
// fopen: Open or Create a file for reading or writing
//-----------------------------------------------------------------------------
void* fl_fopen(const char *path, const char *mode)
{
	int i;
	FL_FILE* file; 
	unsigned char flags = 0;

	// If first call to library, initialise
	CHECK_FL_INIT();

	if (!Filelib_Valid)
		return NULL;

	if (!path || !mode)
		return NULL;
		
	// Supported Modes:
	// "r" Open a file for reading. The file must exist. 
	// "w" Create an empty file for writing. If a file with the same name already exists its content is erased and the file is treated as a new empty file.  
	// "a" Append to a file. Writing operations append data at the end of the file. The file is created if it does not exist. 
	// "r+" Open a file for update both reading and writing. The file must exist. 
	// "w+" Create an empty file for both reading and writing. If a file with the same name already exists its content is erased and the file is treated as a new empty file. 
	// "a+" Open a file for reading and appending. All writing operations are performed at the end of the file, protecting the previous content to be overwritten. You can reposition (fseek, rewind) the internal pointer to anywhere in the file for reading, but writing operations will move it back to the end of file. The file is created if it does not exist. 

	for (i=0;i<(int)strlen(mode);i++)
	{
		switch (tolower(mode[i]))
		{
		case 'r':
			flags |= FILE_READ;
			break;
		case 'w':
			flags |= FILE_WRITE;
			flags |= FILE_ERASE;
			flags |= FILE_CREATE;
			break;
		case 'a':
			flags |= FILE_WRITE;
			flags |= FILE_APPEND;
			flags |= FILE_CREATE;
			break;
		case '+':
			if (flags & FILE_READ)
				flags |= FILE_WRITE;
			else if (flags & FILE_WRITE)
			{
				flags |= FILE_READ;
				flags |= FILE_ERASE;
				flags |= FILE_CREATE;
			}
			else if (flags & FILE_APPEND)
			{
				flags |= FILE_READ;
				flags |= FILE_WRITE;
				flags |= FILE_APPEND;
				flags |= FILE_CREATE;
			}
			break;
		case 'b':
			flags |= FILE_BINARY;
			break;
		}
	}
	
	file = NULL;

#ifndef FATFS_INC_WRITE_SUPPORT
	// No write support!
	flags &= ~(FILE_CREATE | FILE_WRITE | FILE_APPEND);
#endif

	FL_LOCK(&Fs);

	// Read
	if (flags & FILE_READ)
		file = _open_file(path);

	// Create New
	if (!file && (flags & FILE_CREATE))
		file = _create_file(path);

	// Write Existing (and not open due to read or create)
	if (!(flags & FILE_READ))
		if (!(flags & FILE_CREATE))
			if (flags & (FILE_WRITE | FILE_APPEND))
				file = _open_file(path);

	if (file)
		file->flags = flags;

	FL_UNLOCK(&Fs);
	return file;	
}
//-----------------------------------------------------------------------------
// fl_fflush: Flush un-written data to the file
// NB: after serializing clustersize-writes for dma, this call is essentially
// a no-op as the sector-sized buffer is no in use (further optimization is
// possible for small, consecutive writes)
//-----------------------------------------------------------------------------
int fl_fflush(void *f)
{
#ifdef FATFS_INC_WRITE_SUPPORT
	FL_FILE *file = (FL_FILE *)f;

	// If first call to library, initialise
	CHECK_FL_INIT();

	if (file)
	{
		FL_LOCK(&Fs);

		// If some write data still in buffer
		if (file->file_data.dirty)
		{
			// Write back current sector before loading next
			if (fatfs_sector_writer(&Fs, file->startcluster, file->file_data.address, file->file_data.sector)) 
				file->file_data.dirty = 0;
		}

		FL_UNLOCK(&Fs);
	}
#endif
	return 0;
}
//-----------------------------------------------------------------------------
// fl_fclose: Close an open file
//-----------------------------------------------------------------------------
void fl_fclose(void *f)
{
	FL_FILE *file = (FL_FILE *)f;

	// If first call to library, initialise
	CHECK_FL_INIT();

	if (file)
	{
		FL_LOCK(&Fs);

		// Flush un-written data to file
		fl_fflush(f);

		// File size changed?
		if (file->filelength_changed)
		{
#ifdef FATFS_INC_WRITE_SUPPORT
			// Update filesize in directory
			fatfs_update_file_length(&Fs, file->parentcluster, (char*)file->shortfilename, file->filelength);
#endif
			file->filelength_changed = 0;
		}

		file->bytenum = 0;
		file->filelength = 0;
		file->startcluster = 0;
		file->file_data.address = 0xFFFFFFFF;
		file->file_data.dirty = 0;
		file->filelength_changed = 0;

		// Free file handle
		_free_file(file);

		fatfs_fat_purge(&Fs);

		FL_UNLOCK(&Fs);
	}
}
//-----------------------------------------------------------------------------
// fl_fgetc: Get a character in the stream
//-----------------------------------------------------------------------------
int fl_fgetc(void *f)
{
	int res;
	unsigned char data = 0;
	
	res = fl_fread(&data, 1, 1, f);
	if (res == 1)
		return (int)data;
	else
		return res;
}
//-----------------------------------------------------------------------------
// fl_fread: Read a block of data from the file
//-----------------------------------------------------------------------------
int fl_fread(void *buffer, int size, int length, void *f)
{
	unsigned long sector;
	unsigned long offset;
	unsigned long copyCount;
	int count = size * length;
	int bytesRead = 0;
	char *localbuffer;

	FL_FILE *file = (FL_FILE *)f;

	// If first call to library, initialise
	CHECK_FL_INIT();

	if (buffer==NULL || file==NULL)
		return -1;

	// No read permissions
	if (!(file->flags & FILE_READ))
		return -1;

	// Nothing to be done
	if (!count)
		return 0;

	// Check if read starts past end of file
	if (file->bytenum >= file->filelength)
		return 0;

	if (!file->buffer_sectors) {
		int clusterSize = Fs.sectors_per_cluster * FAT_SECTOR_SIZE;
		file->buffer_sectors = memalign(clusterSize, clusterSize);
		// Fatal, no buffer for transfering data
		if (!file->buffer_sectors)
			return -1;
	}

	// Limit to file size
	if ((file->bytenum + count) > file->filelength)
		count = file->filelength - file->bytenum;

	// Calculate start sector
	sector = file->bytenum / FAT_SECTOR_SIZE;

	// Offset to start copying data from first sector
	offset = file->bytenum % FAT_SECTOR_SIZE;

	while (bytesRead < count)
	{
	// Super slow, sector by sector version
#if 0
		// Do we need to re-read the sector?
		if (file->file_data.address != sector)
		{
			// Flush un-written data to file
			if (file->file_data.dirty)
				fl_fflush(file);

			// Read sector of file
			if (!fatfs_sector_reader(&Fs, file->startcluster, sector, file->file_data.sector))
				// Read failed - out of range (probably)
				break;

			file->file_data.address = sector;
			file->file_data.dirty = 0;
		}
		// We have upto one sector to copy
		copyCount = FAT_SECTOR_SIZE - offset;

		// Only require some of this sector?
		if (copyCount > (count - bytesRead))
			copyCount = (count - bytesRead);

		// Copy to application buffer
		memcpy((unsigned char *)((unsigned char *)buffer + bytesRead), (unsigned char *)(file->file_data.sector + offset), copyCount);
	
#else
		int copySectors = Fs.sectors_per_cluster - (sector % Fs.sectors_per_cluster);
		copyCount = copySectors * FAT_SECTOR_SIZE - offset;
		if (copyCount > (length - bytesRead))
			copyCount = (count - bytesRead);
		copySectors = (copyCount + offset) / FAT_SECTOR_SIZE + (offset || (copyCount % FAT_SECTOR_SIZE));

		if (!fatfs_sectors_reader(&Fs, file->startcluster, sector, copySectors, file->buffer_sectors))
			break;

		// Copy to application buffer
		memcpy((unsigned char *)buffer + bytesRead, (unsigned char *)file->buffer_sectors + offset, copyCount);
#endif

		// Increase total read count 
		bytesRead += copyCount;

		// Increment file pointer
		file->bytenum += copyCount;

		// Move onto next sector and reset copy offset
		sector += copySectors;
		offset = 0;
	}	

	return bytesRead;
}
//-----------------------------------------------------------------------------
// fl_fseek: Seek to a specific place in the file
//-----------------------------------------------------------------------------
int fl_fseek( void *f, long offset, int origin )
{
	FL_FILE *file = (FL_FILE *)f;
	int res = -1;

	// If first call to library, initialise
	CHECK_FL_INIT();

	if (!file)
		return -1;

	if (origin == SEEK_END && offset != 0)
		return -1;

	FL_LOCK(&Fs);

	// Invalidate file buffer
	file->file_data.address = 0xFFFFFFFF;
	file->file_data.dirty = 0;

	if (origin == SEEK_SET)
	{
		file->bytenum = (unsigned long)offset;

		if (file->bytenum > file->filelength)
			file->bytenum = file->filelength;

		res = 0;
	}
	else if (origin == SEEK_CUR)
	{
		// Positive shift
		if (offset >= 0)
		{
			file->bytenum += offset;

			if (file->bytenum > file->filelength)
				file->bytenum = file->filelength;
		}
		// Negative shift
		else
		{
			// Make shift positive
			offset = -offset;

			// Limit to negative shift to start of file
			if ((unsigned long)offset > file->bytenum)
				file->bytenum = 0;
			else
				file->bytenum-= offset;
		}

		res = 0;
	}
	else if (origin == SEEK_END)
	{
		file->bytenum = file->filelength;
		res = 0;
	}
	else
		res = -1;

	FL_UNLOCK(&Fs);

	return res;
}
//-----------------------------------------------------------------------------
// fl_fgetpos: Get the current file position
//-----------------------------------------------------------------------------
int fl_fgetpos(void *f , unsigned long * position)
{
	FL_FILE *file = (FL_FILE *)f;

	if (!file)
		return -1;

	FL_LOCK(&Fs);

	// Get position
	*position = file->bytenum;

	FL_UNLOCK(&Fs);

	return 0;
}
//-----------------------------------------------------------------------------
// fl_ftell: Get the current file position
//-----------------------------------------------------------------------------
long fl_ftell(void *f)
{
	unsigned long pos = 0;

	fl_fgetpos(f, &pos);

	return (long)pos;
}
//-----------------------------------------------------------------------------
// fl_feof: Is the file pointer at the end of the stream?
//-----------------------------------------------------------------------------
int fl_feof(void *f)
{
	FL_FILE *file = (FL_FILE *)f;
	int res;

	if (!file)
		return -1;

	FL_LOCK(&Fs);

	if (file->bytenum == file->filelength)
		res = EOF;
	else
		res = 0;

	FL_UNLOCK(&Fs);

	return res;
}
//-----------------------------------------------------------------------------
// fl_fputc: Write a character to the stream
//-----------------------------------------------------------------------------
#ifdef FATFS_INC_WRITE_SUPPORT
int fl_fputc(int c, void *f)
{
	unsigned char data = (unsigned char)c;
	int res;

	res = fl_fwrite(&data, 1, 1, f);
	if (res == 1)
		return c;
	else
		return res;
}
//-----------------------------------------------------------------------------
// fl_fwrite: Write a block of data to the stream
//-----------------------------------------------------------------------------
int fl_fwrite(const void *data, int size, int count, void *f)
{
	FL_FILE *file = (FL_FILE *)f;
	unsigned long sector;
	unsigned long offset;	
	unsigned long length = (size*count);
	unsigned char *buffer = (unsigned char *)data;
	int dirtySector = 0;
	unsigned long bytesWritten = 0;
	unsigned long copyCount;

	// If first call to library, initialise
	CHECK_FL_INIT();

	if (!file)
		return -1;

	FL_LOCK(&Fs);

	// No write permissions
	if (!(file->flags & FILE_WRITE))
	{
		FL_UNLOCK(&Fs);
		return -1;
	}

	if (!file->buffer_sectors) {
		int clusterSize = Fs.sectors_per_cluster * FAT_SECTOR_SIZE;
		file->buffer_sectors = memalign(clusterSize, clusterSize);
		// Fatal, no buffer for transfering data
		if (!file->buffer_sectors) {
			FL_UNLOCK(&Fs);
			return -1;
		}
	}

	// Append writes to end of file
	if (file->flags & FILE_APPEND)
		file->bytenum = file->filelength;
	// Else write to current position

	// Calculate start sector
	sector = file->bytenum / FAT_SECTOR_SIZE;

	// Offset to start copying data from first sector
	offset = file->bytenum % FAT_SECTOR_SIZE;

	while (bytesWritten < length)
	{
	// Super slow, sector by sector version
#if 0
		// We have upto one sector to copy
		copyCount = FAT_SECTOR_SIZE - offset;

		// Only require some of this sector?
		if (copyCount > (length - bytesWritten))
			copyCount = (length - bytesWritten);

		// Do we need to read a new sector?
		if (file->file_data.address != sector)
		{
			// Flush un-written data to file
			if (file->file_data.dirty)
				fl_fflush(file);

			// If we plan to overwrite the whole sector, we don't need to read it first!
			if (copyCount != FAT_SECTOR_SIZE)
			{
				// Read the appropriate sector
				// NOTE: This does not have succeed; if last sector of file
				// reached, no valid data will be read in, but write will 
				// allocate some more space for new data.
				fatfs_sector_reader(&Fs, file->startcluster, sector, file->file_data.sector);
			}

			file->file_data.address = sector;
			file->file_data.dirty = 0;
		}

		// Copy from application buffer into sector buffer
		memcpy((unsigned char *)(file->file_data.sector + offset), (unsigned char *)(buffer + bytesWritten), copyCount);

		// Mark buffer as dirty
		file->file_data.dirty = 1;
#else
		int copySectors = Fs.sectors_per_cluster - (sector % Fs.sectors_per_cluster);
		copyCount = copySectors * FAT_SECTOR_SIZE - offset; 
		if (copyCount > (length - bytesWritten))
			copyCount = (length - bytesWritten);
		copySectors = (copyCount + offset) / FAT_SECTOR_SIZE + (offset || (copyCount % FAT_SECTOR_SIZE));

		// Optimize for cases
		if (!offset && (copyCount % FAT_SECTOR_SIZE)) 
			fatfs_sectors_reader(&Fs, file->startcluster, sector + copySectors - 1, 1, file->buffer_sectors + FAT_SECTOR_SIZE * (copySectors - 1));
		else if (!offset)
			;
		else if (!((copyCount + offset) % FAT_SECTOR_SIZE))
			fatfs_sectors_reader(&Fs, file->startcluster, sector, 1, file->buffer_sectors);
		else {
			fatfs_sectors_reader(&Fs, file->startcluster, sector, 1, file->buffer_sectors);
			if (copySectors > 1)
				fatfs_sectors_reader(&Fs, file->startcluster, sector + copySectors - 1, 1, file->buffer_sectors + FAT_SECTOR_SIZE * (copySectors - 1));
		}

		memcpy((unsigned char *)file->buffer_sectors + offset, (unsigned char *)buffer + bytesWritten, copyCount);

		// Flush all immediately
		fatfs_sectors_writer(&Fs, file->startcluster, sector, copySectors, file->buffer_sectors);
#endif
	
		// Increase total read count 
		bytesWritten += copyCount;

		// Increment file pointer
		file->bytenum += copyCount;

		// Move onto next sector and reset copy offset
		sector += copySectors;
		offset = 0;
	}

	// Write increased extent of the file?
	if (file->bytenum > file->filelength)
	{
		// Increase file size to new point
		file->filelength = file->bytenum;

		// We are changing the file length and this 
		// will need to be writen back at some point
		file->filelength_changed = 1;
	}

	FL_UNLOCK(&Fs);

	return bytesWritten;
}
//-----------------------------------------------------------------------------
// fl_fputs: Write a character string to the stream
//-----------------------------------------------------------------------------
int fl_fputs(const char * str, void *f)
{
	int len = (int)strlen(str);
	int res = fl_fwrite(str, 1, len, f);

	if (res == len)
		return len;
	else
		return res;
}
//-----------------------------------------------------------------------------
// fl_remove: Remove a file from the filesystem
//-----------------------------------------------------------------------------
int fl_remove( const char * filename )
{
	FL_FILE* file;
	int res = -1;

	FL_LOCK(&Fs);

	// Use read_file as this will check if the file is already open!
	file = fl_fopen((char*)filename, "r");
	if (file)
	{
		// Delete allocated space
		if (fatfs_free_cluster_chain(&Fs, file->startcluster))
		{
			// Remove directory entries
			if (fatfs_mark_file_deleted(&Fs, file->parentcluster, (char*)file->shortfilename))
			{
				// Close the file handle (this should not write anything to the file
				// as we have not changed the file since opening it!)
				fl_fclose(file);

				res = 0;
			}
		}
	}

	FL_UNLOCK(&Fs);

	return res;
}
#endif
//-----------------------------------------------------------------------------
// fl_listdirectory: List a directory based on a path
//-----------------------------------------------------------------------------
void fl_listdirectory(const char *path)
{
	int levels;
	UINT32 cluster = FAT32_INVALID_CLUSTER;

	// If first call to library, initialise
	CHECK_FL_INIT();

	FL_LOCK(&Fs);

	levels = fatfs_total_path_levels((char*)path) + 1;

	// If path is in the root dir
	if (levels == 0)
		cluster = fatfs_get_root_cluster(&Fs);
	// Find parent directory start cluster
	else
		_open_directory((char*)path, &cluster);

	if (cluster != FAT32_INVALID_CLUSTER)
		fatfs_list_directory(&Fs, cluster);

	FL_UNLOCK(&Fs);
}
//-----------------------------------------------------------------------------
// fl_createdirectory: Create a directory based on a path
//-----------------------------------------------------------------------------
int fl_createdirectory(const char *path)
{
	int res;

	// If first call to library, initialise
	CHECK_FL_INIT();

	FL_LOCK(&Fs);
	res =_create_directory((char*)path);
	FL_UNLOCK(&Fs);

	return res;
}
//-----------------------------------------------------------------------------
// fl_getdirectory_n: Copy the nth entry in a directory into parameter name
// @return 1 if found, 0 if not
//-----------------------------------------------------------------------------
#ifndef NONEXUS
int fl_getdirectory_n(const char *filepath, unsigned long offset, char *name)
{
	char *_name;
	unsigned long cluster;

	// If first call to library, initialise
	CHECK_FL_INIT();

	// do call
	FL_LOCK(&Fs);
	cluster = fl_opendirectory(filepath);
	if (cluster && cluster != FAT32_INVALID_CLUSTER)
		_name = fatfs_get_directory_n(&Fs, cluster, offset);
	else
		_name = NULL;
	FL_UNLOCK(&Fs);

	if (_name == NULL)
		return 0;

	memcpy(name, _name, strlen(_name) + 1);
	return 1;
}
//-----------------------------------------------------------------------------
// fl_isdirectory: Check whether a file is a directory
// @return 1 if dir, 0 if file, -1 on error
//-----------------------------------------------------------------------------
int fl_isdirectory(const char *parentpath, const char *filename)
{
	int ret = -1;
	unsigned long cluster;

	// If first call to library, initialise
	CHECK_FL_INIT();

	// do call
	FL_LOCK(&Fs);
	cluster = fl_opendirectory(parentpath);
	if (cluster && cluster != FAT32_INVALID_CLUSTER)
		ret = fatfs_is_directory(&Fs, cluster, filename);
	FL_UNLOCK(&Fs);

	return ret;
}
//-----------------------------------------------------------------------------
// fl_fcluster: Extracts the start cluster number of a file 
// @return cluster number
//-----------------------------------------------------------------------------
unsigned long
fl_fcluster(void *file)
{
	struct sFL_FILE *_file = file;

	return _file->startcluster;
}
//-----------------------------------------------------------------------------
// fl_fsize: Get the size (total bytes) of a file
// @return file size
//-----------------------------------------------------------------------------
unsigned long
fl_fsize(void *file)
{
	FL_FILE *_file = file;

	return _file->filelength;
}
//-----------------------------------------------------------------------------
// fl_getpartitionsize: Get the total usable number of data bytes within
//                      this partition
// @return number of bytes 
//-----------------------------------------------------------------------------
unsigned long long fl_getpartitionsize(void)
{
	unsigned long ret = 0;
	CHECK_FL_INIT();

	FL_LOCK(&Fs);
	ret = Fs.total_bytes;	
	FL_UNLOCK(&Fs);

	return ret;
}
//-----------------------------------------------------------------------------
// fl_truncate: Modify the file length, pad null bytes if length increases
// @return 0 on success -1 on error
//-----------------------------------------------------------------------------
int fl_truncate(void *file, int newlength)
{
	int i;
	FL_FILE *_file = file;
	char *buf = "\0";

	if (_file->filelength < newlength) {
		if (fl_fseek(file, _file->filelength, SEEK_SET))
			return -1;
		// Zero out the extra bytes
		for (i = 0; i < newlength - _file->filelength; i++)
			fl_fwrite(buf, 1, 1, file);

	}

	_file->filelength = newlength;
	return 0;
}
#endif
