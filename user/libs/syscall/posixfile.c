/** NexusOS: implementation of common Posix IO file operations.
             This file reflects equivalents of open(..), .. to Nexus FS.svc */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <dirent.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <asm/ioctls.h>

#include <nexus/vector.h>
#include <nexus/util.h>
#include <nexus/init.h>
#include <nexus/test.h>
#include <nexus/fs.h>
#include <nexus/fs_path.h>
#include <nexus/FS.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/linuxcalls_io.h>

#include "io.private.h"

// process's current directory ($PWD)
Path curr_directory;

typedef struct FileDescriptor {
  FSID node; 	
  unsigned long long file_position;
  unsigned long flags;
  int supports_pin:1; 	// some filesystems don't support pin/unpin, so don't bother with them
  int has_path:1; 	// open files have no path, open directories keep a path
  int needs_sync:1; 	// sync on close? only for writable files.
  Path path; 
} FileDescriptor;


void posix_file_init(void) 
{
  if (!__disable_filesystem) {
    if (nexusfs_mount(FSID_EMPTY, FSID_ROOT(KERNELFS_PORT)))
	    fprintf(stderr, "Failed to mount root filesystem\n");
  }

  Path_new(&curr_directory);
}

void posix_chroot(void)
{
  Path_new(&curr_directory);	// memleak?
}

/** @param error is the errno value to return if returnvalue is NULL */
static FileDescriptor *
_posix_open(const char *name, int flags, mode_t mode, int *error) 
{
  FileDescriptor *desc;
  Path path;
  FSID rv;
  int rc, created = 0;

  // unsupported flags: not critical so do not warn and continue
  // if (flags & (O_NDELAY | O_NOCTTY | O_SYNC))

  // unsupported flags that are critical: fail
  if (unlikely(flags & O_ASYNC)) {
    *error = -EACCES;
    fprintf(stderr, "open(%s): asynchronous I/O not supported\n", name);
    return NULL;
  }

  if (unlikely(flags & O_CREAT)) {

    // lookup the inode
    rc = Path_resolve1(&path, &curr_directory, name);
    switch (rc) {
      case 0:			break; // no error
      case -FS_NOTDIR: 		*error = -ENOTDIR; return NULL;
      case -FS_ACCESSERROR:	*error = -EFAULT; return NULL;
      default:			*error = -EACCES; return NULL;
    }

    // successful lookup of parent and no node? create
    if (!FSID_isValid(Path_last(&path)->node)) {
    
      // create the inode
      if (flags & O_DIRECTORY) {
        fprintf(stderr, "create directory with open() forbidden");
	return NULL;
      }

      rv = nexusfs_mk(Path_lastparent(&path)->node, Path_last(&path)->fname, NULL);
      if (!FSID_isFile(rv)) {
	      Path_clear(&path);
	      *error = -EACCES;
	      return NULL;
      }

      // extend path
      if (!rc)
	Path_last(&path)->node = rv;
      created = 1;
    } 
    else 
      // fail if O_CREAT and O_EXCL are given, but the file already exists
      if (flags & O_EXCL) {
        *error = -EEXIST;
        return NULL;
      }

  } else {
    // lookup path: all elements must exit
    rc = Path_resolve(&path, &curr_directory, name);
    switch (rc) {
      case 0:			break; // no error
      case -FS_NOTFOUND:	*error = -ENOENT; return NULL;	
      case -FS_NOTDIR: 		*error = -ENOTDIR; return NULL;
      case -FS_ACCESSERROR:	*error = -EFAULT; return NULL;
      default:			printf("nxdebug: %s unknown error %d\n", name, rc);
				*error = -EACCES; return NULL;
    }
  }

  PathComponent *file = Path_last(&path);
  FSID fsid = file->node;
  int isdir = FSID_isDir(fsid);

  // verify flags
  if (!isdir && (flags & O_DIRECTORY)) {
    Path_clear(&path);
    *error = -ENOTDIR; 
    return NULL;
  }

  // if a mountpoint, resolve mounted directory
  if (isdir & !(flags & O_CREAT)) {
	  PathComponent *parent_fsid;

	  parent_fsid = Path_lastparent(&path);
	  if (parent_fsid && FSID_isDir(parent_fsid->node)) {
	  	fsid = nexusfs_lookup_resolvelink(parent_fsid->node, 
					          Path_last(&path)->fname);
		Path_last(&path)->node = fsid;
	  }
  }

  // pin
  // this stops an unlink request from removing the inode until we close the 
  // file, as Posix dictates. Semantics are correct IFF pin is supported by 
  // the backend filesystem. 
  if (FS_Pin_ext(fsid.port, fsid)) {
    Path_clear(&path);
    *error = -EACCES;
    return NULL;
  }

  // truncate if O_TRUNC is given (and environment is correct)
  if ((flags & O_TRUNC) && !created && !isdir && 
      ((flags & O_WRONLY) || (flags & O_RDWR))) {
    if (nexusfs_truncate(fsid, 0)) {
      Path_clear(&path);
      *error = -EACCES;
      return NULL;
    }
  }

  // create open-file structure 
  desc = calloc(1, sizeof(FileDescriptor));
  desc->node = fsid;
  desc->supports_pin = 0;
  desc->has_path = isdir;
  desc->flags = flags;
  desc->needs_sync = (flags & O_WRONLY || flags & O_RDWR) ? 1 : 0;
  if (isdir) 
	  desc->path = path;
  else 
	  Path_clear(&path);
  if (flags & O_APPEND)
  	desc->file_position = FS_Size_ext(fsid.port, fsid);
  else
  	desc->file_position = 0;

  return desc;
}

static int 
posix_open(GenericDescriptor *d, const char *name, int flags, mode_t mode) 
{
  FileDescriptor *desc; 
  int error;

  desc = _posix_open(name, flags, mode, &error);
  if (!desc)
	return error;
  
  d->private = desc;
  return 0;
}

static int 
posix_size(GenericDescriptor *d) 
{
  FileDescriptor *desc; 
  int ret;

  assert(d); // debug XXX remove
  desc = d->private;
  
  ret = FS_Size_ext(desc->node.port, desc->node);
  if (ret < 0)
    return -EINVAL;
  
  return ret;
}

static int 
posix_fsync(GenericDescriptor *d) 
{
  FileDescriptor *desc;
  int ret;

  desc = d->private;
  ret = FS_Sync_ext(desc->node.port, desc->node);
  if (ret < 0)
    return -EINVAL;
  
  return ret;
}

static ssize_t 
posix_pread(GenericDescriptor *d, void *buf, size_t count, off_t offset)
{
  FileDescriptor *desc;
  int len;
	  
  desc = d->private;

  // verify input
  if (count < 0)
    return -EINVAL;
  if (!count) 
    return 0;

  len = FS_Read_ext(desc->node.port, desc->node, offset,
     	           (struct VarLen) {.data = buf, .len = count}, count);
 
  // verify reply
  if (len < 0) {
    fprintf(stderr, "posix read error #2: off=%ld len=%d\n", offset, len);
    return -EINVAL;
  }

  return len;
}


static ssize_t 
posix_read(GenericDescriptor *d, void *buf, size_t count) 
{
  FileDescriptor *desc;
  int len;
	  
  desc = d->private;

  len = posix_pread(d, buf, count, desc->file_position);
  if (len > 0)
  	desc->file_position += len;

  return len;
}

static int
posix_port(GenericDescriptor *d)
{
  FileDescriptor *desc;

  desc = d->private;
  return desc->node.port;  
}

static int 
posix_ioctl(GenericDescriptor *d, int flag, void *data) 
{
  // this is not a terminal
  if (flag == TCGETS || flag == TCSETS)
	  return -ENOTTY;

  // not supported
  fprintf(stderr, "[file] ioctl %d not supported\n", flag);
  return -EINVAL;
}

#define MAX_NAMESPACE_WRITE_LEN 4096
static ssize_t 
posix_pwrite(GenericDescriptor *d, const void *buf, size_t count, off_t off) 
{
  FileDescriptor *desc;
  int written = 0;
  int len = 0;
  
  if (count < 0)
    return -EINVAL;
  if (!count)
    return 0;

  desc = d->private;
  int position = off;

  while(written < count) {
    int size = min(((int)count - written),MAX_NAMESPACE_WRITE_LEN);

    struct VarLen data_region;
    data_region.data = (char *)buf + written;
    data_region.len = size;

    len = FS_Write_ext(desc->node.port, desc->node, position, data_region, size);

    if (len < 0) {
      if (written > 0)
	return written;
      else
        return -EINVAL;
    }
    
    position += len;
    written += len;
  }
  return written;
}

static ssize_t 
posix_write(GenericDescriptor *d, const void *buf, size_t count) 
{
  FileDescriptor *desc = d->private;
  ssize_t ret;

  ret = posix_pwrite(d, buf, count, desc->file_position);
  if (ret > 0)
    desc->file_position += ret;

  return ret;
}

// close one among possibly many dup'd handles
static int 
posix_close(GenericDescriptor *d) 
{
  FileDescriptor *desc = d->private;
  int do_sync;
  
  do_sync = (FSID_isFile(desc->node) && desc->needs_sync) ? 1 : 0;
  if (FS_Unpin_ext(desc->node.port, desc->node, do_sync))
    return -EIO;

  return 0;
}

// close the last handle
static int 
posix_destroy(GenericDescriptor *d) 
{
  FileDescriptor *desc; 
  
  desc = d->private;
  assert(desc); // debug XXX remove
  
  if (desc->has_path) 
    Path_clear(&desc->path);
  
  free(desc);
  d->private = NULL;
  return 0;
}

/** Posix requires lseek to allow seeking beyond end-of-file, in which
    case a subsequent write will fill in intermediate bytes with 0. For
    simplicity, this implementation deviates and already extend file at lseek().

    NB: files are not sparse.

     */
static __off_t 
posix_lseek(GenericDescriptor *d, __off_t offset, int whence) 
{
  FileDescriptor *desc;
  int len;

  desc = d->private;
  switch (whence) {
    case SEEK_SET: desc->file_position = offset; break;
    case SEEK_CUR: desc->file_position += offset; break;
    case SEEK_END: desc->file_position = posix_size(d) + offset; break;
    default:
      fprintf(stderr, "lseek: incorrect whence. Did you swap parameters?\n");
      return -EINVAL;
  };

  // extend file if seek beyond EOF
  len = FS_Size_ext(desc->node.port, desc->node);
  if (desc->file_position > len)
	  FS_Truncate_ext(desc->node.port, desc->node, desc->file_position);

  return desc->file_position;
}

static int 
posix_fcntl(GenericDescriptor *d, int cmd, long arg)
{
  FileDescriptor *desc = d->private;

  switch(cmd) {
	case F_GETFL: return desc->flags;
	case F_SETFL: desc->flags = arg; return 0;
	case F_GETFD:
	case F_SETFD:
	case F_GETSIG:
	case F_SETSIG:
	case F_SETLK:
	case F_SETOWN:	return 0;	
	case F_GETOWN:	return 1; /* fake a pid */
	case F_GETLEASE: return F_UNLCK;
  	default :
		fprintf(stderr, "NXLIBC posix fcntl: unsupported %d\n", cmd);
		return -EINVAL;
  }
}

static int 
posix_poll(GenericDescriptor *d, int dir)
{
	return dir;
}

static int 
posix_unsupported(GenericDescriptor *d, const char *opname, int is_sock) 
{
  printf("Posix '%s()' unsupported!\n", opname);
  if (is_sock)
    return -ENOTSOCK;
  else
    return -EINVAL;
}

GenericDescriptor_operations File_ops = {
  .name = "file",
  .unsupported = posix_unsupported,

  .open = posix_open,
  .destroy = posix_destroy,

  .pread = posix_pread,
  .pwrite = posix_pwrite,
  .read = posix_read,
  .write = posix_write,
  .lseek = posix_lseek,
  .close = posix_close,

  .fsync = posix_fsync,
  .fcntl = posix_fcntl,
  .ioctl = posix_ioctl,
  .size = posix_size,
  .poll = posix_poll,
};


// remainder of this file implements posix-style directory handling

char * 
nxlibc_syscall_getcwd(char *buf, int size)
{
	char *pathstring;
	int pathlen;

	pathstring = Path_string(&curr_directory) + 1 /* skip double slash */;
	pathlen = strlen(pathstring);

	// posix spec: return error if exceeds size
	if (size > 0 && pathlen + 1 > size)
		return NULL;

	if (!buf) {
		if (size <= 0 || size > NAME_MAX)
			size = NAME_MAX + 1;
		buf = malloc(size);
	}

	// create private copy of curr_directory
	strcpy(buf, pathstring);
	return buf;
}

int 
nxlibc_syscall_chdir(const char *filename) {
  FileDescriptor *desc;
  Path *olddir;
  int error;

  desc = _posix_open(filename, O_DIRECTORY, O_RDONLY, &error); 
  if (!desc)
    return error;

  // switch current directory ($PWD)
  // (minor) race condition. XXX use locking
  Path_clear(&curr_directory);
  Path_dup(&curr_directory, &desc->path);

  free(desc);
  return 0;
}

int 
nxlibc_syscall_mkdir(const char *name, mode_t mode) 
{
  Path path;

  int rc = Path_resolve1(&path, &curr_directory, name);

  // error: parent not found or not a directory 
  if (rc) {
    if (rc == -FS_NOTDIR)
      return -ENOTDIR;
    else
      return -EACCES;
  } 
  
  // error: node exists
  if (FSID_isValid(Path_last(&path)->node)) {
    Path_clear(&path);
    return -EEXIST;
  }

  // lookup parent
  FSID parent = Path_lastparent(&path)->node;
  char *fname = Path_last(&path)->fname;
  Path_clear(&path);

  // create child
  FSID rv = nexusfs_mkdir(parent, fname);

  // error handling
  rc = FSID_getError(rv);
  switch (rc) {
  	case 0: break;
	case -FS_NOTDIR:	return -ENOTDIR;
	case -FS_ACCESSERROR:	return -EFAULT;
	default:		return -EACCES;
  }

  return 0;
}

/** original Nexus mount: mounts the filesystem with ID target at unixpath. 
    NB: should not be called directly. Use regular posix mount(..) instead.

    @param unixpath gives the directory where the fs is to be mounted 
    @param target contains a Nexus filesystem ID */
static int 
__nxlibc_syscall_mount(const char *unixpath, FSID child) 
{
  FSID parent, fsold;
  Path path;
  int rc;
 
  rc = Path_resolve1(&path, &curr_directory, unixpath);
  switch (rc) {
      case 0:			break;
      case -FS_NOTDIR:		return -ENOTDIR;
      case -FS_ACCESSERROR:	return -EFAULT;
      default:			return -EACCES;
  }

  parent = Path_last(&path)->node;
  if (!FSID_isValid(parent)) 
    return -ENOENT;
  if (!FSID_isDir(parent)) 
    return -ENOTDIR;

  rc = nexusfs_mount(parent, child);
  Path_clear(&path);

  if (rc)
    return -EACCES;

  return 0;
}

/** posix conformant mount definition; argument handling is NOT conformant. 
 
    @param source accepts an IPC port number in string form, e.g., "1234" 
    @param target gives a destination directory to mount the volume */
int nxlibc_syscall_mount(const char *source, const char *target,
		         const char *filesystemtype, unsigned long mountflags,
			 const void *data) 
{
	long port_num;

	port_num = strtol(source, NULL, 10);
	return __nxlibc_syscall_mount(target, FSID_ROOT(port_num));

}

/// Nexus equivalent of dirent. 
//  Embeds a conformant struct dirent to give to clients
struct __dirstream { 
  int fd;
  int offset;
  int done:1;
  struct dirent entry;	///< returned to user
};

DIR *
nxlibc_syscall_opendir(const char *dirname) 
{
  DIR *rv;
  int fd;
  
  fd = nxlibc_syscall_open(dirname, O_DIRECTORY, O_RDONLY);
  if (fd < 0)
    return NULL;

  rv = calloc(1, sizeof(struct __dirstream));
  rv->fd = fd;
  return rv;
}

struct dirent *
nxlibc_syscall_readdir(DIR *dirstream) 
{
  struct VarLen data;
  GenericDescriptor *d;
  FileDescriptor *desc;
  int ret;

  // special case: did last call say that we are done?
  if (dirstream->done)
    return NULL;

  d = nxdesc_find(dirstream->fd);
  if (!d) {
    errno = EBADF; // XXX uclibc may override this on return
    return NULL;
  }

  // ask the FS for this item
  desc = d->private;
  data.data = dirstream->entry.d_name;
  data.len = sizeof(dirstream->entry.d_name);
  ret = FS_ReadDir_ext(desc->node.port, desc->node, data, dirstream->offset);
  if (ret < 0) {
    nxdesc_put(d);
    errno = EINVAL; // XXX uclibc may override this on return
    return NULL;
  }

  // special case: return value is 0 indicates there are no more items to process
  if (ret == 0)
    dirstream->done = 1;
  dirstream->offset++;

  nxdesc_put(d);
  return &dirstream->entry;
}

void 
nxlibc_syscall_rewinddir(DIR *dir) 
{
  dir->offset = 0;
  dir->done = 0;
}

int 
nxlibc_syscall_closedir(DIR *dirstream) 
{
  int err = close(dirstream->fd);
  free(dirstream);
  return err;
}

int 
nxlibc_syscall_unlink(const char *pathname) 
{
  FSID fsid, fsold;
  Path path;
  int rc;
 
  rc = Path_resolve1(&path, &curr_directory, pathname);
  if (rc) {
    Path_clear(&path);
    return -EFAULT;
  }

  rc = nexusfs_unlink(Path_lastparent(&path)->node, Path_last(&path)->fname);
  Path_clear(&path);
  return rc;
}

int 
nxlibc_syscall_rmdir(const char *dirname)
{
	return nxlibc_syscall_unlink(dirname);
}

int 
nxlibc_syscall_rename(const char *oldpathstr, const char *newpathstr) 
{
  FSID oldnode, newparent;
  const char *newfilestr;
  Path path, newpath;

  if (Path_resolve(&path, &curr_directory, oldpathstr)) {
    Path_clear(&path);
    return -ENOENT;
  }

  if (Path_resolve1(&newpath, &curr_directory, newpathstr)) {
    Path_clear(&path);
    return -ENOENT;
  }

  // find last element of new path
  newfilestr = strrchr(newpathstr, '/');
  if (newfilestr) {
	  newfilestr++;	// skip the '/' itself
	  newparent = Path_lastparent(&newpath)->node;
  }
  else {
	  newfilestr = newpathstr;
	  newparent = Path_last(&curr_directory)->node;
  }

  // call filesystem's rename() implementation
  oldnode = Path_last(&path)->node;
  errno = nexusfs_rename(oldnode, newparent, newfilestr);
  Path_clear(&path);
  Path_clear(&newpath);
 
  return errno ? -errno : 0;
}

int 
nxlibc_syscall_chmod(const char *pathname, mode_t mode) 
{
  // noop as we do not use unix permissions
  return 0;
}

////////  Support  ////////

/** Lookup an FSID by a file descriptor. 
    Only works for posixfiles */
FSID nxcall_fsid_get(int fd)
{
  GenericDescriptor *d;
  FileDescriptor *desc;
  
  d = nxdesc_find(fd);
  if (!d || d->ops != &File_ops) 
	  return FSID_ERROR(FS_INVALID);
  
  desc = d->private;
  return desc->node;
}

/** Lookup an FSID by a filepath */
FSID nxcall_fsid_byname(const char *filepath)
{
  Path path;
  PathComponent *file;

  if (Path_resolve(&path, &curr_directory, filepath))
	  return FSID_ERROR(FS_INVALID);

  file = Path_last(&path);
  return file->node;
}


