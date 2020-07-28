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

#include <nexus/vector.h>
#include <nexus/util.h>
#include <nexus/init.h>
#include <nexus/fs.h>
#include <nexus/fs_path.h>
#include <nexus/FS.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/RamFS.interface.h>
#include <nexus/linuxcalls_io.h>

#include "io.private.h"

#define ReturnError(code) do { errno = code; return -1; } while (0)

static const int dbg_posixfile = 0;
#define printf_dbg(x...) do { if (dbg_posixfile) printf(x); } while (0)
#define FAILRETURN(retval, ...) \
  do { \
    printf_dbg("%s:%d ", __FILE__, __LINE__); \
    printf_dbg( __VA_ARGS__); \
    printf_dbg("\n"); \
    return (retval); \
  } while (0)

FSID curr_fs_root;
Path curr_directory;
int curr_directory_supports_pin;

typedef struct FileDescriptor {
  FSID node; // will be pinned
  Connection_Handle h;
  unsigned long long file_position;
  int append_mode; // writes go at the end, rather than using file_position
  int supports_pin; // some filesystems don't support pin/unpin, so don't bother with them
  int has_path; // open files have no path, open directories keep a path
  Path path; 
} FileDescriptor;


void posix_file_init(void) 
{
  if (!__disable_filesystem) {
    curr_fs_root = FSID_ROOT(KERNELFS_PORT);
    if (nexusfs_mount(FSID_EMPTY, curr_fs_root))
	    fprintf(stderr, "Failed to mount filesystem\n");
  }

  Path_new(&curr_directory, curr_fs_root);
  curr_directory_supports_pin = 0;	// don't pin the root
}

int posix_check_flags(int fd, int flags) {
  /* XXX check to make sure the flags for fd = flags.  It is needed
   * by fdopen.  We currently do not pay attention to any of the flags (except
   * for O_TRUNC, O_CREAT, and O_APPEND on open) */
  return 0;
}

static FileDescriptor *_posix_open(const char *name, int flags, mode_t mode) {
  Path path;
  int rc, error, created;

  if (flags & (O_NONBLOCK | O_NDELAY /* | O_NOFOLLOW | O_DIRECTORY */)) {
    //dump_stack_trace(NULL);
    FAILRETURN(NULL, "unhandled O-flag: 0x%x", flags);
  }
  if (flags & (O_NOCTTY | O_SYNC | O_ASYNC /* | O_DIRECT | O_LARGEFILE */)) {
    FAILRETURN(NULL, "unhandled O-flag: 0x%x", flags);
  }

  created = 0;
  if (flags & O_CREAT) {
    FSID rv;

    rc = Path_resolve1(&path, curr_fs_root, &curr_directory, name);
    if (!rc && !FSID_isValid(Path_last(&path)->node)) {

      // create the inode
      if (flags & O_DIRECTORY)
        FAILRETURN(NULL, "create directory with open() forbidden");
      else
        rv = nexusfs_mk(Path_lastparent(&path)->node, Path_last(&path)->fname, NULL);
      rc = FSID_getError(rv);

      // extend path
      if (!rc)
	Path_last(&path)->node = rv;
      else
	Path_clear(&path);
      created = 1;
    } 
    else if (!rc && (flags & O_EXCL)) {
      Path_clear(&path);
      errno = EEXIST;
      FAILRETURN(NULL, "path exists");
    }
  } else {
    rc = Path_resolve(&path, curr_fs_root, &curr_directory, name);
  }

  if (rc) {
    if (rc == -FS_NOTDIR) errno = ENOTDIR;
    else if (rc == -FS_ACCESSERROR) errno = EFAULT;
    else errno = EACCES;
    FAILRETURN(NULL, "problem resolving path");
  }

  FSID fsid = Path_last(&path)->node;
  int isdir = FSID_isDir(fsid);

  // verify flags
  if (!isdir && (flags & O_DIRECTORY)) {
    Path_clear(&path);
    errno = ENOTDIR;
    FAILRETURN(NULL, "not dir");
  } else if (isdir && !(flags & O_DIRECTORY)) {
    Path_clear(&path);
    errno = EISDIR;
    FAILRETURN(NULL, "is dir");
  } 

  // resolve mountpoint
  if (isdir & !(flags & O_CREAT)) {
	  PathComponent *parent_fsid;

	  parent_fsid = Path_lastparent(&path);
	  if (parent_fsid && FSID_isDir(parent_fsid->node)) {
	  	fsid = nexusfs_lookup_mount(parent_fsid->node, Path_last(&path)->fname);
		Path_last(&path)->node = fsid;
	  }
  }

  rc = nexusfs_pin(fsid);
  if (rc < 0) {
    Path_clear(&path);
    errno = EACCES;
    FAILRETURN(NULL, "can't pin (rc = %d)", rc);
  } 
  int pin_supported = (rc > 0);
  
  if (!created && !isdir && (flags & O_TRUNC) && ((flags & O_WRONLY) || (flags & O_RDWR))) {
    // try to truncate the file
    rc = nexusfs_truncate(fsid, 0);
    if (rc != 0) {
      Path_clear(&path);
      if (pin_supported) 
	      nexusfs_unpin(fsid);
      errno = EACCES;
      FAILRETURN(NULL, "can't truncate");
    }
  }

  // create open file structure 
  FileDescriptor *desc = calloc(1, sizeof(FileDescriptor));
  desc->node = fsid;
  desc->file_position = 0;
  desc->h = nexusfs_getmount(fsid);
  desc->append_mode = !!(flags & O_APPEND);
  desc->supports_pin = pin_supported;
  desc->has_path = isdir;
  if (isdir) 
	  desc->path = path;
  else 
	  Path_clear(&path);
  return desc;
}

static int posix_open(GenericDescriptor *d, const char *name, int flags, mode_t mode) {
  FileDescriptor *desc = _posix_open(name, flags, mode);
  if (!desc)
    FAILRETURN(-1, "can't open");
  d->private = desc;
  return 0;
}

static int posix_size(GenericDescriptor *d) {
  if (d == NULL) {
    errno = EBADF;
    return -1;
  }
  FileDescriptor *desc = d->private;
  int ret = FS_Size_ext(desc->h, desc->node);
  if(ret < 0) {
    errno = EINVAL;
    return -1;
  }
  return ret;
}

static int posix_fsync(GenericDescriptor *d) {
  if (d == NULL) {
    errno = EBADF;
    return -1;
  }
  FileDescriptor *desc = d->private;
  int ret = FS_Sync_ext(desc->h, desc->node);
  if(ret < 0) {
    errno = EINVAL;
    return -1;
  }
  return ret;
}

static ssize_t posix_read(GenericDescriptor *d, void *buf, size_t count) {
  FileDescriptor *desc;
  ssize_t read;
  int len;
	  
  desc = d->private;

  // verify input
  if (count < 0) {
    errno = EINVAL;
    return -1;
  }
  if (!count)
    return 0;


  read = 0;
  while (read < count) {
    // read
    len = FS_Read_ext(desc->h, desc->node, desc->file_position, 
		      (struct VarLen) {.data = buf + read, .len = count - read}, count - read);

    // verify reply
    if (len < 0) {
      errno = EINVAL;
      return -1;
    } 
    if (!len)	// EOF
      break;

    // update offsets
    desc->file_position += len;
    read += len;
  }

  return read;
}

static int posix_ioctl(GenericDescriptor *d, int flag, void *data) {
  // not supported
  return -1;
}

//#define MAX_NAMESPACE_WRITE_LEN 1048576
#define MAX_NAMESPACE_WRITE_LEN 4096
static ssize_t posix_write(GenericDescriptor *d, const void *buf, size_t count) {
  printf_dbg("in posix_write(%p, %d)\n", buf, count);

  if(count == 0)
    return 0;
  if (count < 0) {
    errno = EINVAL;
    return -1;
  }

  FileDescriptor *desc = d->private;

  int written = 0;
  int len = 0;

  int position = (desc->append_mode ? posix_size(d) : desc->file_position);

  while(written < count){
    int size = min(((int)count - written),MAX_NAMESPACE_WRITE_LEN);

    struct VarLen data_region;
    data_region.data = (char *)buf + written;
    data_region.len = size;

    //printf_dbg("Namespace_Write %lld 0x%p %d -> len %d\n", position, data_region.data, data_region.len,len);
    printf_dbg("namespace write %d", __LINE__);
    len = FS_Write_ext(desc->h, desc->node, position, data_region, size);

    if(len < 0) {
      if (written > 0) {
	printf_dbg("aborting posix_write(%p, %d) with %d bytes written\n", buf, count, written);
	return written;
      } else {
	printf_dbg("aborting posix_write(%p, %d) with no bytes written\n", buf, count);
	errno = EINVAL;
	return -1;
      }
    }
    position += len;
    if (!desc->append_mode)
      desc->file_position = position;

    written += len;
    printf_dbg("status of posix_write(%p, %d) : %d bytes written\n", buf, count, written);
  }
  return written;
}

// close one among possibly many dup'd handles
static int posix_close(GenericDescriptor *d) {
  FileDescriptor *desc = d->private;
  if (!desc)
    return -1;
  if (FSID_isFile(desc->node))
    FS_Sync_ext(desc->h, desc->node);
  return 0;
}

// close the last handle
static int posix_destroy(GenericDescriptor *d) {
  FileDescriptor *desc = d->private;
  if (!desc)
    return -1;
  if (FSID_isFile(desc->node))
    FS_Sync_ext(desc->h, desc->node);
  if (desc->has_path) Path_clear(&desc->path);
  free(desc);
  d->private = NULL;
  return 0;
}

static __off_t posix_lseek(GenericDescriptor *d, __off_t offset, int whence) {
  FileDescriptor *desc = d->private;
  if (!desc) {
    errno = -EBADF;
    FAILRETURN(-1, "bad fd");
  }

  switch (whence) {
    case SEEK_SET: return desc->file_position = offset;
    case SEEK_CUR: return desc->file_position += offset;
    case SEEK_END: return desc->file_position = posix_size(d) + offset;    
    default:
      errno = EINVAL;
      FAILRETURN(-1, "seek");
  };
}

static int posix_unsupported(GenericDescriptor *d, const char *opname, int is_sock) {
  printf("Posix '%s()' unsupported!\n", opname);
  if(is_sock) {
    errno = ENOTSOCK;
  } 
  return -1;
}

GenericDescriptor_operations File_ops = {
  .unsupported = posix_unsupported,
  .open = posix_open,
  .destroy = posix_destroy,

  .read = posix_read,
  .write = posix_write,
  .lseek = posix_lseek,
  .close = posix_close,

  .fsync = posix_fsync,
  .ioctl = posix_ioctl,
  .size = posix_size,
};


// remainder of this file implements posix-style directory handling

char * 
nxlibc_syscall_getcwd(char *buf, int size)
{
	char *pathname;
	int plen;

	if (buf == NULL) {
		printf("size is %d\n", size);
		if (size > NAME_MAX)
			size = NAME_MAX;
		buf = malloc(size ? size : NAME_MAX + 1);
	}

	pathname = Path_string(&curr_directory, Path_len(&curr_directory));
	plen = strlen(pathname);
	assert(plen < NAME_MAX);
	
	memcpy(buf, pathname, plen);
	buf[plen] = '\0';

	buf[0] = ' ';	// small hack: would otherwise show two slashes
	return buf;
}

int nxlibc_syscall_chdir(const char *filename) {
  FileDescriptor *desc;
  
  desc = _posix_open(filename, O_DIRECTORY, O_RDONLY); 
  if (!desc)
    FAILRETURN(-1, "could not open directory");

  Path_clear(&curr_directory);
  if (curr_directory_supports_pin)
    nexusfs_unpin(desc->node);

  // at the moment, we don't pin the cwd
  curr_directory = desc->path;
  curr_directory_supports_pin = desc->supports_pin;
  free(desc);
  return 0;
}

int nxlibc_syscall_mkdir(const char *name, mode_t mode) {
  Path path;

  int rc = Path_resolve1(&path, curr_fs_root, &curr_directory, name);

  // error handling
  if (rc) {
    if (rc == -FS_NOTDIR) errno = ENOTDIR;
    else if (rc == -FS_ACCESSERROR) errno = EFAULT;
    else errno = EACCES;
    return -1;
  }
  // error: node exists
  if (FSID_isValid(Path_last(&path)->node)) {
    Path_clear(&path);
    errno = EEXIST;
    return -1;
  }

  // lookup parent
  FSID parent = Path_lastparent(&path)->node;
  char *fname = Path_last(&path)->fname;
  Path_clear(&path);

  // create child
  FSID rv = nexusfs_mkdir(parent, fname);

  // error handling
  rc = FSID_getError(rv);
  if (rc) {
    if (rc == -FS_NOTDIR) errno = ENOTDIR;
    else if (rc == -FS_ACCESSERROR) errno = EFAULT;
    else errno = EACCES;
    return -1;
  }

  return 0;
}

int nexus_chroot(FSID new_fs_root) {
  curr_fs_root = new_fs_root;
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
 
  rc = Path_resolve1(&path, curr_fs_root, &curr_directory, unixpath);
  if (rc) {
    fprintf(stderr, "cannot resolve %s\n", unixpath);
    switch (rc) {
	case -FS_NOTDIR:	ReturnError(ENOTDIR);
	case -FS_ACCESSERROR:	ReturnError(EFAULT);
	default:		ReturnError(EACCES);

    }
  }
  
  parent = Path_last(&path)->node;
  if (!FSID_isValid(parent)) {
    fprintf(stderr, "%s does not exist\n", unixpath);
    ReturnError(ENOENT);
  }
  if (!FSID_isDir(parent)) {
    fprintf(stderr, "%s is not a directory\n", unixpath);
    Path_clear(&path);
    ReturnError(ENOTDIR);
  }

  rc = nexusfs_mount(parent, child);
  Path_clear(&path);

  if (rc) {
    fprintf(stderr, "mount: can't mount (rc = %d)\n", rc);
    ReturnError(EACCES);
  }

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

  d = GenericDescriptor_find(dirstream->fd);
  if (!d) {
    errno = EBADF;
    FAILRETURN(NULL, "badf");
  }

  // ask the FS for this item
  desc = d->private;
  data.data = dirstream->entry.d_name;
  data.len = sizeof(dirstream->entry.d_name);
  ret = FS_ReadDir_ext(desc->h, desc->node, data, dirstream->offset);
  if (ret < 0) {
    errno = EINVAL;
    GenericDescriptor_put(d);
    FAILRETURN(NULL, "can't read dir");
  }

  // special case: return value is 0 indicates there are no more items to process
  if (ret == 0)
    dirstream->done = 1;
  dirstream->offset++;

  GenericDescriptor_put(d);
  return &dirstream->entry;
}

void nxlibc_syscall_rewinddir(DIR *dir) {
  dir->offset = 0;
  dir->done = 0;
}

int nxlibc_syscall_closedir(DIR *dirstream) {
  int err = close(dirstream->fd);
  free(dirstream);
  return err;
}

int nxlibc_syscall_unlink(const char *pathname) {
  FSID fsid, fsold;
  Path path;
  int rc;
 
  rc = Path_resolve1(&path, curr_fs_root, &curr_directory, pathname);
  if (rc)
    ReturnError(EFAULT);

  return nexusfs_unlink(Path_lastparent(&path)->node, Path_last(&path)->fname);
}

int nxlibc_syscall_chmod(const char *pathname, mode_t mode) {
  printf("chmod not supported\n");
  return -1;
}

FSID fsid_from_fd(int fd) {
  GenericDescriptor *f = GenericDescriptor_find(fd);
  if (f == NULL) {
    errno = EBADF;
    return FSID_ERROR(FS_INVALID);
  }
  FileDescriptor *desc = f->private;
  if (!desc) {
    errno = EBADF;
    return FSID_ERROR(FS_INVALID);
  }
  return desc->node;
}
