/** Nexus OS: a simple shell */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <dirent.h>
#include <limits.h>
#include <sys/mount.h>

#include <nexus/init.h>
#include <nexus/ipc.h>
#include <nexus/fs.h>
#include <nexus/test.h>
#include <nexus/linuxcalls.h>
#include <nexus/nexuscalls.h>
#include <nexus/IPC.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>

char *cwd_name;

static int execute_file(const char *filepath);

/** Execute a task. 
    Normally, wait for completion.
    Run in background in own console if last element of argv is "&" */
static int 
exec_file(const char *path, int argc, char **argv)
{
  int wait, ret;

  if (argc > 1 && !strcmp(argv[argc - 1], "&")) {
	  wait = 0;
	  argv[--argc] = 0;
  }
  else
	  wait = -1;

  ret = nxcall_exec_ex(path, argv, NULL, wait);
  if (ret < 0) {
  	if (ret != -EACCES)
    		fprintf(stderr, "[%s] exit %d\n", argv[0], ret);
	return 1;
  }

  return 0;
}

////////  builtin commands  ////////

static int 
do_cat(int argc, char **argv) 
{
// XXX eventually, replace builtins with busybox equivalents
//     requires busybox to inherit its parent's $PWD
#define DO_OLD
#ifdef DO_OLD
  int i;
  char recv_buf[1024];
  int recv_len;

  for(i=1; i < argc; i++) {
    int handle = open(argv[i], O_RDONLY);
    if(handle < 0) {
      printf("%s: not found\n", argv[i]);
      continue;
    } else {
      printf("%s:\n", argv[i]);
    }

    while(1) {
      memset(recv_buf, 0, sizeof(recv_buf));
      int actual, requested = sizeof(recv_buf);
      actual = read(handle, recv_buf, requested);

      int j;
      for(j=0; j < actual; j++) {
	printf("%c", recv_buf[j]);
      }
      if(actual != requested) break;
    }
    printf("\n");
    close(handle);
  }
  return 0;
#else
  return exec_file("/bin/busybox", argc, argv);
#endif
}

static int 
do_cd(int argc, char **argv) 
{
  char *newdir;
  char *olddir;

  if (argc == 1)
    newdir = "/"; // XXX should be user HOME
  else
    newdir = argv[1];

  if (chdir(newdir)) {
    printf("%s: No such file or directory\n", newdir);
    return -1;
  }

  olddir = cwd_name;
  cwd_name = getcwd(NULL, NAME_MAX);
  free(olddir);

  return 0;
}

static int 
do_echo(int argc, char **argv) 
{
  int i;

  for (i = 1; i < argc; i++) {
	  write(1, argv[i], strlen(argv[i]));
  	  write(1, " ", 1);
  }
  write(1, "\n", 1);
  return 0;
}

static int 
do_tail(int argc, char **argv) 
{
	char buf[1000], *pos;
	int fd, lines, maxlines, len;
    
	if (argc == 3)
		maxlines = strtol(argv[2], NULL, 10);
	else
		maxlines = 50;

	// read last 1K (arbitrary number) bytes
	fd = open(argv[1], O_RDONLY);
	len = lseek(fd, 0, SEEK_END);
	if (len < 0)  {
		fprintf(stderr, "seek()\n");
		return 1;
	}
	if (len > 1000)
		len = 1000;
	len = lseek(fd, len, SEEK_SET);
	if (len < 0) {
		fprintf(stderr, "seek()\n");
		return 1;
	}
	if (read(fd, buf, len) < 0) {
		fprintf(stderr, "read()\n");
		return 1;
	}
	if (close(fd)) {
		fprintf(stderr, "close()\n");
		return 1;
	}

	// calculate #lines
	lines = 0;
	for (pos = buf; *pos; pos++) {
		if (*pos == '\n')
			lines++;
	}

	// skip until last 50 lines at most
	lines -= maxlines;	
	for (pos = buf; lines > 0; pos++) {		
		if (*pos == '\n')
			lines--;
	}
	len -= pos - buf;

	// write
	write(1, pos, len);

	// add endline, if missing
	if (pos[len] != '\n')
		write(1, "\n", 1);

	return 0;
}

static int do_sync(int argc, char **argv) {
  int i;
  for(i=1; i < argc; i++) {
    FILE *fp = fopen(argv[i], "r");
    if(fp == NULL) {
      printf("Could not sync %s\n", argv[i]);
      continue;
    }
    fsync(fileno(fp));
    fclose(fp);
  }
  return 0;
}

static int do_size(int argc, char **argv) {
  struct stat _stat;

  if (argc != 2 || stat(argv[1], &_stat)) {
	  printf("stat failed\n");
	  return -1;
  }

  printf("%s %20lu\n", argv[1], _stat.st_size);
  return 0;
}

static int do_sleep(int argc, char **argv)
{
	unsigned long seconds;

	if (argc != 2)
		ReturnError(1, "sleep: incorrect number of parameters (%d)\n");

	seconds = strtoul(argv[1], NULL, 10);
	if (seconds == ULONG_MAX)
		ReturnError(1, "sleep: illegal parameter\n");

	Thread_USleep(seconds * 1000000);
	return 0;
}

static int do_checksum(int argc, char **argv) {
  int i;
  char recv_buf[1024];
  int recv_len;

  for(i=1; i < argc; i++) {
    int handle = open(argv[i], O_RDONLY);
    if(handle < 0) {
      printf("%s: not found\n", argv[i]);
      continue;
    } else {
      printf("%s:\n", argv[i]);
    }

    int accum = 0, count = 0, accum1 = 0;
    while(1) {
      memset(recv_buf, 0, sizeof(recv_buf));
      int actual, requested = sizeof(recv_buf);
      actual = read(handle, recv_buf, requested);

      int j;
      for(j=0; j < actual; j++) {
	accum += (unsigned char)recv_buf[j];
	accum1 += (unsigned char)recv_buf[j];
	if(count % 1048576 == 0) {
	  printf("%d (%d)\n", accum, count);
	  accum = 0;
	}
	count++;
      }
      if(actual != requested) break;
    }
    printf("%d %d (%d)\n", accum, accum1, count);
    close(handle);
  }
  return 0;
}

static int do_kernel(int argc, char **argv) {
    return Debug_KCommand(argc - 1, argv + 1);
}

static int do_ls(int argc, char **argv) {
  DIR *dir;
  struct dirent *d;
  int i;
  
  printf("\n.\n..\n");

  if (argc == 1) {
    argc++;
    argv[1] = ".";
  }

  for (i = 1; i < argc; i++) {
    dir = opendir(argv[i]);
    if (!dir) {
      fprintf(stderr, "Error: %s not found\n", argv[i]);
      continue;
    }
    
    while ((d = readdir(dir)))
      printf("%s\n", d->d_name);

    if (closedir(dir) != 0)
      fprintf(stderr, "Error during close\n");
  }

  return 0;
}

static int do_create(int argc, char **argv) {
  if(argc < 2) {
    printf("create: need at least one argument\n");
    return -1;
  }
  int new_fd = open(argv[1], O_CREAT);
  if(new_fd < 0) {
    printf("error while creating\n");
    return -1;
  }
  close(new_fd);
  return 0;
}

static int do_mkdir(int argc, char **argv) {
  if(argc < 2) {
    printf("%s: need at least one argument\n", __FUNCTION__);
    return -1;
  }
  if (mkdir(argv[1], 0644)) {
    printf("error while creating\n");
    return -1;
  }
  return 0;
}

static int do_unlink(int argc, char **argv) {
  if(argc < 2) {
    printf("%s: need at least one argument\n", __FUNCTION__);
    return -1;
  }
  if (unlink(argv[1])) {
    printf("error while unlinking\n");
    return -1;
  }
  return 0;
}

static int do_write(int argc, char **argv) {
  if(argc < 2) {
    printf("write: need at least one argument\n");
    return -1;
  }
  int fd = open(argv[1], O_RDWR);
  if(fd < 0) {
    printf("error opening file %s for write\n", argv[1]);
    return -1;
  }
  char line[1024];
  while (1) {
    fgets(line, sizeof(line) - 1, stdin);
    if (!strcmp(line, ".\n"))
      break;

    int sz = strlen(line);
    int res = write(fd, line, sz);
    if(sz != res) {
      printf("write mismatch %d %d\n", sz, res);
      break;
    }
  }
  close(fd);
  return 0;
}

int do_fault(int argc, char **argv) {
  printf("generating a page fault\n");
  *(int*)0 = 0;
  return 0;
}

int do_help(int argc, char **argv);

int nxlibc_syscall_mount(const char *source, const char *target,
		         const char *filesystemtype, unsigned long mountflags,
			 const void *data);

int do_mount(int argc, char **argv) {
  char mountport[12];

  if (argc < 3) {
    printf("Usage: mount <server port> <destination dir>\n");
    return -1;
  }

  printf("[explorer] mounting %s at %s\n", argv[1], argv[2]);
  return mount(argv[1], argv[2], NULL, 0, NULL);
  //return nxlibc_syscall_mount(argv[1], argv[2], NULL, 0, NULL);
}

int do_umount(int argc, char **argv) {

  if (argc != 2) {
    fprintf(stderr, "Usage: umount <destination dir>\n");
    return -1;
  }

  fprintf(stderr, "umount: not implemented\n");
  // XXX implement uclibc umount redirect 
  // XXX implement nxlibc_syscall_umount that calls FS_Unmount
  return -1;
}

int do_exit_cmd(int argc, char **argv) {
  exit(0);
  return 0;
}

static int do_import(int argc, char **argv)
{
	if (argc != 2) {
    		fprintf(stderr, "Usage: import <script>\n");
    		return -1;
	}

	execute_file(argv[1]);
	return 0;
}

// builtin commands
struct Command {
  char *str;
  int (*func)(int argc, char **argv);
};

struct Command commands[] = {
  { "cat", do_cat },
  { "cd", do_cd },
  { "checksum", do_checksum },
  { "create", do_create },
  { "echo", do_echo },
  { "exit", do_exit_cmd },
  { "fault", do_fault },
  { "help", do_help },
  { "import", do_import },
  { "kernel", do_kernel },
  { "ls", do_ls },
  { "mount", do_mount },
  { "mkdir", do_mkdir },
  { "size", do_size },
  { "sleep", do_sleep },
  { "sync", do_sync },
  { "tail", do_tail },
  { "umount", do_umount },
  { "unlink", do_unlink },
  { "write", do_write },
};

int do_help(int argc, char **argv) {
  int i;

  printf("Builtin commands:\n");
  for (i=0; i < sizeof(commands) / sizeof(commands[0]); i++)
    printf("%s\n", commands[i].str);
  
  return 0;
}

#define NUM_COMMANDS ( sizeof(commands) / sizeof(commands[0]) )

/** Execute a command, where command is a binary process or a builtin */
static int 
execute_line(char *line)
{
    const char MAX_ARGS = 12;

    char *args[MAX_ARGS];
    int ret, i, cur_arg = 0;

    // tokenize the line
    for (i = 0; line[i] != '\0'; i++) {
      switch(line[i]) {

      // whitespace
      case '\n': 
      case ' ': 
      case '\t': 
	line[i++] = '\0';
	while ((line[i] == ' ' || line[i] == '\t') && line[i] != '\0') {
	  i++;
	}

	if (line[i] == '\0') 
		goto call_cmd;

	if (cur_arg == MAX_ARGS - 1)
		ReturnError(1, "too many arguments");

	args[cur_arg++] = line + i;
	break;

      // other
      default:
	if (!cur_arg) {
	  args[cur_arg++] = line + i;
	}
	break;
      }
    }

call_cmd:
    args[cur_arg] = 0;
      if (!cur_arg)
        return 1;

    // try a builtin command
    for (i = 0; i < NUM_COMMANDS; i++) {
      if (!strcmp(args[0], commands[i].str)) {
	commands[i].func(cur_arg, args);
	return 0;
      }
    }

    // try an executable in the filepath
    ret = exec_file(args[0], cur_arg, args);
    if (!ret)
      return 0;

    // try a kernel command
    ret = Debug_KCommand(cur_arg, args);
    if (!ret)
      return 0;

    fprintf(stderr, "[%s] command not found\n", args[0]);
    return 1;
}

/** Parse a script file 
    File format is simple: execute any line up until a hash sign ('#') */
static int
execute_file(const char *filepath)
{
	const int line_maxlen = 256;

  	char line[line_maxlen];
	int fd, line_off, line_use, line_skip;
	char c;

  	fd = open(filepath, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "error opening %s\n", filepath);
		return 1;
	}
	
	line_off = 0;
	line_use = 0;	// execute line. true unless only whitespace or comment
	line_skip = 0;
	// read and execute script. 
	// NB: last line will be skipped (i.e., must be empty)
	while (read(fd, &c , 1) == 1) {
		switch (c) {
			// endline
			case '\n':	
				line[line_off] = 0;
				if (line_use && !line_skip) {
					execute_line(line);
				}
				line_skip = 0;
				line_use = 0;
				line_off = 0;
				continue;	// to avoid line_use++
			break;
			// comment
			case '#':
				// execute up to here
				if (line_use) {
					line[line_off] = 0;
					execute_line(line);
				}
				line_skip = 1;
				line_use = 0;
			break;
			// whitespace
			case ' ':
			case '\t':
				// do not record whitespace before start of line
				if (line_use)
					line[line_off] = ' ';
			break;
			default:
				// end of whitespace: start recording
				if (!line_use) {
					line_use = 1;
					line_off = 0;
				}
				line[line_off] = c;
		}
		line_off++;

		if (line_off == line_maxlen)
			ReturnError(1, "line exceeds maximum length");
	}

	close(fd);
	return 0;
}

int main(int argc, char **argv) {
  char line[1024];
  
  cwd_name = getcwd(NULL, NAME_MAX);
 
  if (argc > 3) {
	  fprintf(stderr, "usage: %s <filepath>\n"
			  "       %s -c <command>\n", argv[0], argv[0]);
	  return 1;
  }

  printf("Nexus shell\n"
	 "Enter 'help' to list all commands\n\n");

  // if a filepath is given, execute as script before going interactive
  if (argc == 3 && !strcmp(argv[1], "-c"))
	  execute_line(argv[2]);
  if (argc == 2)
	  execute_file(argv[1]);
  else
	  execute_line("ls");

  while (1) {
	  printf("[user@%s]# ", cwd_name);
	  memset(line, 0, sizeof(line));
	  fgets(line, sizeof(line), stdin);
	  execute_line(line);
  }

  return 0;
}

