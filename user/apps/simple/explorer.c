/** Nexus OS: a simple shell */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/mount.h>

#include <nexus/init.h>
#include <nexus/ipc.h>
#include <nexus/fs.h>
#include <nexus/IPC.interface.h>
#include <nexus/Debug.interface.h>

#define AUTORUN_COUNT (sizeof(autorun) / sizeof(autorun[0]))

char *autorun[] = { "ls" };
char *cwd_name;

// XXX eventually replace the internal nxlibc... with the real libc execve
#include <nexus/linuxcalls.h>
static int do_exec(int argc, char **argv) {
  return nxlibc_syscall_execve(argv[1], argv + 1, NULL);
}

static int do_cd(int argc, char **argv) {

  if(argc != 2) {
    printf("cd expects exactly one argument\n");
    return -1;
  }

  char *target = argv[1];
  if(chdir(target) != 0) {
    printf("could not cd to %s\n", target);
    return -1;
  }

  free(cwd_name);
  cwd_name = getcwd(NULL, NAME_MAX);
  return 0;
}

static int do_cat(int argc, char **argv) {
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

int do_cancel(int argc, char **argv) {
  Debug_cancel_shell_wait();
  return 0;
}

int do_exit_cmd(int argc, char **argv) {
  exit(-1);
  return 0;
}

static void do_find(char *path) {
  DIR *dir = opendir(path);
  if(dir == NULL) {
    char *args[3] = {"cat", path, 0};
    do_cat(2, args);
    return;
  }
  printf("%s/", path);
  struct dirent *d;
  while((d = readdir(dir)) != NULL) {
    char *filename = malloc(1024);
    snprintf(filename, 1024, "%s/%s", path, d->d_name);
    do_find(filename);
    free(filename);
  }

  if(closedir(dir) != 0) {
    printf("closedir '%s' error\n", path);
  }
}

int do_find_cat(int argc, char **argv) {
  int i;
  if(argc == 1) {
    argc++;
    argv[1] = ".";
  }

  for(i=1; i < argc; i++) {
    char *fname = argv[i];
    printf("%s", argv[i]);
    do_find(fname);
  }
  return 0;
}

struct Command {
  char *str;
  int (*func)(int argc, char **argv);
} commands[] = {
  { "cancel", do_cancel },
  { "cat", do_cat },
  { "cd", do_cd },
  { "checksum", do_checksum },
  { "create", do_create },
  { "exec", do_exec },
  { "exit", do_exit_cmd },
  { "fault", do_fault },
  { "findcat", do_find_cat },
  { "help", do_help },
  { "ls", do_ls },
  { "mount", do_mount },
  { "mkdir", do_mkdir},
  { "sync", do_sync },
  { "umount", do_umount },
  { "unlink", do_unlink },
  { "write", do_write },
};

int do_help(int argc, char **argv) {
  int i;
  printf("Supported commands:\n");
  for(i=0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    printf("%s\n", commands[i].str);
  }
  return 0;
}

#define NUM_COMMANDS ( sizeof(commands) / sizeof(commands[0]) )

int main(int argc, char **argv) {
#define MAX_ARGS (1024)
  char line[1024];
  char **args;
  int autorun_pos, cur_arg, i;
  
  args = calloc(1, MAX_ARGS * sizeof(char *));
  autorun_pos = 0;
  cwd_name = getcwd(NULL, NAME_MAX);
    
  printf("Nexus shell\n"
	 "Enter 'help' for a list of all commands\n"
	 "      '<command> help' for more detailed information\n\n");

  while (1) {

    if (autorun_pos < AUTORUN_COUNT) {
      strcpy(line, autorun[autorun_pos]);
      autorun_pos++;
    } else {
      printf("[root@%s]# ", cwd_name);
      memset(line, 0, sizeof(line));
      fgets(line, sizeof(line), stdin);
    }

    cur_arg = 0;

    // tokenize the line
    for (i = 0; line[i] != '\0'; i++) {
      switch(line[i]) {

      // whitespace
      case '\n': case ' ': case '\t': 
	line[i++] = '\0';
	while ((line[i] == ' ' || line[i] == '\t') && line[i] != '\0') {
		printf("TRUE\n");
	  i++;
	}

	if (line[i] == '\0') 
		goto call_cmd;

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
      continue;

    for (i = 0; i < NUM_COMMANDS; i++) {
      if (!strcmp(args[0], commands[i].str)) {
	commands[i].func(cur_arg, args);
	break;
      }
    }

    if(i == NUM_COMMANDS)
      fprintf(stderr, "%s: command not found\n", args[0]);

  } // while

  return 0;
}

