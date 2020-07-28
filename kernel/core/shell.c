/** NexusOS: kernel shell */
#include <linux/config.h>
//#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <asm/delay.h>
#include <linux/pci.h>
#include <asm/hw_irq.h>
#include <asm/io.h>
#include <asm/param.h>
#include <asm/msr.h>

#include <nexus/defs.h>
#include <nexus/queue.h>
#include <nexus/thread.h>
#include <nexus/thread-private.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/clock.h>
#include <nexus/mem.h>
#include <nexus/mem-private.h>	
#include <nexus/machineprimitives.h>
#include <nexus/net.h>
#include <nexus/log.h>
#include <libtcpa/tcpa.h>
#include <nexus/idtgdt.h>
#include <nexus/device.h>
#include <nexus/ipd.h>
#include <nexus/service.h>
#include <nexus/util.h>
#include <nexus/kbd.h>
#include <nexus/initrd.h>
#include <nexus/ksymbols.h>
#include <nexus/malloc_checker.h>
#include <nexus/regression.h>
#include <nexus/mousedev.h>
#include <nexus/mtrr.h>
#include <nexus/handle.h>
#include <nexus/ipc_private.h>
#include <nexus/hashtable.h>
#include <nexus/stringbuffer.h>
#include <nexus/vdir.h>
#include <nexus/kvkey.h>
#include <nexus/version.h>
#include <nexus/unet.h>
#include <nexus/test.h>
#include <nexus/elf.h>
#include <nexus/tftp.h>

KVKey_nsk *default_nsk = NULL;

int tpm_present = 0;
static int skip_screens = 1;

KThread *shell_thread;
NexusOpenDevice *shell_kbd;

int refcnt_print = 1;

/** enable skipping of automatic initscript execution from the command line */
static int skip_autorun = 0;
void 
set_skip_autorun(char *opt) {
	skip_autorun = 1;
}

typedef struct ShellCommand {
	char *name;
	char *usage;
	shell_cmd_t proc; // if proc is null, this is a "command group" entry
} ShellCommand;

ShellCommand *commands;
int numcommands;

static int start_shell_thread(void *arg);

/** from the init thread, initialize the shell and start a shell thread */
void 
shell_init(void) 
{
	KSymbol *ksym;
	int ksym_count, i;

	printkx(PK_SHELL, PK_DEBUG, "%d low page tables zapped to oblivion\n", 
	        num_zapped_low_ptab);

	ksym = ksym_table(&ksym_count);
	if (!ksym_count) {
		printkx(PK_SHELL, PK_WARN, "[shell] System.map not found."
			                   " kernel shell will be useless.\n");
		nexusthread_init(start_shell_thread, NULL); // why bother?
		return;
	}

	int n = 0;
	for (i = 0; i < ksym_count; i++) {
		if (ksym[i].type == 'D' &&
				(!strncmp(ksym[i].name, "SHELL_COMMAND_FN_", 17) ||
				!strncmp(ksym[i].name, "SHELL_COMMAND_GROUP_", 20))) {
			n++;
		}
	}
	commands = galloc(n * sizeof(ShellCommand));
	numcommands = n;
	n = 0;
	for (i = 0; i < ksym_count; i++) {
		if (ksym[i].type != 'D') continue;
		if (!strncmp(ksym[i].name, "SHELL_COMMAND_FN_", 17)) {
			commands[n].name = ksym[i].name + 17;
			commands[n].proc = *(shell_cmd_t *)ksym[i].addr;
			if (i+1 < ksym_count && ksym[i+1].type == 'D' &&
					!strncmp(ksym[i+1].name, "SHELL_COMMAND_DESC_", 19)) {
				commands[n].usage =  *(char **)ksym[i+1].addr;
			} else {
				commands[n].usage =  "???";
				static int warned = 0;
				if (!warned) {
					warned = 1;
					printk_red("warning: System.map not in expected order (%s)\n",
							ksym[i].name);
				}
			}
			n++;
		} else if (!strncmp(ksym[i].name, "SHELL_COMMAND_GROUP_", 20)) {
			commands[n].name = ksym[i].name + 20;
			commands[n].proc = 0;
			commands[n].usage =  *(char **)ksym[i].addr;
			n++;
		}
	}
	printkx(PK_SHELL, PK_INFO, "Loaded %d shell commands\n", numcommands);

	shell_kbd = ipd_get_open_device(kernelIPD, DEVICE_KEYBOARD, -1);
	nexusthread_init(start_shell_thread, NULL);
}

int shell(char *cmdline) {
	while (isspace(*cmdline)) cmdline++; // drop leading whitespace
	char *c;
	for (c = cmdline; *c && *c != '#'; c++); // drop trailing comments
	if (c != cmdline && c[-1] == '\n')  *(--c) = 0; // drop trailing newline
	if (c == cmdline) return 0; // ignore blank lines

	int ac = 1;
	for (c = cmdline; c[1]; c++)
		if (isspace(c[0]) && !isspace(c[1])) ac++;
	char **av = galloc((ac+1)*sizeof(char *));
	av[0] = cmdline;
	av[ac] = 0;
	ac = 1;
	for (c = cmdline; c[1]; c++) {
		if (isspace(c[0])) {
			c[0] = 0;
			if (!isspace(c[1]))
				av[ac++] = &c[1];
		}
	}

	int i;
	for(i = 0; i < numcommands; i++) {
		if(!strcmp(av[0], commands[i].name)) {
			break;
		}
	}
	int ret = -1;
	if (i < numcommands && commands[i].proc) {
		ret = (commands[i].proc)(ac, av);
		if (ret == BAD_USAGE)
			printk("bad usage:\n  %s %s\n", av[0], commands[i].usage);
		else if (ret)
			printk("'%s' returned error code %d\n", av[0], ret);
	} else {
		printk("command not found: %s\n", av[0]);
	}
	gfree(av);
	return ret;
}

#define SHELL_LINE_SIZE (512)
#define SHELL_HISTORY 10
char shell_hist[SHELL_HISTORY][SHELL_LINE_SIZE];

int shell_history(int ac, char **av);
int shell_source(int ac, char **av);

static char *get_line(void) {
	static char shell_input[SHELL_LINE_SIZE];
	// shell_hist[0] = last typed command
	// shell_hist[n] = the nth one before that
	int linesize = SHELL_LINE_SIZE;

	printk("[kshell]# ");
	kbd_getdata(shell_kbd, &linesize, shell_input);
	shell_input[linesize] = 0;
	if (shell_input[0] == '!') {
		if (shell_input[1] < '0' || shell_input[1] > '9') {
			shell_history(0, 0);
			shell_input[0] = '\0';
			return shell_input;
		}
		int hist = atoi(&shell_input[1]);
		if (hist > 0 && hist <= SHELL_HISTORY)
			strcpy(shell_input, shell_hist[hist-1]);
	} else if (linesize > 0) {
		int hist;
		for (hist = SHELL_HISTORY-1; hist > 0; hist--)
			strcpy(shell_hist[hist], shell_hist[hist-1]);
		strcpy(shell_hist[0], shell_input);
	}
	return shell_input;
}

int show_screen(char *name) {
	if (!skip_screens) return 1;
	char *goodnames[] = {"mplayer", "capmgr", "email", "keymgr", "mplayer-nowrite"};
	int i;
	for(i = 0; i < sizeof(goodnames)/sizeof(char*); i++)
		if(!strcmp(name, goodnames[i]) == 0) return 1;
	return 0;
}

static char *known_filehashes;
int num_known_filehashes = 0;

char *is_known_filehash(char *hash) {
	int i;
	char *name = known_filehashes;
	char *khash = known_filehashes + 20;
	for (i = 0; i < num_known_filehashes; i++) {
		if(!memcmp(hash, khash, 20)) return name;
		name += 40;
		khash += 40;
	}
	return NULL;
}

static int start_shell_thread(void *arg) {
	NexusDevice *nd = find_device(DEVICE_KEYBOARD, NULL);
	assert(nd);
	kbd_start(nd);

	shell_thread = (KThread *) nexusthread_self();

	// initialize subsystems that depend on working threads
	kernelfs_init(); 
	nxnet_switch_init();

	// run self tests
  	unittest_runall_late();
	unittest_runall_user();
  
	// delay pci initialization until after self-tests
	// so that no real device can interfere with dummy netdev test
	ddrm_sys_init();

	// process initscript
	if (!skip_autorun)
		shell_source(2, (char *[]) { "source", "initscript", NULL });
	
	printk_green("[kernel] initializing drivers. Please wait..\n");
	nexusthread_sleep(1000);	// a bit ugly. wait for initscript tasks to complete

	printk_green("\n[kernel] up. version %s\n", NEXUSVERSION);
	printk("Welcome to the Nexus kernel shell\n"
	       "Enter 'help' for more information\n\n");

	// process user input
	while (1)
		shell(get_line());

	// not reached (useless gcc warning)
	return -1;
}


void showbytes(char *data, int len) {
	int i;
	for(i = 0; i < len; i++){
		printk("%02x ", 0xff & data[i]);
		if (((i + 1) % 32) == 0) printk("\n");
	}
	printk("\n");
}


/* ----------- most of the rest of this could be elsewhere -------------- */

DECLARE_SHELL_COMMAND_GROUP(basic, "Basic Commands");

int shell_help(int ac, char **av) {

	if (ac < 2) {
		char *spaces = "                    \0";
		int colwidth = strlen(spaces);
		int i, j, k = 0;
		for (i = 0; i <= numcommands; i++) {
			if (k < i && (i == numcommands || !commands[i].proc)) {
				int n = i-k;
				int rr = (n+3)/4;
				int r;
				for (r = 0; r < rr; r++) {
					char *cmd1 = commands[k+r].name;
					char *cmd2 = (k+r+rr<i) ? commands[k+r+rr].name : "";
					char *cmd3 = (k+r+2*rr<i) ? commands[k+r+2*rr].name : "";
					char *cmd4 = (k+r+3*rr<i) ? commands[k+r+3*rr].name : "";
					printk("   %s%s%s%s%s%s%s\n",
							cmd1, &spaces[strlen(cmd1)],
							cmd2, &spaces[strlen(cmd2)],
							cmd3, &spaces[strlen(cmd3)],
							cmd4);
				}
			}
			if (i < numcommands && !commands[i].proc) {
				char *header = commands[i].usage;
				int l = colwidth*4 - strlen(header+2);
				for (j = 0; j < l/2; j++) printk_red("-");
				printk_red(" %s ", header);
				for (j = 0; j < l-l/2; j++) printk_red("-");
				printk_red("\n");
				k = i+1;
			}
		}
	} else {
		int i;
		char *cmd = av[1];
		for(i = 0; i < numcommands; i++) {
			if(!strcmp(cmd, commands[i].name)) {
				break;
			}
		}
		if (i == numcommands) {
			printk("command not found: %s\n  try 'help help'\n", cmd);
			return -1;
		} else {
			printk("%s %s\n", cmd, commands[i].usage);
		}
	}
	return 0;
}
DECLARE_SHELL_COMMAND(help, shell_help, "[cmd] -- ask for help an all commands (or just one)");

int shell_history(int ac, char **av) {
	int i;
	for (i = SHELL_HISTORY-1; i >= 0; i--)
		if (shell_hist[i][0]) printk("!%d = %s", i+1, shell_hist[i]);
	return 0;
}
DECLARE_SHELL_COMMAND(hist, shell_history, "-- show the shell history");

#if 0
int shell_echo(int ac, char **av) {
	int i;
	for (i = 1; i < ac; i++) printk("%s ", av[i]);
	printk("\n");
	return 0;
}
DECLARE_SHELL_COMMAND(echo, shell_echo, "[args] ... -- just echo");
#endif

int shell_logo(int ac, char **av) {
	fbcon_show_logo(-1, -1);
	return 0;
}
DECLARE_SHELL_COMMAND(logo, shell_logo, "... -- shows the logo");

int shell_exit(int ac, char **av) {
	printk_red("Going down for reboot now..."); 
	machine_restart();
	return 0;
}
DECLARE_SHELL_COMMAND(exit, shell_exit, "-- reboot machine");

#if 0
int shell_dumplog(int ac, char **av) {
	nexusdumplog();
	return 0;
}
DECLARE_SHELL_COMMAND(dumplog, shell_dumplog, "-- dump kernel log");

int shell_sendlog(int ac, char **av) {
	nexussendlog("nexuslog.000");
	return 0;
}
DECLARE_SHELL_COMMAND(sendlog, shell_sendlog, "-- send kernel log");

int shell_log(int ac, char **av) {
	int i;
	nexuslog("%s:", av[0]);
	for (i = 1; i < ac; i++) nexuslog(" %s", av[i]);
	nexuslog("\n");
	return 0;
}
DECLARE_SHELL_COMMAND(log, shell_log, "[text] ... -- write to kernel log");
#endif

int shell_idle(int ac, char **av) {
	printk("idle [sec:%d%%] [min:?%%]\n", nexusthread_idle_pct_sec);
	if (ac < 2) skip_screens = !skip_screens;
	else skip_screens = av[1][0] == '1';
	return 0;
}
DECLARE_SHELL_COMMAND(idle, shell_idle, "-- show idle time");

#if 0
int shell_skiptoggle(int ac, char **av) {
	if (ac < 2) skip_screens = !skip_screens;
	else skip_screens = av[1][0] == '1';
	return 0;
}
DECLARE_SHELL_COMMAND(skiptoggle, shell_skiptoggle, "[0|1] -- skip (or not) anything bug \"good\" apps when alt-tabbing");
#endif

#if 0
int shell_loadhashes(int ac, char **av) {
	if (ac < 2) return BAD_USAGE;
	int size;
	char *f = fetch_file(av[1], &size);
	num_known_filehashes = size/40;
	if (known_filehashes) gfree(known_filehashes);
	known_filehashes = f;
	return 0;
}

DECLARE_SHELL_COMMAND(loadhashes, shell_loadhashes, "file -- set the array of known file hashes");
#endif

int shell_source(int ac, char **av) {
	char *filename, *file, *line;
	int i, size, if0depth = 0, if1depth = 0, ret = 0;
	
	printk("[source] %s\n", av[1]);

	if (ac < 2) {
		printk("[source] Error: no filepath supplied\n");
		return BAD_USAGE;
	}

	filename = av[1];
	file = fetch_file(filename, &size);
	if (!file) {
		printk("[source] Error: no such file %s\n", filename);
		return -1;
	}

	line = file;
	for(i = 0; i < size; i++) {
		if(file[i] == '\n') {
			file[i] = '\0';
			while (isspace(*line)) line++; // drop leading whitespace
			char *c;
			for (c = line; *c && *c != '#'; c++); // drop trailing comments
			while (c != line && (isspace(c[-1]) || c[-1] == '\n'))  *(--c) = 0; // drop trailing newline and whitespace
			if (if0depth > 0) {
			  // do nothing but count open and close braces
			  if (!strcmp(line, "if (0) {")) if0depth++;
			  else if (!strcmp(line, "if (1) {")) if0depth++;
			  else if (!strcmp(line, "}") && if0depth > 0) if0depth--;
			  else if (!strcmp(line, "}")) printk("unmatched close brace\n");
			  line = file + i + 1;
			  continue;
			}
			if (!strcmp(line, "if (0) {")) if0depth++;
			else if (!strcmp(line, "if (1) {")) if1depth++;
			else if (!strcmp(line, "}") && if1depth > 0) if1depth--;
			else if (!strcmp(line, "}")) printk("unmatched close brace\n");
			else ret = shell(line);
			line = file + i + 1;
		}
	}
	cache_remove(filename);
	gfree(file);

	printk("[source] completed %s\n", filename);
	return ret;
}
DECLARE_SHELL_COMMAND(source, shell_source, "file -- read and exec lines of text file");

#if 0
int shell_regtest(int ac, char **av) {
	static int done_once = 0;

	if (ac < 3) return BAD_USAGE;

	char *section = av[2];
	int all_sections = (!strcmp(section, "*") || !strcmp(section, "all"));

	char *cursection = "always";

	int num_tests = 0;
	int num_passed_tests =0;
	int size;
	char *file = fetch_file(av[1], &size);
	if (!size) return -1;

	NexusLog *results = klog_new(8192);

	int i;
	int exitstat = 0;
	char *line = file;
	int line_count = 1;
	for (i = 0; i < size; i++) {
		if(file[i] == '\n') {
			file[i] = '\0';
			if (line[0] == '[' && line[strlen(line)-1] == ']') {
			  cursection = strdup(line+1);
			  cursection[strlen(cursection)-1] = '\0';
			  printk("section: [%s]\n", cursection);
			  klog(results, "section: [%s]\n", cursection);
			  line = file + i + 1;
			  continue;
			}
			if (!all_sections && strcmp(cursection, "always") &&
			    strcmp(cursection, "once") && strcmp(cursection, section)) {
			  // skip this section
			  line = file + i + 1;
			  continue;
			}
			if (!strcmp(cursection, "once")) {
			  if (done_once) {
			    line = file + i + 1;
			    continue;
			  }
			  done_once = 1;
			}
			printk("running command '%s'\n", line);
			char *orig_line = strdup(line);
			exitstat = shell(line);
			printk("logging %s: %s\n", (exitstat == 0)?"PASS":"FAIL", orig_line); 
			klog(results, "[%d]%s: %s\n", line_count,
			     (exitstat == 0)?"PASS":"FAIL", orig_line);
			gfree(orig_line);
			line = file + i + 1;

			num_tests++;
			if(exitstat == 0) {
			  num_passed_tests++;
			}
			line_count++;
		}
	}
	file[i] = '\0';
	if(line - file < size - 2){
	        printk("Running command '%s'\n", line);
		exitstat = shell(line);
		klog(results, "%s: %s\n", (exitstat == 0)?"PASS":"FAIL", line);
		printk("logging %s: %s\n", (exitstat == 0)?"PASS":"FAIL", line); 
		num_tests++;
		if(exitstat == 0) {
		  num_passed_tests++;
		}
	}
	printk("dumping log\n");

	klog_dump(results);
	klog_send(results, "REGOUTPUT.000");
	klog_destroy(results);
	printk("%d of %d passed\n", num_passed_tests, num_tests);

	gfree(file);
	return 0;
}
DECLARE_SHELL_COMMAND(regtest, shell_regtest, "script section -- run and log regression script");
#endif

static int 
shell_flush(int ac, char **av) 
{
	char *buf;
	int i, filesize;

	if (ac < 2) {
		printk("[flush] OK. Removed %d items\n", cache_clear());
	}

	for (i = 1; i < ac; i++) {
		buf = cache_find(av[i], &filesize);
		if (buf) {
			gfree(buf);
			cache_remove(av[i]);
			printk("[flush] %s: OK\n", av[i]);
		} else
			printk("[flush] %s: Error: not present\n", av[i]);
	}

	return 0;
}
DECLARE_SHELL_COMMAND(flush, shell_flush, "file ... -- flush files from file cache");

int shell_ls(int ac, char **av) {
	cache_list();
	return 0;
}
DECLARE_SHELL_COMMAND(ls, shell_ls, "-- list files in file cache");

#if 0
int shell_getmyip(int ac, char **av) {
	char *ip = getmyip();
	if (ip) {
		printk("my ip is %d.%d.%d.%d\n", 
				(unsigned char)ip[0], (unsigned char)ip[1], 
				(unsigned char)ip[2], (unsigned char)ip[3]);
		return 0;
	} else return -1;
}
DECLARE_SHELL_COMMAND(getmyip, shell_getmyip, "-- print local host ip address");
#endif

int shell_sleep(int ac, char **av) {
	if (ac < 2) return BAD_USAGE;
	nexusthread_sleep(atoi(av[1]) * HZ);
	return 0;
}
DECLARE_SHELL_COMMAND(sleep, shell_sleep, "n -- sleep n seconds");

int shell_usleep(int ac, char **av) {
	if (ac < 2) 
		return BAD_USAGE;

	nexusthread_sleep((atoi(av[1]) * HZ) / 1000000);
	return 0;
}
DECLARE_SHELL_COMMAND(usleep, shell_usleep, "n -- sleep n microseconds (currently limited to millesecond precision)");

int shell_exec(int ac, char **av) {
	int flags = 0;

	if (ac < 2) 
		return BAD_USAGE;

	if (av[0][0] == 'w')
		flags = PROCESS_WAIT;
	else if (av[0][0] == 'b')
		flags = PROCESS_BG;
	else if (av[0][0] == 'q')
		flags = PROCESS_QUIET;

	// refresh from NFS
	if (av[0][0] == 'h') {
		char *args[] = { "flush", av[1] };
		shell_flush(2, args);
		char *args2[] = { "wexec", "fetch", "/nfs", av[1] }; // was httpfs
		shell_exec(4, args2);
	}

	return elf_exec(av[1], flags, ac - 1, av + 1) >= 0 ? 0 : -1;
}

DECLARE_SHELL_COMMAND(exec, shell_exec, "prog [args] ... -- fetch prog and exec with args");
DECLARE_SHELL_COMMAND(wexec, shell_exec, "prog [args] ... -- like exec, but wait for program");
DECLARE_SHELL_COMMAND(bexec, shell_exec, "prog [args] ... -- like exec, but put in background");
DECLARE_SHELL_COMMAND(qexec, shell_exec, "prog [args] ... -- like exec, but without console");

typedef enum UThreadIteratorMode {
  STACKTRACE,
  PRINTID,
} UThreadIteratorMode;

static void uthread_iterator(void *item, void *arg) {
  UThreadIteratorMode mode = (UThreadIteratorMode)arg;
  UThread *ut = (UThread *)item;
  char *s;
  switch(mode) {
  case STACKTRACE:
    printk_green("Thread %d, refcnt = %d  ", nexusthread_id((BasicThread *)ut),
		 ut->ref_cnt);
    nexusthread_dump_regs_stack((BasicThread *)ut);
    break;
  case PRINTID:
    s = guess_thread_place((BasicThread *)ut, NULL);
    if (s) {
      printk("%d - %s\n", nexusthread_id((BasicThread *)ut), s);
      gfree(s);
    } else {
      printk("%d\n", nexusthread_id((BasicThread *)ut));
    }
    break;
  }
}

int shell_listipd(int ac, char **av) {
  int i;
  for(i=0; i < 15; i++) {
    IPD *ipd = ipd_find(i);
    if(ipd != NULL) {
      printf("[%d] = %s\n", i, ipd->name);
    }
  }
  return 0;
}
DECLARE_SHELL_COMMAND(ps, shell_listipd, "-- enumerate first 15 IPDs");

int shell_psipd(int ac, char **av) {
	if (ac < 2) {
		printk("Need at least 1 argument!\n");
		return -1;
	}
	int id = atoi(av[1]);
	IPD *ipd = ipd_find(id);
	if(ipd == NULL) {
		printk("could not find ipd %d\n", id);
		return -1;
	}
	UThreadIteratorMode mode;
	switch(av[0][0]) {
	case 'p':
	  mode = STACKTRACE;
	  break;
	case 'l':
	  mode = PRINTID;
	  break;
	default:
	  printk("unknown psipd mode %s\n", av[0]);
	  return -1;
	}
	printk_red("threads from %d\n", id);
	hash_iterate(ipd->uthreadtable, uthread_iterator, (void *)mode);
	return 0;
}
DECLARE_SHELL_COMMAND(psipd, shell_psipd, "<ipd_num> -- print all threads in ipd_num");

int shell_printthreads(int ac, char **av) {
	print_all_threads();
	return 0;
}
DECLARE_SHELL_COMMAND(pst, shell_printthreads, "-- print threads");

#if 0
void conn_handle_printer(Connection_Handle h, IPC_Connection *conn, void *arg) {
  printk("[%d] => %d\n ", h, (conn != NULL && conn->dest_port != NULL) ? conn->dest_port->port_num : -1);
}

int shell_connipd(int ac, char **av) {
	if (ac < 2) {
		printk("Need at least 1 argument!\n");
		return -1;
	}
	int id = atoi(av[1]);
	IPD *ipd = ipd_find(id);
	if(ipd == NULL) {
		printk("could not find ipd %d\n", id);
		return -1;
	}
	printk_red("handles from %d\n", id);
	HandleTable_iterate(&ipd->conn_handle_table, (HandleTable_IterateFunc)conn_handle_printer, NULL);
	return 0;
}
DECLARE_SHELL_COMMAND(connipd, shell_connipd, "connipd <ipd_num> -- list all connections ipd_num");

int shell_examine_thread(int ac, char **av) {
	if(ac < 2) {
		printk_red("expects thread id\n");
		return -1;
	}
	int thread_id = atoi(av[1]);
	BasicThread *t = nexusthread_find(thread_id);
	if(t == NULL) {
		printk_red("thread id %d not found\n", thread_id);
		return -1;
	}
	IPD *ipd = nexusthread_get_base_ipd(t);
	printk_red("Thread %d is in IPD %d\n", thread_id, (ipd != NULL) ? ipd->id : -1);
	nexusthread_dump_regs_stack(t);
	nexusthread_put(t);
	return 0;
}
DECLARE_SHELL_COMMAND(xt, shell_examine_thread, "xt <thread_id> -- Dump the state of <thread_id>");
#endif


int shell_kill_ipd(int ac, char **av) {
	if(ac < 2) {
		printk_red("expects ipd id\n");
		return -1;
	}
	IPD_ID ipd_id = atoi(av[1]);
	IPD *ipd = ipd_find(ipd_id);
	if(ipd == NULL) {
		printk_red("could not find ipd_id %d\n", ipd_id);
		return -1;
	}
	ipd_killall(ipd);
	return 0;
}
DECLARE_SHELL_COMMAND(kill, shell_kill_ipd, "kill <ipd_id> -- Kill IPD <ipd_id>");

int shell_kill_thread(int ac, char **av) {
	if (ac != 2) 
		return BAD_USAGE;

	int tid = atoi(av[1]);
	if (tid == curt->id) {
		printk("Error. Will not commit suppuku\n");
		return BAD_USAGE;
	}

	BasicThread *t = nexusthread_find(tid);
	if (!t) {
		printk("Error. Not found\n");
		return 1;
	}

	if (!nexusthread_kill(t))
		printk("killed\n");
	else
		printk("not killed\n");

	nexusthread_put(t);
	return 0;
}

DECLARE_SHELL_COMMAND(killt, shell_kill_thread, "[thread_id] -- kill a thread");


int 
shell_selftest(int argc, char **argv) 
{
	unittest_runall_early();
	unittest_runall_late();
	return 0;
}

DECLARE_SHELL_COMMAND(selftest, shell_selftest, "Run all in-kernel selftests");

#if 0
#define FORKTESTLEN 4
static int 
__shell_fork_child(void *name) 
{
	int i;
	
	for (i = 0; i < FORKTESTLEN; i++) {
		printk("<Thread %d>: %s\n", nexusthread_id(nexusthread_self()), 
		       (char *) name);
		nexusthread_yield();
	}

	gfree(name);
	return 0;
}

int 
shell_fork(int ac, char **av) 
{
	char *name, *in; 
	int nlen;

	if (ac > 1)
		in = av[1];
	else
		in = "noarg";

	nlen = strlen(in);
	name = galloc(nlen + 1);
	strcpy(name, in);
	name[nlen] = '\0';

	nexusthread_fork(__shell_fork_child, name);
	return 0;
}

DECLARE_SHELL_COMMAND(fork, shell_fork, "[name] -- fork of a kernel thread");

int kernelexiter(void *arg) {
	printk("<Kexiter %d>\n", nexusthread_id(nexusthread_self()));
	nexusthread_exit();
	return 0;
}
int shell_kexiter(int ac, char **av) {
	nexusthread_fork(kernelexiter, NULL);
	return 0;
}
DECLARE_SHELL_COMMAND(kexiter, shell_kexiter, "-- ask alan");

int alarmtesthelper(void *arg) {
	Sema *s;
	int delta = *(int *)arg;

	s = sema_new();
	register_alarm(delta, (void *)V, (void *)s);
	printk("<Thread %d>: Going to sleep for an alarm in %d ticks\n",
			nexusthread_id(nexusthread_self()),
			delta);
	P(s);
	printk("<Thread %d>: Woke up from an alarm in %d ticks\n",
			nexusthread_id(nexusthread_self()),
			delta);
	sema_destroy(s);
	return 0;
}
int shell_alarm(int ac, char **av) {
	int *delta = galloc(sizeof(int));
	*delta = (ac > 1 ? atoi(av[1]) : 100);
	nexusthread_fork(alarmtesthelper, delta);
	return 0;
}
DECLARE_SHELL_COMMAND(alarm, shell_alarm, "[delta] -- ask alan");
#endif

DECLARE_SHELL_COMMAND_GROUP(network, "Networking");

int shell_ifconfig(int ac, char **av) {
	printk("host mac:       %02hx.%02hx.%02hx.%02hx.%02hx.%02hx\n"
	       "host ip:        %hu.%hu.%hu.%hu\n"
	       "netmask:        %hu.%hu.%hu.%hu\n"
	       "gateway ip:     %hu.%hu.%hu.%hu\n" 
	       "server mac:     %02hx.%02hx.%02hx.%02hx.%02hx.%02hx\n"
	       "server ip:      %hu.%hu.%hu.%hu\n\n"
	       "packets:	%u\n",
	       default_mac_address[0] & 0xff, default_mac_address[1] & 0xff, 
	       default_mac_address[2] & 0xff, default_mac_address[3] & 0xff, 
	       default_mac_address[4] & 0xff, default_mac_address[5] & 0xff,
	       (my_ipaddress >> 0)  & 0xff, (my_ipaddress >>  8) & 0xff,
	       (my_ipaddress >> 16) & 0xff, (my_ipaddress >> 24) & 0xff,
	       (my_netmask >> 0)    & 0xff, (my_netmask >>  8) & 0xff,
	       (my_netmask >> 16)   & 0xff, (my_netmask >> 24) & 0xff,
	       (my_gateway >> 0)    & 0xff, (my_gateway >>  8) & 0xff,
	       (my_gateway >> 16)   & 0xff, (my_gateway >> 24) & 0xff,
	       serverip[0], serverip[1], serverip[2], serverip[3],
	       server_mac[0] & 0xff, server_mac[1] & 0xff, 
	       server_mac[2] & 0xff, server_mac[3] & 0xff, 
	       server_mac[4] & 0xff, server_mac[5] & 0xff,
	       switch_packetcount);
	return 0;
}
DECLARE_SHELL_COMMAND(ifconfig, shell_ifconfig, "-- network interface info");

int shell_setserver(int ac, char **av) {
	if (ac != 2)
		return BAD_USAGE;

	set_server(av[1]);
	return 0;
}
DECLARE_SHELL_COMMAND(server, shell_setserver, "[ip] -- set the default TFTP server");

#if 0
DECLARE_SHELL_COMMAND_GROUP(file, "tftp fetch and send tests (deprecated)");

#include <nexus/tpm_platform.h> /* for tpm_crt's */
int shell_tftp_fetch_tpmcerts(int ac, char **av) {
  if(ac != 4)
    return BAD_USAGE;
  
  tpm_platform_crt = fetch_file(av[1], &tpm_platform_crt_len);
  tpm_conformance_crt = fetch_file(av[2], &tpm_conformance_crt_len);
  tpm_ek_crt = fetch_file(av[3], &tpm_ek_crt_len);
  
  return 0;
}
DECLARE_SHELL_COMMAND(tftp_fetch_tpmcerts, shell_tftp_fetch_tpmcerts, "[platform.crt] [conformance.crt] [ek.crt] ... -- fetch tpmcerts via tftp");

/** Shell command to retrieve files from the cache or network.
 
    @param av contains a list of filenames
    @return 0 on success , -1 on failure */
int shell_fetch(int ac, char **av) {
	int i, size;
	char *file;

	if (ac < 2) 
		return BAD_USAGE;

	for (i = 1; i < ac; i++) {
		file = fetch_file(av[i], &size);
		if (!file) {
			printk("[tftp] Error: aborting\n");
			return -1;
		}

		printk("[tftp] OK: retrieved %dB\n", size);
	}

	return 0;
}
DECLARE_SHELL_COMMAND(fetch, shell_fetch, "[filename] ... -- fetch and dump files via tftp");

DECLARE_SHELL_COMMAND_GROUP(netaudio, "audio support");

extern unsigned int i810_set_my_dac_rate(unsigned int rate);
extern ssize_t i810_write(const char *buffer, size_t count, loff_t *ppos);
extern int i810_init_module (void);
extern int i810_myinit(void);

int shell_audio(int ac, char **av) {
	static int audio_initialized = 0;
	if (ac != 1) return BAD_USAGE;
	if(audio_initialized) {
		printk("Audio already initialized!\n");
		// return 0 to hide error from regression test
		return 0;
	}
	audio_initialized = 1;
	i810_init_module();
	i810_myinit();
	return 0;
}
DECLARE_SHELL_COMMAND(audio, shell_audio, "-- initialize audio sub-system");

int shell_dac(int ac, char **av) {
	if (ac != 2) return BAD_USAGE;
	int rate = i810_set_my_dac_rate(atoi(av[1]));
	printk("Audio playback rate set to %d Hz\n", rate);
	return 0;
}
DECLARE_SHELL_COMMAND(audio_rate, shell_dac, "rate -- play raw audio file");

int shell_play(int ac, char **av) {
	int size, i;

	if (ac < 2 || ac > 3) return BAD_USAGE;

	char *file = fetch_file(av[1], &size);
	if (!file) return -1;

	if (ac == 3) i810_set_my_dac_rate(atoi(av[2]));
	printk("Sending %d bytes to i810_write\n", size);
#define CHUNKSIZE 1024
	for(i = 0; i < size - CHUNKSIZE; ){
		i += i810_write(file + i, CHUNKSIZE & ~0x3, NULL);
	}
	printk("Played %d bytes\n", i);
	gfree(file);
	return 0;
}
DECLARE_SHELL_COMMAND(play, shell_play, "file [rate] -- play raw audio file");
#endif

DECLARE_SHELL_COMMAND_GROUP(processor, "Hardware Configuration");

int shell_memutil(int ac, char **av) {
	dump_page_utilization();
	return 0;
}
DECLARE_SHELL_COMMAND(memutil, shell_memutil, "-- print mem utilization");

int shell_leds(int ac, char **av) {
	if (!strcmp(av[0], "ledson")) nexus_ledson();
	else if (!strcmp(av[0], "ledsoff")) nexus_ledsoff();
	else {
		if (ac != 2) return BAD_USAGE;
		printk("setting leds to 0x%x\n", atoi(av[1]));
		nexus_leds(atoi(av[1]));
	}
	return 0;
}
DECLARE_SHELL_COMMAND(leds, shell_leds, "int -- set keyboard LED state");
DECLARE_SHELL_COMMAND(ledson, shell_leds, "-- turn on keyboard LEDs ");
DECLARE_SHELL_COMMAND(ledsoff, shell_leds, "-- turn off keyboard LEDs ");

int shell_preempt(int ac, char **av) {
	if (ac < 2)
		printk("preemption is %s.\n", preemption_enabled ? "on" : "off");
	else {
		preemption_enabled = atoi(av[1]);
		printk("preemption is now %s.\n", preemption_enabled ? "on" : "off");
	}
	return 0;
}
DECLARE_SHELL_COMMAND(preempt, shell_preempt, "[0|1] -- print preemption status");

#if 0
/// XXX fix
int shell_mouse(int ac, char **av) {
  psaux_init();
  return 0;
}
DECLARE_SHELL_COMMAND(mouse, shell_mouse, " -- activate mouse device ");
#endif

#if 0

int shell_divzero(int ac, char **av) {
	int x = 5, y = 0;
	print_idt();
	x = x / y;
	printk("divzero caused no fault?\n");
	return 0;
}
DECLARE_SHELL_COMMAND(divzero, shell_divzero, "divide by zero and cause a trap");

int shell_pfault(int ac, char **av) {
	if (ac < 2) return BAD_USAGE;
	int *ptr = (int *) hexatoi(av[1]);
	print_idt();
	printk("And now we fault at address 0x%x!\n", (unsigned int) ptr);
	int x = *ptr;
	printk("Read %d from address 0x%x\n", x, (unsigned int) ptr);
	return 0;
}
DECLARE_SHELL_COMMAND(pfault, shell_pfault, "addr -- read and probably pfault at address");

int shell_pcheck1(int ac, char **av) {
	if (ac < 2) return BAD_USAGE;
	unsigned int addr = hexatoi(av[1]);
	printk("Checking address 0x%x!\n", addr);
	unsigned int pdbr = readcr3();
	printk("PDBR=0x%x\n", pdbr);
	int i = (addr >> 22) & 0x3ff;
	printk("upper ten bits =0x%x\n", i);
	DirectoryEntry *dirent = (DirectoryEntry *)(pdbr + i * sizeof(DirectoryEntry));
	printk("directory entry is =0x%x\n", *((int *)(pdbr + i * sizeof(DirectoryEntry))));
	printk("physaddr 0x%x %d big=%d %d accessed=%d uncached=%d writethrough=%d user=%d rw=%d present=%d\n",
			dirent->physaddr,   dirent->globalpage,   dirent->bigpage,
			dirent->reserved,   dirent->accessed,   dirent->uncached,   dirent->writethrough,
			dirent->user,   dirent->rw,   dirent->present);
	return 0;
}
DECLARE_SHELL_COMMAND(pcheck1, shell_pcheck1, "addr - check the page entries for addr somehow");

int shell_pcheck2(int ac, char **av) {
	if (ac < 2) return BAD_USAGE;
	unsigned int addr = hexatoi(av[1]);

	printk("Checking address 0x%x!\n", (unsigned int) addr);
	unsigned int pdbr = readcr3();
	printk("PDBR=0x%x\n", pdbr);
	int i = (addr >> 22) & 0x3ff;
	printk("upper ten bits =0x%x\n", i);
	DirectoryEntry *dirent = (DirectoryEntry *)PHYS_TO_VIRT(pdbr + i * sizeof(DirectoryEntry));
	printk("directory entry is =0x%x\n", *((int *)PHYS_TO_VIRT(pdbr + i * sizeof(DirectoryEntry))));
	printk("size=%d physaddr 0x%x %d big=%d %d accessed=%d uncached=%d writethrough=%d user=%d rw=%d present=%d\n",
			sizeof(DirectoryEntry),
			dirent->physaddr,   dirent->globalpage,   dirent->bigpage,
			dirent->reserved,   dirent->accessed,   dirent->uncached,   dirent->writethrough,
			dirent->user,   dirent->rw,   dirent->present);

	if(!dirent->present) return -1;

	i = (addr >> 12) & 0x3ff;
	printk("middle ten bits = 0x%x\n", i);
	PageTableEntry *pte = (PageTableEntry *)PHYS_TO_VIRT((dirent->physaddr << 12) + i * sizeof(PageTableEntry));

	printk("size=%d pagebase 0x%x %d reserved=%d dirty=%d accessed=%d uncached=%d writethrough=%d user=%d rw=%d present=%d\n",
			sizeof(PageTableEntry),
			pte->pagebase,   pte->globalpage,   pte->reserved,
			pte->dirty,  pte->accessed,   pte->uncached,   pte->writethrough,
			pte->user,   pte->rw,   pte->present);
	return 0;
}
DECLARE_SHELL_COMMAND(pcheck2, shell_pcheck2, "addr - check the page entries for addr some other way");

int shell_cr0(int ac, char **av) {
	printk("cr0 = 0x%x\n", readcr0());
	return 0;
}
DECLARE_SHELL_COMMAND(cr0, shell_cr0, "-- print cr0");

int shell_cr4(int ac, char **av) {
	printk("cr4 = 0x%x\n", readcr4());
	return 0;
}
DECLARE_SHELL_COMMAND(cr4, shell_cr4, "-- print cr4");
#endif

int shell_irq(int ac, char **av) {
	if (!strcmp(av[0], "irq_mask")) {
		int mask = getirqmask();
		printk("irq mask: %x ", mask);
		if (!mask)
			printk("(all irqs disabled)\n");
		else {
			printk("(enabled irqs are:");
			int i;
			for (i = 0; i < 16; i++)
				if (!(mask & (1<<i)))
					printk(" %d", i);
			printk(")\n");
		}
	} else if(!strcmp(av[0], "irq_enable")) {
		if (ac < 2) return BAD_USAGE;
		int irq = atoi(av[1]);
		printk("enabling irq %d\n", irq);
		enable_8259A_irq(irq);
	} else if(!strcmp(av[0], "irq_disable")) {
		if (ac < 2) return BAD_USAGE;
		int irq = atoi(av[1]);
		printk("disabling irq %d\n", irq);
		disable_8259A_irq(irq);
	} else {
		printk_red("irq unsupported operation '%s'\n", av[0]);
	}
	return 0;
}
DECLARE_SHELL_COMMAND(irq_enable, shell_irq, "num -- enable an irq");
DECLARE_SHELL_COMMAND(irq_disable, shell_irq, "num -- disable an irq");
DECLARE_SHELL_COMMAND(irq_mask, shell_irq, "-- show irq mask");

static struct pci_device_id e1000_pci_tbl[] /* __devinitdata */ = {
	{0x8086, 0x1000, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x1001, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x1004, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x1008, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x1009, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x100C, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x100D, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x100E, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x100F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x1011, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x1010, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x1012, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x1016, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x1017, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x101E, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x101D, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x1013, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x1019, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	/* required last entry */
	{0,}
};

void dump_pci_dev(const struct pci_dev *pdev) {
	int i;

	printk("0x%x: ",(unsigned int)pdev);
	if (pdev == NULL){
		printk("null\n");
	}else{
		printk("global list next addr: 0x%x, ", (unsigned int) pdev->global_list.next);
		printk("global list prev addr: 0x%x, ", (unsigned int) pdev->global_list.prev);
		printk("bus list next addr: 0x%x, ", (unsigned int) pdev->bus_list.next);
		printk("bus list prev addr: 0x%x\n", (unsigned int) pdev->bus_list.prev);
		printk("bus addr: 0x%x, \n", (unsigned int) pdev->bus);

		printk("sub bus addr: 0x%x, ", (unsigned int) pdev->subordinate);
		printk("sysdata addr: 0x%x, ", (unsigned int) pdev->sysdata);
		printk("procent addr: 0x%x\n", (unsigned int) pdev->procent);
		printk("devfn: 0x%x, ", pdev->devfn);
		printk("vendor: 0x%x, ", pdev->vendor);
		printk("device: 0x%x, ", pdev->device);
		printk("subsystem_vendor: 0x%x\n", pdev->subsystem_vendor);
		printk("subsystem_device: 0x%x, ", pdev->subsystem_device);
		printk("class: 0x%x, ", pdev->class);
		printk("hdr_type: 0x%x, ", pdev->hdr_type);
		printk("base_reg: 0x%x, ", pdev->rom_base_reg);
		printk("driver addr: 0x%x\n", (unsigned int) pdev->driver);
		printk("driver_data addr: 0x%x, ", (unsigned int) pdev->driver_data);
		printk("dma_mask: 0x%llx, ", pdev->dma_mask);
		printk("current_state: 0x%x\n", pdev->current_state);

		printk("vendor_compatible: ");
		for(i = 0; i < DEVICE_COUNT_COMPATIBLE; i++)
			printk("0x%x ", pdev->vendor_compatible[i]);
		printk("\ndevice_compatible: ");
		for(i = 0; i < DEVICE_COUNT_COMPATIBLE; i++)
			printk("0x%x ", pdev->device_compatible[i]);
		printk("irq: 0x%x\n", pdev->irq);

		printk("resource: ");
		for(i = 0; i < DEVICE_COUNT_RESOURCE; i++){
			printk("name %s ", pdev->resource[i].name);
			printk("start 0x%lx ", pdev->resource[i].start);
			printk("end 0x%lx ", pdev->resource[i].end);
			printk("flags 0x%lx ", pdev->resource[i].flags);
			printk("parent 0x%x ", (unsigned int)pdev->resource[i].parent);
			printk("sibling 0x%x ", (unsigned int)pdev->resource[i].sibling);
			printk("child 0x%x\n", (unsigned int)pdev->resource[i].child);
		}
		printk("dma_resource: ");
		for(i = 0; i < DEVICE_COUNT_DMA; i++){
			printk("name %s ", pdev->dma_resource[i].name);
			printk("start 0x%lx ", pdev->dma_resource[i].start);
			printk("end 0x%lx ", pdev->dma_resource[i].end);
			printk("flags 0x%lx ", pdev->dma_resource[i].flags);
			printk("parent 0x%x ", (unsigned int)pdev->dma_resource[i].parent);
			printk("sibling 0x%x ", (unsigned int)pdev->dma_resource[i].sibling);
			printk("child 0x%x\n", (unsigned int)pdev->dma_resource[i].child);
		}
		printk("irq_resource: ");
		for(i = 0; i < DEVICE_COUNT_IRQ; i++){
			printk("name %s ", pdev->irq_resource[i].name);
			printk("start 0x%lx ", pdev->irq_resource[i].start);
			printk("end 0x%lx ", pdev->irq_resource[i].end);
			printk("flags 0x%lx ", pdev->irq_resource[i].flags);
			printk("parent 0x%x ", (unsigned int)pdev->irq_resource[i].parent);
			printk("sibling 0x%x ", (unsigned int)pdev->irq_resource[i].sibling);
			printk("child 0x%x\n", (unsigned int)pdev->irq_resource[i].child);
		}
		printk("name: %s\n", pdev->name);
		printk("slot_name: %s ", pdev->slot_name);
		printk("active = %d ", pdev->active);
		printk("ro = %d ", pdev->ro);
		printk("regs = 0x%x ", pdev->regs);
		printk("transparent = 0x%x\n", pdev->transparent);
		printk("prepare addr: 0x%x, ", (unsigned int) pdev->prepare);
		printk("activate addr: 0x%x, ", (unsigned int) pdev->activate);
		printk("deactivate addr: 0x%x\n", (unsigned int) pdev->deactivate);
	}
}

void dump_pci_id(struct pci_device_id *ent) {
	printk("pci_id: 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%lx\n",
			ent->vendor,
			ent->device,
			ent->subvendor,
			ent->subdevice,
			ent->class,
			ent->class_mask,
			ent->driver_data);
}

void dump_pci_bus(struct pci_bus *bus) {
	//bus->ops = fake_ops;
	//bus->sysdata = NULL;
	//bus->procdir = NULL;

	printk("num=0x%x ", bus->number);
	printk("pri=0x%x ", bus->primary);
	printk("sec=0x%x ", bus->secondary);
	printk("sub=0x%x ",   bus->subordinate);

	printk("name=%s ",bus->name);
	printk("vend=0x%x ",   bus->vendor);
	printk("dev=0x%x ",   bus->device);
	printk("ser=0x%x ",   bus->serial);
	printk("pnpver=0x%x ",   bus->pnpver);
	printk("prodver=0x%x ",   bus->productver);
	printk("cksm=0x%x ",   bus->checksum);
	printk("pad=0x%x ",   bus->pad1);
}

void dump_pci_ops(struct pci_ops *ops) {
	printk("ops: 0x%x ", (unsigned int)ops->read_byte);
	printk("0x%x ", (unsigned int)ops->read_word);
	printk("0x%x ", (unsigned int)ops->read_dword);
	printk("0x%x ", (unsigned int)ops->write_byte);
	printk("0x%x ", (unsigned int)ops->write_word);
	printk("0x%x\n", (unsigned int)ops->write_dword);
}

const struct pci_dev *find_pci_dev(const struct pci_dev *dev) {
	struct pci_device_id *ids = e1000_pci_tbl;

	while (ids->vendor || ids->subvendor || ids->class_mask) {
		if ((ids->vendor == PCI_ANY_ID || ids->vendor == dev->vendor) &&
				(ids->device == PCI_ANY_ID || ids->device == dev->device) &&
				(ids->subvendor == PCI_ANY_ID || ids->subvendor == dev->subsystem_vendor) &&
				(ids->subdevice == PCI_ANY_ID || ids->subdevice == dev->subsystem_device) &&
				!((ids->class ^ dev->class) & ids->class_mask)){
			dump_pci_id(ids);
			return dev;
		}
		ids++;
	}
	return NULL;
}

int dump_pci_giga(int ac, char **av) {
	struct pci_dev *dev;
	pci_for_each_dev(dev) {
		if (find_pci_dev(dev)){
			dump_pci_dev(dev);
			dump_pci_bus(dev->bus);
			dump_pci_ops(dev->bus->ops);
		}
	}
	return 0;
}
DECLARE_SHELL_COMMAND(dump_pci, dump_pci_giga, "-- find and dump e1000 pci info");
#if 0
int shell_nocache(int ac, char **av) {
	printk("turning off caching\n");
	unsigned int oldcr0 = readcr0();
	writecr0((oldcr0 & ~(1 << 29)) | (1 << 30));
	__asm("wbinvd");
	printk("invalidated cache\n");
	return 0;
}
DECLARE_SHELL_COMMAND(nocache, shell_nocache, "-- disable hardware cache");

#include <asm/e820.h>
int shell_biosmap(int ac, char **av) {
	int i, j;
	int printed = 0;
	extern char _end;

	//use map copied from BIOS e820
	for (i = 0; i < e820.nr_map; i++) {
		unsigned long start, end;
		/* RAM? */
		if (e820.map[i].type != E820_RAM)
			continue;

		printk("end of kernel = 0x%p\n", (void *) VIRT_TO_PHYS(&_end));

		start = e820.map[i].addr;
		end = e820.map[i].addr + e820.map[i].size;
		printk("original start = 0x%lx end = 0x%lx\n", start, end);

		start = round((e820.map[i].addr + (PAGESIZE - 1)), PAGESIZE);   //round up
		end = round((e820.map[i].addr + e820.map[i].size), PAGESIZE); //round down
		printk("rounded start = 0x%lx end = 0x%lx\n", start, end);

		start = max(round((e820.map[i].addr + PAGESIZE - 1), PAGESIZE),
				round((VIRT_TO_PHYS(&_end) + PAGESIZE - 1), PAGESIZE));   //round up
		printk("start becomes 0x%lx\n", start);

		printk("adding page: ");
		for(j = start; j < end && printed < 20; j += PAGESIZE){
			printk("0x%x ", j);
			printed++;
		}
		printk("\n");
	}
	return 0;
}
DECLARE_SHELL_COMMAND(biosmap, shell_biosmap, "-- print bios e820 mem map");
#endif

#define CLOCK_TICK_RATE 1193182 /* Underlying HZ of 8254 counter */
#define CALIBRATE_TIME_MSEC 30 /* 30 msec */
#define CALIBRATE_LATCH \
  ((CLOCK_TICK_RATE * CALIBRATE_TIME_MSEC + 1000/2)/1000)

static inline void mach_prepare_counter(void)
{
  /* Set the Gate high, disable speaker */
  outb((inb(0x61) & ~0x02) | 0x01, 0x61);

  /*
   * Now let's take care of CTC channel 2
   *
   * Set the Gate high, program CTC channel 2 for mode 0,
   * (interrupt on terminal count mode), binary count,
   * load 5 * LATCH count, (LSB and MSB) to begin countdown.
   *
   * Some devices need a delay here.
   */
  outb(0xb0, 0x43);                       /* binary, mode 0, LSB/MSB, Ch 2 */
  outb_p(CALIBRATE_LATCH & 0xff, 0x42);   /* LSB of count */
  outb_p(CALIBRATE_LATCH >> 8, 0x42);       /* MSB of count */
}

static inline void mach_countup(unsigned long *count_p)
{
  unsigned long count = 0;
  do {
    count++;
  } while ((inb_p(0x61) & 0x20) == 0);
  *count_p = count;
}

#include <asm/div64.h>
static unsigned long calculate_cpu_khz(void)
{
  unsigned long long start, end;
  unsigned long count;
  u64 delta64;
  int i;
  unsigned long intlevel;

  intlevel = disable_intr();

  /* run 3 times to ensure the cache is warm */
  for (i = 0; i < 3; i++) {
    mach_prepare_counter();
    start = rdtsc64();
    mach_countup(&count);
    end = rdtsc64();
  }
  /*
   * Error: ECTCNEVERSET
   * The CTC wasn't reliable: we got a hit on the very first read,
   * or the CPU was so fast/slow that the quotient wouldn't fit in
   * 32 bits..
   */
  if (count <= 1)
    goto err;

  delta64 = end - start;

  /* cpu freq too fast: */
  if (delta64 > (1ULL<<32))
    goto err;

  /* cpu freq too slow: */
  if (delta64 <= CALIBRATE_TIME_MSEC)
    goto err;

  delta64 += CALIBRATE_TIME_MSEC/2; /* round for do_div */
  do_div(delta64,CALIBRATE_TIME_MSEC);

  restore_intr(intlevel);
  return (unsigned long)delta64;
err:
  restore_intr(intlevel);
  return 0;
}

int shell_clock(int ac, char **av) {
	int i;
	printk("---- clock timing test ----\n");
	unsigned long start, cur, end;
	long long tsc;
	printk("HZ = %d interrupts per second\n", HZ);
	printk("tsc_per_jiffie = %lu (assumed) kilocylces per interupt\n", tsc_per_jiffie);
	printk("tsc_per_jiffie = %d (default) kilocylces per interupt\n", TSCCONST_DEFAULT);
	for (i = 0; i < 10; i++) {
	  long khz = calculate_cpu_khz();
	  printk("measured khz = %ld\n", khz);
	}
	start = nexustime;
	end = start + 10*HZ;
	printk("start = %lu.%03lu sec and counting...\n", start/HZ, start%HZ);
	do {
		cur = nexustime;
		if (cur > start+HZ) {
			printk("  tick %lu.%03lu sec\n", cur/HZ, cur%HZ);
			start = cur;
		}
	} while (cur < end);
	printk("Calling rdtsc() a bunch... ");
	for (i=0; i<10000; i++) {
		tsc = rdtsc64();
	}
	printk("Done.\n");
	printk("---- end timing test ----\n");
	return 0;
}
DECLARE_SHELL_COMMAND(clock, shell_clock, "-- run clock timing tests");

int shell_ctsc(int ac, char **av) {
	long khz = calculate_cpu_khz();
	if (khz < 1000 || khz > 100*1000*1000) {
	  printk("Could not detect processor frequency: %lu.%06lu GHz ???\n", khz/1000000, khz%1000000);
	  return 1;
	}
	printk("Detected %lu.%06lu GHz processor\n", khz/1000000, khz%1000000);
	tsc_per_jiffie = (khz+500)/1000;
	printk("  set TSC_CONST to %lu\n", tsc_per_jiffie);
	return 0;
}
DECLARE_SHELL_COMMAND(ctsc, shell_ctsc, "-- detect and calibrate TSC frequency");
int shell_stsc(int ac, char **av) {
	if (ac != 2) {
	  printk("usage: stsc mhz -- manually set TSC frequency\n");
	  return 1;
	}
	int mhz = atoi(av[1]);
	if (mhz <= 0) {
	  printk("bad tsc value: %s\n", av[1]);
	  return 1;
	}
	tsc_per_jiffie = mhz;
	printk("  set TSC_CONST to %lu\n", tsc_per_jiffie);
	return 0;
}
DECLARE_SHELL_COMMAND(stsc, shell_stsc, "mhz -- manually set TSC frequency");

int shell_gtod(int ac, char **av) {
	int seconds;
	int usecs;
	int time = nexustime;

	seconds  = time;
	seconds *= USECPERTICK;
	seconds /= 1000000;

	usecs   = time * USECPERTICK;
	usecs  -= seconds * 1000000;
	seconds += ntp_offset;
	printk("seconds = %d, usecs = %d\n", seconds, usecs);
	return 0;
}
DECLARE_SHELL_COMMAND(gtod, shell_gtod, "-- print time of day");

#if 0
int shell_mtrr_dump(int ac, char **av) {
	mtrr_dump();
	return 0;
}
DECLARE_SHELL_COMMAND(mtrr, shell_mtrr_dump, "-- dump mtrrs");


int shell_vesa_init(int ac, char **av) {
	return vesafb_init();
}
DECLARE_SHELL_COMMAND(vesa_init, shell_vesa_init, "-- reinit vesa (sets up mtrrs)");
#endif

#if 0
int shell_zap(int ac, char **av) {
	/*Zap the zero page */
	unsigned int *pdiraddr = (unsigned int *)PHYS_TO_VIRT(readcr3() & 0xfffff000);
	unsigned int pdirentry = *pdiraddr;
	unsigned int *ptba = (unsigned int *)PHYS_TO_VIRT(pdirentry & 0xffff000);
	*ptba = 0;

	/* need to flush the TLB */
	flushglobalTLB();
	printk("zapped zero page\n");
	return 0;
}
DECLARE_SHELL_COMMAND(zap, shell_zap, "-- zap the zero page");

int shell_heap(int ac, char **av){
  int testsize = 1024;
  char *test;
  printk_red("underflow\n");
  test = galloc(testsize);
  strcpy(test-5, "hello");
  gfree(test);
  
  printk_red("overflow\n");
  test = galloc(testsize);
  strcpy(test+testsize, "hello");
  gfree(test);
  printk_red("done\n");
  return 0;
}

DECLARE_SHELL_COMMAND(heap, shell_heap, "-- Intentionally smash heap to trigger heap guard");
#endif

#if 0
int shell_dumpscreens(int ac, char **av){
  extern void screen_dump(void *voidipd, void *ignore);

  if (strcmp(av[0], "dumpscreens") == 0){
    ipd_iterate(screen_dump, NULL);    
  }
  else if (strcmp(av[0], "dumpscreen") == 0){
    if(ac < 2) return BAD_USAGE;
    screen_dump(ipd_find(atoi(av[1])), NULL);
  }
  return 0;
}
DECLARE_SHELL_COMMAND(dumpscreen, shell_dumpscreens, "num -- dumpscreen");
DECLARE_SHELL_COMMAND(dumpscreens, shell_dumpscreens, "-- dumpscreens");
#endif

DECLARE_SHELL_COMMAND_GROUP(tpm_stuff, "TPM");

extern int init_nsc(void);
extern int init_atmel(void);
int shell_tpm(int ac, char **av) {
	NexusDevice *dev;
	if (tpm_present && ac == 2 && !strcmp(av[1], "unload")) {
		printk("shutting down previously loaded tpm driver\n");
		dev = find_device(DEVICE_TPM, "tpm0");
		if (!dev) {
			printk("oops: no driver loaded\n");
			return 1;
		}
		if (!dev->data) {
			printk("oops: driver is garbage\n");
			return 1;
		}
		if (!((struct device_tpm_ops *)dev->data)->shutdown) {
			printk("oops: driver is garbage\n");
			return 1;
		}
		((struct device_tpm_ops *)dev->data)->shutdown();
		tpm_present = 0;
		return 0;
	} else if (tpm_present) {
		printk("tpm driver already loaded: use \"tpm unload\" to unload driver\n");
		return -1;
	}

	int ret = -1;
	printk("trying to load tpm driver\n");
	char *arg = "probe";
	if (ac > 1) arg = av[1];
	if (!strcmp(arg, "nsc"))
		ret = init_nsc();
	else if (!strcmp(arg, "atmel"))
		ret = init_atmel();
	else if (!strcmp(arg, "probe")) {
		printk("... trying nsc\n");
		ret = init_nsc();
		if (ret) {
			printk("... trying amtel\n");
			ret = init_atmel();
		}
	} else return BAD_USAGE;

	if (ret == 0) {
		tpm_present = 1;
		printk("TPM driver loaded: %s\n", arg);
		dev = find_device(DEVICE_TPM, "tpm0");
		if (dev == NULL) {
		  printk("oops: no driver loaded\n");
		  return -1;
		}
		printk("Device loaded as: %s\n", dev->name);
		extern int tcpa_discover_version(void);
		tcpa_discover_version();
	} else {
		printk("TPM driver did not load: %d\n", ret);
	}
	return 0;
}
DECLARE_SHELL_COMMAND(tpm, shell_tpm, "[probe|nsc|atmel|unload] -- load a suitable tpm driver, or unload it");

int shell_tcpademo(int ac, char **av) {
	extern int tcpademo(void);
	return tcpademo();
}
DECLARE_SHELL_COMMAND(tcpademo, shell_tcpademo, "-- run the tcpa demo");

int shell_evictkey(int ac, char **av) {
	if (ac != 2) return BAD_USAGE;
	return evictkey(hexatoi(av[1]));
}
DECLARE_SHELL_COMMAND(evictkey, shell_evictkey, "keyname -- evict a TPM key");

int shell_evictall(int ac, char **av) {
	return evictall();
}
DECLARE_SHELL_COMMAND(evictall, shell_evictall, "-- evict all TPM keys");

int test_vdir(int argc, char **argv);
DECLARE_SHELL_COMMAND(testvdir, test_vdir, "-- test vdir list archive and retrieve");

int shell_vdir(int ac, char **av) {
	int numgen = 0;
	if(ac > 1) numgen = atoi(av[1]);
	if(!DISABLE_TPM){
	  shell("tpm");
	  shell("evictall");
	  vdir_init();
	  //vkeyInit(numgen);
	}else{
	  vdir_init();
	}

	return 0;
}
DECLARE_SHELL_COMMAND(vdir, shell_vdir, " [numgen] -- how many vkeys to pre-generate");


int shell_clearvdir(int ac, char **av){
  vdir_clear_dbg(av[1]);
  return 0;
}
int shell_clearvkey(int ac, char **av){
  vkey_clear_dbg(av[1]);
  return 0;
}
DECLARE_SHELL_COMMAND(clearvdir, shell_clearvdir, " char* name -- the name of the vdir to destroy");
DECLARE_SHELL_COMMAND(clearvkey, shell_clearvkey, " char* name -- the name of the vkey to destroy");

#if 0
int shell_setnsk(int ac, char **av){
  char *filename = "nexus.nsk";
  if (ac > 1) filename = av[1];
  int size;
  char *file = fetch_file(filename, &size);
  if (!file) return -1;
  KVKey_nsk *nsk = nsk_deserialize((unsigned char *) file, size);
  gfree(file);
  if (!nsk) return -2;
  default_nsk = nsk;
  return 0;
}
DECLARE_SHELL_COMMAND(setnsk, shell_setnsk, " filename -- set the system default nsk");
#endif

int shell_dumpdev(int ac, char **av) {
	dump_devices();
	return 0;
}
DECLARE_SHELL_COMMAND(dumpdev, shell_dumpdev, "-- dump device table");

int shell_blitclear(int ac, char **av) {
	extern void nexus_blit_clear(void);
	nexus_blit_clear();
	return 0;
}
DECLARE_SHELL_COMMAND(blitclear, shell_blitclear, "-- clear screen");

#if 0
void nexus_fbcon_putc(char *, int, int);
int shell_putc(int ac, char **av) {
	int i;
	for (i = 0; i < 30; i++)
		nexus_fbcon_putc(av[ac-1], i+20, i);
	return 0;
}
DECLARE_SHELL_COMMAND(putc, shell_putc, "[char] -- scatter a char on screen");
#endif


#if 0
int shell_mouse_debug(int ac, char **av) {
  printk_red("Mouse log: ");
  mouse_dump_log();
  return 0;
}
DECLARE_SHELL_COMMAND(mouse_debug, shell_mouse_debug, " -- mouse debugging ");
#endif

