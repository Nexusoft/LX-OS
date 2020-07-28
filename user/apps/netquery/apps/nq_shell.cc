#include <nq/netquery.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <nq/net.h>
#include <nq/uuid.h>
#include <nq/site.hh>
#include <nq/marshall.hh>
#include <nq/attribute.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <set>
#include <ext/hash_map>

NQ_Host home;
using namespace __gnu_cxx;
using namespace std;
using namespace NQ_Output;

#define AUTORUN_COUNT (sizeof(autorun) / sizeof(autorun[0]))
char *autorun[] = { "list_tuples -t" };

OutputContext output_context(home);
ostream &operator<<(ostream &os, const NQ_Trigger_Desc_and_Dest &desc) {
  output_context.output_trigger(os, desc, true, true);
  return os;
}

int do_list_tuples_cmd(int argc, char **argv) {
  output_context.home = home;
  output_context.show_speaker = false;
  output_context.show_tid = false;
  output_context.show_type = false;
  output_context.show_triggers = false;
  output_context.all_tuple_triggers.clear();
  optind = 0; // reset getopt() internal state
  while(1) {
    int opt;
    switch( (opt = getopt(argc, argv, "at")) ) {
    case 'a':
      // add speaker and type
      output_context.show_speaker = true;
      output_context.show_tid = true;
      output_context.show_type = true;
      break;
    case 't':
      output_context.show_triggers = true;
      break;
    case -1:
      goto done;
    default:
      cerr << "Unknown option " << opt << "\n";
      break;
    }
  }
 done: ;
  NQ_Tuple *tuples;
  int tuple_count;
  int err = 0;
  if(optind != argc) {
    cerr << "Usage: list_tuples\n";
    return -1;
  }

  err = NQ_Enumerate_Tuples(home, &tuples, &tuple_count);
  if(err != 0) {
    cerr << "Error while enumerating all tuples\n";
    return err;
  }
  qsort(tuples, tuple_count, sizeof(tuples[0]), (int (*)(const void*, const void*))NQ_UUID_cmp);
  int i;
  output_context.tuple_aliases.resize(0);
  NQ_Transaction transaction = NQ_Transaction_begin();

  for(i=0; i < tuple_count; i++) {
    output_context.tuple_aliases.
      push_back( OutputContext::TupleAlias(tuples[i], string("%") + itos(i+1)) );
  }
  
  if(output_context.show_triggers) {
    NQ_Trigger_Desc_and_Dest *descs = NULL;
    int num_descs = 0;
    if( (err = NQ_Enumerate_Triggers(home, &descs, &num_descs)) != 0) {
      cerr << "err enumerating triggers\n";
      return err;
    }
    for(i=0; i < num_descs; i++) {
      output_context.all_tuple_triggers[descs[i].desc->tuple].insert(descs[i]);
    }
    free(descs);
    // XXX cleanup data
  }

  for(i=0; i < tuple_count; i++) {
    cout << "[%" << (i + 1) << "]";
    if(output_context.show_speaker) {
      cout << tuples[i];
    }
    cout << " = ";
    output_context.output_tuple(cout, transaction, tuples[i]);
  }
  err = NQ_Transaction_abort(transaction);
  return err;
}

int do_show_aliases_cmd(int argc, char **argv) {
  // aliases, i.e. %1-%n shortcuts for referring to tuples
  if(argc != 1) {
    cerr << "Usage: show_aliases\n";
    return -1;
  }
  unsigned i;
  for(i=0; i < output_context.tuple_aliases.size(); i++) {
    cout << "%" << (i + 1) << " " << output_context.tuple_aliases[i].tuple << "\n";
  }
  return 0;
}

NQ_Tuple parse_alias(char *arg) {
  unsigned alias = atoi(arg+1);
  if(alias == 0 || alias > output_context.tuple_aliases.size()) {
    cerr << "No such alias " << alias << "\n";
    return NQ_uuid_null;
  }
  return output_context.tuple_aliases[alias - 1].tuple;
}

int do_write_cmd(int argc, char **argv) {
  if(argc != 4) {
    cerr << "Usage: write <tuple alias, i.e. #<num> expression> <attr name> <value>\n";
    return -1;
  }
  if(argv[1][0] != '%') {
    cerr << "bad alias prefix\n";
    return -1;
  }

  NQ_Tuple tid = parse_alias(argv[1]);
  char *var_name = argv[2];

  if(tid == NQ_uuid_null) {
    return -1;
  }

  NQ_Transaction transaction = NQ_Transaction_begin();
  int err;
  char *str = argv[3];
  int len = sizeof(int) + strlen(str) + 1;
  char *pickled_data = (char *)malloc(len);
  *(int*)pickled_data = strlen(str) + 1;
  strcpy(pickled_data + sizeof(int), str);
  NQ_Attribute_Name *name = NQ_Attribute_Name_alloc(&home, NQ_ATTRIBUTE_RAW, var_name);
  err = NQ_Attribute_operate(transaction, &NQ_default_owner,
			     name, tid, 
			     NQ_OPERATION_WRITE, &pickled_data, &len, NULL);
  free(pickled_data);
  if(err != 0) {
    cerr << "error on attribute operate\n";
    return -1;
  }
  err = NQ_Transaction_commit(transaction);
  if(err != 0) {
    cerr << "error on commit\n";
    return -1;
  }
  return 0;
}

int do_exit_cmd(int argc, char **argv) {
  exit(0);
}

int do_help_cmd(int argc, char **argv);

int trigger_callback(NQ_Transaction transaction, NQ_Trigger_Description *trigger, NQ_Trigger_Upcall_Type type, int arg, void *userdata) {
  cerr << "Upcall\n";
  return 1;
}

int do_add_trigger_cmd(int argc, char **argv) {
  int err;

#if 0
  optind = 0; // reset getopt() internal state
  while(1) {
    int opt;
    switch( (opt = getopt(argc, argv, "at")) ) {

  if(argc - optind < 1) {
    cerr << "Usage: add_trigger ";
    return -1;
  }
#endif
  if(argc != 3) {
    cerr << "Usage: add_trigger <%%[num]|*> <attr_name>\n";
    return -1;
  }
  // <*, attribute name>
  NQ_Tuple tid;
  if(strcmp(argv[1], "*") == 0) {
    /* wildcard */
    tid = NQ_uuid_null;
  } else {
    tid = parse_alias(argv[1]);
    if(tid == NQ_uuid_null) {
      return -1;
    }  
  }
  char *var_name = argv[2];

  NQ_Transaction transaction = NQ_Transaction_begin();

  NQ_Trigger_Description *desc = (NQ_Trigger_Description *)malloc(sizeof(*desc));
  desc->name = NQ_Attribute_Name_alloc(&home, NQ_ATTRIBUTE_RAW, var_name);
  desc->tuple = tid;
  desc->type = NQ_TRIGGER_VALUECHANGED;
  desc->upcall_type = NQ_TRIGGER_UPCALL_SYNC_VERDICT | NQ_TRIGGER_UPCALL_ASYNC_COMMIT_DONE;

  NQ_Trigger trigger = NQ_Trigger_create(transaction, &NQ_default_owner, desc, trigger_callback, NULL);

  err = NQ_Transaction_commit(transaction);
  if(err != 0) {
    cerr << "error on commit\n";
    return -1;
  }
  return 0;
}

struct Command {
  char *str;
  int (*func)(int argc, char **argv);
} commands[] = {
  { "list_tuples", do_list_tuples_cmd },
  { "show_tuples", do_list_tuples_cmd },
  { "ls", do_list_tuples_cmd },
  { "show_aliases", do_show_aliases_cmd },

  { "add_trigger", do_add_trigger_cmd },

  // { "read", do_read_cmd },
  { "write", do_write_cmd },
  { "exit", do_exit_cmd },
  { "quit", do_exit_cmd },
  { "help", do_help_cmd },
};

#define NUM_COMMANDS ( sizeof(commands) / sizeof(commands[0]) )

int do_help_cmd(int argc, char **argv) {
  if(argc != 1) {
    cerr << "usage: help\n";
    return -1;
  }
  unsigned i;
  for(i=0; i < NUM_COMMANDS; i++) {
    cout << commands[i].str << "\n";
  }
  return 0;
}

int main(int argc, char **argv) {
  if(argc < 3 && argc != 1) {
  usage:
    cout << "Usage: nqsh [<host> <port>] \n";
    exit(-1);
  }
  NQ_init(NQ_PORT_ANY);
  NQ_cpp_lib_init();

  if(argc >= 3) {
    home.addr = inet_addr(argv[1]);
    home.port = atoi(argv[2]);
  } else {
    if(NQ_getenv_server(&home) != 0) {
      goto usage;
    }
  }

  NQ_Host h = NQ_Net_get_localhost();
  string principal_fname = NQ_Host_as_string(h) + ".principal";
  NQ_publish_principal(&NQ_default_owner, principal_fname.c_str());

  char line[1024];
#define MAX_ARGS (1024)
  int arg_size = MAX_ARGS * sizeof(char *);
  char **args = (char **)malloc(arg_size);
  unsigned autorun_pos = 0;
  while(1) {
    memset(args, 0, arg_size);
    printf("> ");
    if(autorun_pos < AUTORUN_COUNT) {
      strcpy(line, autorun[autorun_pos]);
      autorun_pos++;
    } else {
      fgets(line, sizeof(line), stdin);
    }
    int cur_arg = 0;
    unsigned i;
    for(i=0; line[i] != '\0'; i++) {
      switch(line[i]) {
      case '\n':
      case ' ':
      case '\t':
	line[i++] = '\0';
	while((line[i] == ' ' || line[i] == '\t') && line[i] != '\0') {
	  i++;
	}
	if(line[i] == '\0') goto done_processing;
	args[cur_arg++] = &line[i];
	break;
      default:
	if(cur_arg == 0) {
	  args[cur_arg++] = &line[i];
	}
	break;
      }
    }
  done_processing: ;
    if(cur_arg == 0) {
      continue;
    }
    int command_found = 0;
    for(i=0; i < NUM_COMMANDS; i++) {
      if(strcmp(args[0], commands[i].str) == 0) {
	command_found = 1;
	// printf("%s: calling\n", args[0]);
	commands[i].func(cur_arg, args);
	break;
      }
    }
    if(!command_found) {
      printf("%s: command not found\n", args[0]);
    }
    fflush(stdout);
    fflush(stderr);
  }
}
