#ifndef OPTION_LIST_H_SHIELD
#define OPTION_LIST_H_SHIELD

#include <vector>
#include <map>
#include <string>

#define OPTION_TYPEMASK 0x07
#define OPTION_TYPE_INT 0x01
#define OPTION_TYPE_STR 0x02
#define OPTION_TYPE_NULL 0x03

struct ltstr
{
  bool operator()(const char* s1, const char* s2) const
  {
    return strcmp(s1, s2) < 0;
  }
};

typedef  char *(*Command_Call)(std::map<char *,void *,ltstr> *options, void *userinfo);

struct Option_List {
  char *option;
  void *def;
  int flags;
};

struct Command_Entry {
  char *command;
  Command_Call call;
  void *userinfo;
  char *help;
  std::map<char*,Option_List *,ltstr> options;
};

class Command_List {
 public:
  Command_List();
  ~Command_List();
  
  void add_command(char *command, Command_Call call, void *userinfo);
  void set_help(char *command, char *help);
  void add_int_option(char *command, char *option);
  void add_str_option(char *command, char *option);
  void add_null_option(char *command, char *option); //null options are effectively booleans
  
  char *process_command(char *command);
  
 private:
  std::map<char *,Command_Entry *,ltstr> commands;
};

#define CMD_DEFUN(name) char *command_##name(std::map<char *,void *,ltstr> *options, void *userinfo)
#define CMD_ARG(name,type) type name = (type)((*options)[(char *)#name])
#define CMD_ARG_INT(name) CMD_ARG(name,long)
#define CMD_ARG_STR(name) CMD_ARG(name,char*)
#define CMD_ARG_NULL(name) CMD_ARG(name,long)

#define CMD_INSTALL_INFO(name,uinfo) { char * lastcmd = #name; cmds->add_command(lastcmd, &command_##name, uinfo)
#define CMD_INSTALL(name) CMD_INSTALL_INFO(name,NULL)
#define CMD_HELP(text) cmds->add_help(lastcmd, text)
#define CMD_OPTION(name,type) cmds->add_##type##_option(lastcmd, #name)
#define CMD_OPTION_INT(name) CMD_OPTION(name,int)
#define CMD_OPTION_STR(name) CMD_OPTION(name,str)
#define CMD_OPTION_NULL(name) CMD_OPTION(name,null)
#define CMD_END() }


#endif
