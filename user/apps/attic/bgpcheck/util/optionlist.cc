#include <iostream>
#include "../include/util/optionlist.h"

Command_List::Command_List(){

}
Command_List::~Command_List(){

}

void Command_List::add_command(char *command, Command_Call call, void *userinfo){
  Command_Entry *newcmd = new Command_Entry;
  
  newcmd->command = command;
  newcmd->call = call;
  newcmd->userinfo = userinfo;
  newcmd->help = NULL;
  
  //insert it into the list.
  commands[command] = newcmd;
}
void Command_List::set_help(char *command, char *help){
  commands[command]->help = help;
}
void Command_List::add_int_option(char *command, char *option){
  Option_List *opt = new Option_List;
  opt->option = option;
  opt->flags = OPTION_TYPE_INT;
  opt->def = (void *)0;
  
  commands[command]->options[option] = opt;
}
void Command_List::add_str_option(char *command, char *option){
  Option_List *opt = new Option_List;
  opt->option = option;
  opt->flags = OPTION_TYPE_STR;
  opt->def = NULL;
  commands[command]->options[option] = opt;
}
void Command_List::add_null_option(char *command, char *option){
  Option_List *opt = new Option_List;
  opt->option = option;
  opt->flags = OPTION_TYPE_NULL;
  opt->def = (void *)0;
  commands[command]->options[option] = opt;
}

char *my_strsep(char **str, char *sep){
  char *ret;
  int x,sepcnt = strlen(sep)+1;
  
  ret = *str;
  for(; ;(*str)++){
    for(x = 0; x < sepcnt; x++){
      if(*(*str) == sep[x]){
        break;
      }
    }
  }
  if(*(*str) != '\0'){
    for(; ;(*str)++){
      for(x = 0; x < sepcnt; x++){
        if(*(*str) != sep[x]){
          break;
        }
      }
    }
  }
  return ret;
}

char *Command_List::process_command(char *command){
  char *option, *value, *ctx, *cmd_str, *sep = " \t\n\r";
  std::map<char *,void *,ltstr> options;
  std::map<char *,Command_Entry *,ltstr>::iterator cmd_entry;
  std::map<char *,Option_List *,ltstr>::iterator opt_entry;
  Command_Entry *cmd;
  int opt_flags;
  
  if(command[0] == '#') return NULL; //comment line
  
  ctx = command;
  cmd_str = strsep(&ctx, sep);
  if(cmd_str == NULL) return "No commands";
  
  
  cmd_entry = commands.find(cmd_str);
  if(cmd_entry == commands.end()) return "Invalid command";
  cmd = cmd_entry->second;
  
  for(opt_entry = cmd->options.begin(); opt_entry != cmd->options.end(); ++opt_entry){
    //printf("setting default option value: '%s'\n", opt_entry->second->option);
    options[opt_entry->second->option] = opt_entry->second->def;
  }
  
  for(option = strsep(&ctx, sep); option != NULL; option = strsep(&ctx, sep)){
    //printf("processing option: '%s'(remaining:%s)\n", option, ctx);
    opt_entry = cmd->options.find(option);
    if(opt_entry == cmd->options.end()){
      return "Invalid option";
    }
    opt_flags = opt_entry->second->flags;
    if((opt_flags & OPTION_TYPEMASK) != OPTION_TYPE_NULL){
      value = strsep(&ctx, sep);
      if(value == NULL){
        return "Option needs a paramter";
      }
    }
    switch(opt_flags & OPTION_TYPEMASK){
      case OPTION_TYPE_INT:
        options[opt_entry->second->option] = (void *)atoi(value);
        break;
      case OPTION_TYPE_STR:
        //this value should only be used while we call the callback.  This means that it's
        //safe not to malloc.
        options[opt_entry->second->option] = (void *)value; 
        break;
      case OPTION_TYPE_NULL:
        //no option value here.  Just indicate that it's here
        options[opt_entry->second->option] = (void *)1;
        break;
    }
  }
  
  return cmd->call(&options, cmd->userinfo);
}
