#include <stdio.h>
#include <stdlib.h>

#include <nq/optionlist.hh>
#include <nq/netquery.h>
#include <nq/net.h>

#define INITIAL_BUFFER_SIZE 100

typedef struct NQ_Transaction_Stack {
  struct NQ_Transaction_Stack *next, *prev;
  NQ_Transaction id;
} NQ_Transaction_Stack;

Queue transaction_stack = QUEUE_EMPTY;

CMD_DEFUN(transaction){
  CMD_ARG_NULL(begin);
  CMD_ARG_NULL(commit);
  CMD_ARG_NULL(abort);
  
  NQ_Transaction_Stack *entry;
  
  if(begin){
    entry = new NQ_Transaction_Stack;
    bzero(entry, sizeof(NQ_Transaction_Stack));
    entry->id = NQ_Transaction_begin();
    queue_prepend(&transaction_stack, entry);
    printf("Starting transaction\n");
    return NULL;
  } else if(commit != abort) { //effectively commit XOR abort.  We want exactly one to be true at this point
    void *_entry;
    if(queue_dequeue(&transaction_stack, &_entry)){
      return "ERROR: transaction stack is empty";
    }
    entry = (NQ_Transaction_Stack *)_entry;
    if(commit) {
      printf("Committing transaction\n");
      NQ_Transaction_commit(entry->id);
    } else if(abort) {
      printf("Aborting transaction\n");
      NQ_Transaction_abort(entry->id);
    }
    free(entry);
  } else {
    return "ERROR: transaction must begin or end";
  }
  return NULL;
}

NQ_Transaction current_transaction(void){
  NQ_Transaction_Stack *curr = (NQ_Transaction_Stack *)queue_gethead(&transaction_stack);
  if(curr != NULL)
    return curr->id;
  else
    return NQ_uuid_error;
}

typedef struct NQ_Tuple_Stack {
  struct NQ_Tuple_Stack *next, *prev;
  NQ_Tuple tuple;
  int id;
} NQ_Tuple_Stack;

Queue tuple_store = QUEUE_EMPTY;

int tuple_find(NQ_Tuple_Stack *element, int *id){
  return *id == element->id;
}

int lastid = 0;
NQ_Tuple_Stack *lastelement = NULL;

CMD_DEFUN(tuple){
  CMD_ARG_INT(id);
  NQ_Tuple_Stack *element;
  
  if(id == 0){
    id = lastid;
    lastid++;
  }
  
  if(!(element = (NQ_Tuple_Stack *)queue_find(&tuple_store, (PFany)tuple_find, &id))){
    element = new NQ_Tuple_Stack;
    bzero(element, sizeof(NQ_Tuple_Stack));
    element->id = id;
    element->tuple = NQ_Tuple_create(current_transaction(), NQ_default_owner.home, &NQ_default_owner);
    queue_append(&tuple_store, element);
    printf("Tuple (%ld) Created\n", id);
  }
  lastelement = element;
  return NULL;
}

NQ_Attribute_Name *make_attribute_name(char *name){
  char *temp, *type=NULL;
  NQ_Attribute_Name *attribute = NULL;

  temp = strstr(name, "_");
  if(temp == NULL){ return NULL; }
  
  attribute = (NQ_Attribute_Name*)malloc(sizeof(NQ_Attribute_Name)+20 + strlen(temp) +1);
  attribute->owner = &NQ_default_owner;
  strcpy(attribute->name, temp);
  type = (char *)alloca(temp-name+1);
  memcpy(type, name, (temp-name));
  type[temp-name] = '\0';
  
  if(strcmp(type, "raw") == 0){
    attribute->type = NQ_ATTRIBUTE_RAW;
  } else if(strcmp(type, "set") == 0){
    attribute->type = NQ_ATTRIBUTE_SET;
  } else if(strcmp(type, "trie") == 0){
    attribute->type = NQ_ATTRIBUTE_TRIE;
  } else {
    free(attribute);
    attribute = NULL;
  }
  
  return attribute;
}

CMD_DEFUN(attribute){
  CMD_ARG_STR(name);
  CMD_ARG_STR(op);
  CMD_ARG_STR(value);
  NQ_Attribute_Operation op_i;
  int need_v = 0;
  char *err = NULL;
  int ret, iolen;
  char *io = value;
  NQ_Attribute_Name *attribute = NULL;
  
  if(name == NULL) return "ERROR: Attributes must have a name";
  if(lastelement == NULL) return "ERROR: You must specify a tuple before defining attributes";
  
  attribute = make_attribute_name(name);
  if(!attribute){
    err = "ERROR: Attribute names must be preceeded by 'raw_', 'set_', or 'trie_'";
    goto attr_return;
  }
  
  if((op == NULL)||(strcmp(op, "read") == 0)){
    op_i = NQ_OPERATION_READ;
  } else if(strcmp(op, "write") == 0){
    op_i = NQ_OPERATION_WRITE;
  } else if(strcmp(op, "add") == 0){
    need_v = 1;
    op_i = NQ_OPERATION_ADD;
  } else if(strcmp(op, "remove") == 0){
    need_v = 1;
    op_i = NQ_OPERATION_REMOVE;
  } else if(strcmp(op, "contains") == 0){
    need_v = 1;
    op_i = NQ_OPERATION_CONTAINS;
  } else {
    err = "ERROR: Operation types are limited to 'read', 'write', 'add', 'remove', and 'contains'";
    goto attr_return;
  }
  
  if(need_v){
    if(value == NULL){
      err = "ERROR: This operation type requires a value";
    }
  }
  if(value == NULL){
    iolen = 0;
  } else {
    iolen = strlen(io)+1;
  }
  ret = NQ_Attribute_operate(current_transaction(), &NQ_default_owner, attribute, lastelement->tuple, op_i, &io, &iolen, NULL);
  
  printf("\t%d = %s(%d;%s) on %s: %s\n", ret, op, op_i, value, name, io);
  
  if((io != NULL)&&(ret >= 0)){
    free(io);
  }
  
attr_return:
  if(attribute != NULL){
    free(attribute);
  }
  return err;
}

int trigger_callback(NQ_Transaction transaction, NQ_Trigger_Description *desc, NQ_Trigger_Upcall_Type upcall_type, int verdict, void *userdata){
  printf(">>> %s <<<\n", (char *)userdata);
  return 0;
}

CMD_DEFUN(trigger){
  CMD_ARG_STR(name);
  CMD_ARG_STR(type);
  CMD_ARG_STR(msg);
  NQ_Attribute_Name *attribute = NULL;
  NQ_Trigger_Description *desc = NULL;
  char *err = NULL;
  
  desc = (NQ_Trigger_Description *)malloc(sizeof(NQ_Trigger_Description));
  bzero(desc, sizeof(NQ_Trigger_Description));
  desc->tuple = NQ_uuid_error;
  
  desc->name = attribute = make_attribute_name(name);
  if(!attribute){
    err = "ERROR: Attribute names must be preceeded by 'raw_', 'set_', or 'trie_'";
    goto trigger_return;
  }
  
  if((!type)||(strcmp(type, "change"))){
    desc->type = NQ_TRIGGER_VALUECHANGED;
  } else {
    err = "ERROR: Unknown trigger type";
    goto trigger_return;
  }

  desc->upcall_type = NQ_TRIGGER_UPCALL_SYNC_VETO;
  
  if(msg == NULL){
    msg = strdup("Trigger Fired!");
  } else {
    msg = strdup(msg);
  }
  
  NQ_Trigger_create(current_transaction(), &NQ_default_owner, desc, &trigger_callback, msg);
  
trigger_return:
  return err;
}


CMD_DEFUN(dump){
  NQ_Tuple_print_all(current_transaction());
  return NULL;
}

static Command_List *nq_scripting_cmds = NULL;

void NQ_Scripting_init(){
  Command_List *cmds = new Command_List();
  CMD_INSTALL(transaction);
    CMD_OPTION_NULL(begin);
    CMD_OPTION_NULL(commit);
    CMD_OPTION_NULL(abort);
  CMD_END();

  CMD_INSTALL(tuple);
    CMD_OPTION_INT(id);
  CMD_END();

  CMD_INSTALL(attribute);
    CMD_OPTION_STR(name);
    CMD_OPTION_STR(op);
    CMD_OPTION_STR(value);
  CMD_END();
  
  CMD_INSTALL(trigger);
    CMD_OPTION_STR(name);
    CMD_OPTION_STR(type);
    CMD_OPTION_STR(msg);
  CMD_END();
  
  CMD_INSTALL(dump);
  CMD_END();
  nq_scripting_cmds = cmds;
}


int NQ_Scripting_process(FILE *insource){
  char *cmd = (char *)malloc(INITIAL_BUFFER_SIZE);
  char *err;
  int buff_sz = INITIAL_BUFFER_SIZE;
  int len;
  
  assert(nq_scripting_cmds);

  while(!feof(insource)){
    len = 0;
    while(!feof(insource) && (fread(&(cmd[len]), 1, 1, insource) > 0)) {
      if((cmd[len] == '\n') || (cmd[len] == '\r')){
        if(len > 0) break;
        else continue;
      }
      len++;
      if(len + 2 > buff_sz){
        buff_sz *= 2;
        cmd = (char *)realloc(cmd, buff_sz);
      }
    }
    cmd[len] = '\0';
    printf("==> %s\n", cmd);
    if((err = nq_scripting_cmds->process_command(cmd)) != NULL){
      printf("Error: %s\n", err);
      exit(0);
    }
  } 
  free(cmd);
  if(ferror(insource)){
    printf("Error reading file\n");
    exit(0);
  }
  return 0;
}
