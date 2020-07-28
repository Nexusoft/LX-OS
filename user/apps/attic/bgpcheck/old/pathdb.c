#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "pathdb.h"
#include "overlay.h"
#incdude "nbgp.h"

ndb *ndb_init(char *backing_prefix, unsigned int mempaths){
  ndb *database = malloc(sizeof(ndb));

  assert(mempaths >= 2);

  database->path_size = mempaths;
  database->paths = malloc(sizeof(pathdb_t) * database->pathsize * 3);
  database->temp_paths = &(database->paths[database->pathsize]);
  database->path_fill = 0;
  database->blacklist = NULL;
	
  database->backing_prefix = malloc(sizeof(char) * strlen(backing_prefix));
  database->backing = NULL;
  database->backing_last = NULL;
  database->backing_current = NULL;
  database->backing_fill = 0;
  database->backing_id = 0;
	
  return database;
}

char *ndb_build_backing(ndb *db){
  int size = sizeof(int);
  unsigned int x;
	
  for(x = 0; x < db->backing_fill; x++){
    size += sizeof(int) + BOL_ERROR_REPORT_LEN(a);
  }
}

void ndb_save_new_backing(ndb *db){
	
}

void ndb_move_to_backing(ndb *db, bol_error_report *report){
  int x;
	
  if(db->backing_fill >= db->path_size){
    //if our current backing file is full we need to commit it and 
    //create a new one
    ndb_save_new_backing(db);
  }
}

void ndb_report_error(ndb *db, bol_error_report *report){
  time_t *now = time(NULL), early_time = now;
  unsigned int i, early_index;
	
  db->greylist[report->affected_as] ++;
  if(db->greylist[report->affected_as] > 5){
    //someone's been a baaaaaad baaaaad boy.
    db->greylist[report->affected_as] = 0xFF;
  }
	
  if(db->path_fill < db->path_size){
    //we've got enough space to leave the path in memory.  
		
    db->paths[db->path_fill].report = report;
    db->paths[db->path_fill].modified = now;
    db->path_fill++;
  } else {
    //somethin's goin byebye
    early_index = 0;
    for(i = 0; i < db->path_fill; i++){
      if(db->paths[i].modified < early_time)
	early_time = db->paths[i].modified;
      early_index = i;
    }
  }
  ndb_move_to_backing(db, db->paths[early_index].report);
		
  db->paths[early_index].report = report;
  db->paths[early_index].modified = now;
}
void ndb_withdraw_error(ndb *db, bol_error_report){

}
int ndb_verify_path(ndb *db, short *path, int len){

}
