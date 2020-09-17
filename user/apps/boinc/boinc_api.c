#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int boinc_init(void){
	printf("boinc_init\n");
	return 0;
}

int boinc_finish(int status){
	printf("boinc_finish\n");
	return 0;
}

int boinc_resolve_filename(char *logical_name, char *physical_name, int len){
	int i;

	printf("boinc_resolve_filename\n");
	for (i=0; i<len; i++)
		physical_name[i] = logical_name[i];
	return 0;
}

FILE * boinc_fopen(char* path, char* mode){
	FILE * fp = NULL;

	printf("boinc_fopen\n");	
	if (mode[0] == 'a'){
		fp = fopen(path, "a");
		if(fp == NULL){
        		fprintf(stderr,"failed to open out.txt");
        		return NULL;
		}
   	}
	return fp;
}

int boinc_init_diagnostics(int flags){
	FILE * err = NULL;
	printf("boinc_init_diagnostics\n");

	if ((flags & 0x00000020) == 32){
		printf("BOINC_DIAG_REDIRECTSTDERR\n");
		close(2); // close stderr
		err = fopen("stderr.txt", "w");
		dup(fileno(err));
	}
	return 0;
}
