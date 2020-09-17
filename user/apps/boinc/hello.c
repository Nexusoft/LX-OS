/***********************************************************************\
 *  Hello, BOINC World!                                 Version: 6.04
 *   
 *  This is the Hello World program for BOINC.  It is the simplest application
 *  one can write which uses the BOINC API and writes some output to a
 *  file (called "out.txt").   See the sample workunit and result templates
 *  to see how this file is mapped to a real file and how it is uploaded.
 *
 *  Note: if you want to run this program "standalone" then the file "out.txt"
 *  must already exist!
 *  
 *  For more information see the release notes at 
 *      http://www.spy-hill.com/help/boinc/hello.html 
 *
 *  Eric Myers <myers@spy-hill.net> - 16 June 2004 (Unix)/6 July 2004 (Windows)
 *  @(#)  $Revision: 1.22 $ - $Date: 2010/02/25 21:15:52 $ 
\************************************************************************/

#include <stdio.h>
#include <stdlib.h>

/* BOINC API */

#include "boinc_api.h"
  


/* Begin: */ 

int main(int argc, char **argv) {
  int rc;                       // return code from various functions
  char resolved_name[512];      // physical file name for out.txt
  FILE* f;                      // file pointer for out.txt

  /*
   *  Before initializing BOINC itself, intialize diagnostics, so as
   *  to get stderr output to the file stderr.txt, and thence back home.
   */

  boinc_init_diagnostics(BOINC_DIAG_REDIRECTSTDERR|
                         BOINC_DIAG_MEMORYLEAKCHECKENABLED|
                         BOINC_DIAG_DUMPCALLSTACKENABLED| 
                         BOINC_DIAG_TRACETOSTDERR);

  /* Output written to stderr will be returned with the Result (task) */

  fprintf(stderr,"Hello, stderr!\n");


  /* BOINC apps that do not use graphics just call boinc_init() */

  rc = boinc_init();
  if (rc){
    fprintf(stderr, "APP: boinc_init() failed. rc=%d\n", rc);
    fflush(0);
    exit(rc);
  }

  /*
   * Input and output files need to be "resolved" from their logical name
   * for the application to the actual path on the client's disk
   */
  rc = boinc_resolve_filename("out.txt", resolved_name, sizeof(resolved_name));
  if (rc){
    fprintf(stderr, "APP: cannot resolve output file name. RC=%d\n", rc);
    boinc_finish(rc);    /* back to BOINC core */
  }

  /*
   *  Open files with boinc_fopen() not just fopen()
   *  (Output files should usually be opened in "append" mode, in case
   *  this is actually a restart (which will not be the case here)).
   */
  f = boinc_fopen(resolved_name, "a");

  fprintf(f, "Hello, BOINC World!\n");


  /* Now run up a wee bit of credit.   This is the "worker" loop */

  { int j, num, N;
    N = 123456789;
    fprintf(f, "Starting some computation...\n");
    for ( j=0 ; j<N ; j++ ){
      num=rand()+rand();     // just do something to spin the wheels
    }
    fprintf(f, "Computation completed.\n");
  }

  /* All BOINC applications must exit via boinc_finish(rc), not merely exit() */

  fclose(f);               
  fprintf(stderr,"goodbye!\n");
  boinc_finish(0);       /* does not return */

  return 0;
}

