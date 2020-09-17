#define BOINC_DIAG_DUMPCALLSTACKENABLED     0x00000001L
#define BOINC_DIAG_HEAPCHECKENABLED         0x00000002L
#define BOINC_DIAG_MEMORYLEAKCHECKENABLED   0x00000004L
#define BOINC_DIAG_ARCHIVESTDERR            0x00000008L
#define BOINC_DIAG_ARCHIVESTDOUT            0x00000010L
#define BOINC_DIAG_REDIRECTSTDERR           0x00000020L
#define BOINC_DIAG_REDIRECTSTDOUT           0x00000040L
#define BOINC_DIAG_REDIRECTSTDERROVERWRITE  0x00000080L
#define BOINC_DIAG_REDIRECTSTDOUTOVERWRITE  0x00000100L
#define BOINC_DIAG_TRACETOSTDERR            0x00000200L
#define BOINC_DIAG_TRACETOSTDOUT            0x00000400L
#define BOINC_DIAG_HEAPCHECKEVERYALLOC      0x00000800L
#define BOINC_DIAG_BOINCAPPLICATION         0x00001000L

int boinc_init(void);
int boinc_finish(int status);
int boinc_resolve_filename(char *logical_name, char *physical_name, int len);
FILE * boinc_fopen(char* path, char* mode);
int boinc_init_diagnostics(int flags);
