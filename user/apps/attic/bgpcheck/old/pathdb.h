typedef struct pathdb_t {
	bol_error_report *report;
	char  empty;
	time_t *modified;
} pathdb;

typedef struct ndb_backing_t {
	FILE *file;
	char *filename;
	struct ndb_backing_t *next;
}

typedef struct ndb_t {
	unsigned int path_size, path_fill, backing_fill;
	pathdb *paths;
	pathdb *build_paths;
	char *build_backing;
	pathdb *read_paths;
	char *read_backing;
	char greylist[65536];
	char *backing_prefix;
	unsigned int backing_id;
	ndb_backing *backing, *backing_last, *backing_current;
} ndb;

ndb *ndb_init(char *backing_prefix, int memuse);
void ndb_report_error(bol_error_report *report);
void ndb_withdraw_error(bol_error_report);
int ndb_verify_path(short *path, int len);