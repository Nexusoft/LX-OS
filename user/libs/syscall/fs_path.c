/** NexusOS: pathname resolution. Break up strings into lists of FSIDs */

#include <stdlib.h>
#include <string.h>

#include <nexus/vector.h>
#include <nexus/util.h>

#include <nexus/fs.h>
#include <nexus/fs_path.h>
#include <nexus/FS.interface.h>

static void 
Path_init(Path *path) 
{
  PointerVector_init(&path->vec, 8, POINTERVECTOR_ORDER_PRESERVING);
}

/** Trim all occurrences of car from the string of slen bytes (incl. end 0) */
static int
component_rtrim(char *string, int car)
{
	int slen;

	slen = strlen(string);
	while (slen && string[slen - 1] == car)
		slen--;

	return slen;
}

static void 
Path_append(Path *path, FSID node, char *fname) 
{
  PathComponent *pc;
  int flen;

  // drop all terminating slashes (e.g. 'tmp///' -> 'tmp')
  flen = component_rtrim(fname, '/');

  // sanity check input: unix allows all but null and slash
  if (!flen || strchr(fname, '/'))
	  return;

  // create element
  pc = malloc(sizeof(PathComponent) + flen + 1);
  pc->node = node;

  // copy name
  memcpy(pc->fname, fname, flen);
  pc->fname[flen] = 0;
 
  // append to vector
  PointerVector_append(&path->vec, pc);
}

PathComponent *Path_last(Path *path) {
  return (PathComponent *)PointerVector_nth(&path->vec, PointerVector_len(&path->vec) - 1);
}

PathComponent *Path_nth(Path *path, int i) {
  return (PathComponent *)PointerVector_nth(&path->vec, i);
}

PathComponent *Path_lastparent(Path *path) {
  int len;

  len = PointerVector_len(&path->vec);
  if (len < 2)
	  return NULL;

  return (PathComponent *)PointerVector_nth(&path->vec, len - 2);
}

PathComponent *Path_root(Path *path) {
  return (PathComponent *)PointerVector_nth(&path->vec, 0);
}

int Path_pop(Path *path) {
  if (PointerVector_len(&path->vec)  <= 0)
    return -1;
  PathComponent *pc = (PathComponent*)PointerVector_deleteAt(&path->vec, PointerVector_len(&path->vec)-1);
  free(pc);
  return 0;
}

void 
Path_dup(Path *dest, Path *path) 
{
  int i, len;
 
  Path_init(dest);
  len = PointerVector_len(&path->vec);
  
  for (i = 0; i < len; i++) {
    PathComponent *pc = (PathComponent*)PointerVector_nth(&path->vec, i);
    Path_append(dest, pc->node, pc->fname);
  }
}

int 
Path_len(Path *path) 
{
  return PointerVector_len(&path->vec);
}

void 
Path_clear(Path *path) 
{
  assert(path);

  while (Path_len(path))
    Path_pop(path);
  
  PointerVector_dealloc(&path->vec);
}

void 
Path_new(Path *path) 
{
  Path_init(path);
  Path_append(path, nexusfs_getroot(), "a");
}

/** Like Path_resolve1, but do not allow failure in the last segment */
int 
Path_resolve(Path *path, Path *cwd, const char *unix_path) 
{
	int rc;

	rc = Path_resolve1(path, cwd, unix_path);
	if (rc)
		return rc;

	if (!FSID_isValid(Path_last(path)->node)) {
		rc = FSID_getError(Path_last(path)->node);
		Path_clear(path);
		return -FS_NOTFOUND;
	}

	return 0;
}

/** Turn an absolute path into a string. 
    NOT multithread safe

    @return a statically allocated string that may be overridden in 
            subsequent calls. do NOT free. Is not thread safe.
*/
char * 
Path_string(Path *path) 
{
	static char buf[PATH_MAX + 1];
	PathComponent *comp;
	int blen, nlen, max, i;

	// init
	blen = 0;
	max = Path_len(path);
	
	// foreach path component
	for (i = 0; i < max; i++) {

		// find element
		comp = Path_nth(path, i);
		if (!comp)
			break;

		// check bounds
		nlen = strlen(comp->fname);
		if (blen + nlen + 1 > PATH_MAX) {
			fprintf(stderr, "path exceeds max. Aborting\n");
			abort(); 
		}

		// copy data
		memcpy(buf + blen, comp->fname, nlen);
		blen += nlen;
		buf[blen++] = '/';
	}

	buf[blen] = 0;
	return buf;
}

/** Find a filesystem node (inode) by pathname.

@return 0 on success, an error otherwise */
int 
Path_resolve1(Path *path, Path *cwd, const char *_unix_path) 
{
	FSID parent, child;
	char *name, *unix_path, *fname, *end;
	int i, n, nlen, ret = 0;

	unix_path = strdup(_unix_path);
	fname = unix_path;

	PointerVector rpath; // fname components, reversed
	PointerVector_init(&rpath, 4, POINTERVECTOR_ORDER_PRESERVING);

	// absolute path
	if (fname[0] == '/') {
		// strip slashes from start 
		Path_new(path);
		while (fname[0] == '/')
			fname++;
	} 
	// relative path
	else {
		Path_dup(path, cwd);
	}

	if (fname[0] == '\0')
		goto cleanup;

	end = fname + strlen(fname) - 1;
	while (end[0] == '/') 
		*end-- = '\0';

	if (*fname == '\0')
	 	goto cleanup;

	// populate rpath: extract the components (in reverse) 
	int skips = 0;
	char *c;
	for (c = end ; c >= fname; c--) {
		if (*c != '/') 
			continue;
		// see what the current chunk is
		if (c[1] == '.' && c[2] == '\0') { 
			// nothing
		} 
		else if (c[1] == '.' && c[2] == '.' && c[3] == '\0') {
			skips++;
		} else {
			if (skips > 0) {
				skips--;
			} else {
				PointerVector_append(&rpath, c+1);
			}
		}
		c[0] = '\0';
		while (c[-1] == '/') *(c--) = '\0';
	}
	if (c[1] == '.' && c[2] == '\0') { 
		// nothing
	} else if (c[1] == '.' && c[2] == '.' && c[3] == '\0') {
		skips++;
	} else {
		if (skips > 0) {
			skips--;
		} 
		else {
			PointerVector_append(&rpath, c+1);
			//printf("(%s) ", c+1);
		}
	}

	if (skips > 0) {
		int num_up = skips;
		while (skips > 0 && Path_len(path) > 1) {
			skips--;
			Path_pop(path);
		}
	    if (skips > 0) {
	      // anything above root just looks like root in linux
	      // (yes, you can really open '/foo' using '/../../../foo')
	      // so we adopt the same
	      skips = 0;
	    }
  	}

  // walk along the existing path by tokens in rpath
  parent = Path_last(path)->node;
  if (!FSID_isDir(parent)) {
    ret = -FS_NOTFOUND;
    Path_clear(path);
    goto cleanup;
  }

  n = PointerVector_len(&rpath);
  for (i = n - 1; i >= 0; i--) {
    name = PointerVector_nth(&rpath, i);
    
    // remove trailing slashes
    nlen = component_rtrim(name, '/');
    if (!nlen)
	    goto cleanup;
    name[nlen] = 0;
    
    child = nexusfs_lookup_resolvelink(parent, name);

    // any error except for last element: unwind
    if (!FSID_isValid(child) && i) {
    	ret = -FS_NOTFOUND;
    	Path_clear(path);
	goto cleanup;
    }

    // special case: last element may be a new file
    Path_append(path, child, name);
    parent = child;
  }

cleanup:
  PointerVector_dealloc(&rpath);
  free(unix_path);
  return ret;
}

