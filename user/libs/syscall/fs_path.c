/** NexusOS: pathname resolution. Break up strings into lists of FSIDs */

#include <stdlib.h>
#include <string.h>

#include <nexus/vector.h>
#include <nexus/util.h>

#include <nexus/fs.h>
#include <nexus/fs_path.h>
#include <nexus/FS.interface.h>

static const int dbg_paths = 0;
#define printf_dbg(x...) do { if (dbg_paths) printf(x); } while (0)

static void Path_init(Path *path) {
  PointerVector_init(&path->vec, 8, POINTERVECTOR_ORDER_PRESERVING);
}

void Path_append(Path *path, FSID node, char *fname) {
  PathComponent *pc = malloc(sizeof(PathComponent) + strlen(fname) + 1);
  pc->node = node;
  strcpy(pc->fname, fname);
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

void Path_dup(Path *dest, Path *path) {
  Path_init(dest);
  int i, len = PointerVector_len(&path->vec);
  for(i=0; i < len; i++) {
    PathComponent *pc = (PathComponent*)PointerVector_nth(&path->vec, i);
    Path_append(dest, pc->node, pc->fname);
  }
}

int Path_len(Path *path) {
  return PointerVector_len(&path->vec);
}

void Path_clear(Path *path) {
  while (Path_len(path))
    Path_pop(path);
  PointerVector_dealloc(&path->vec);
}

void Path_new(Path *path, FSID fs_root) {
  Path_init(path);
  Path_append(path, fs_root, "/");
}

int Path_resolve(Path *path, FSID fs_root, Path *cwd, const char *unix_path) {
  int rc;
  
  rc = Path_resolve1(path, fs_root, cwd, unix_path);
  if (!rc && !FSID_isValid(Path_last(path)->node)) {
    rc = FSID_getError(Path_last(path)->node);
    Path_clear(path);
  }
  return rc;
}

/** Turn a path into a string. 
 
    @param max is 0 to traverse the entire string, 
                  >0 to traverse max tokens from the start, or
                  <0 to traverse all but the last max tokens. 
 
    @return a statically allocated string that may be overridden in subsequent
            calls. do NOT free. Is not thread safe.
 */
char * Path_string(Path *path, int max) {	
	PathComponent *comp;
	static char buf[NAME_MAX + 1];
	int blen, nlen, i;

	// calculate max
	if (max < 0)
		max = Path_len(path) - max;

	blen = 0;
	for (i = 0; !max || i < max; i++) {
		// find an element
		comp = Path_nth(path, i);
		if (!comp)
			break;

		// check bounds
		nlen = strlen(comp->fname);
		if (blen + nlen > NAME_MAX)
			return NULL;	// path too long

		// copy data
		memcpy(buf + blen, comp->fname, nlen);
		buf[blen + nlen] = '/';
		blen += nlen + 1;
	}

	buf[blen] = 0;
	return buf;
}

/** Find a filesystem node (inode) by pathname.
 
    @return 0 on success, an error otherwise */
int Path_resolve1(Path *path, FSID fs_root, Path *cwd, const char *_unix_path) {
  char *unix_path = strdup(_unix_path);
  char *fname = unix_path;

  PointerVector rpath; // fname components, reversed
  PointerVector_init(&rpath, 4, POINTERVECTOR_ORDER_PRESERVING);

  if (*fname == '/') {
    Path_new(path, fs_root);
    while (*fname == '/')
      fname++;
  } else {
    Path_dup(path, cwd);
  }
  if (*fname == '\0') {
    printf_dbg("(resolving %s: done)\n", _unix_path); 
    return 0;
  }

  char *end = fname + strlen(fname) - 1;
  while (*end == '/') *end-- = '\0';
  if (*fname == '\0') {
    printf_dbg("(resolving %s: done)\n", _unix_path); 
    return 0;
  }

  // fname starts and ends with a non-slash

  // extract the components (in reverse)
  int skips = 0;
  char *c;
  for (c = end ; c >= fname; c--) {
    //printf("%c ", *c);
    if (*c != '/') continue;
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
	//printf("(%s) ", c+1);
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
    } else {
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
    printf_dbg("(resolving %s: moved up %d levels to port=%d,node=%lld,name=%s)\n",
	       _unix_path, num_up, Path_last(path)->node.port, 
	       (long long) Path_last(path)->node.nodeid, Path_last(path)->fname);
    if (skips > 0) {
      // anything above root just looks like root in linux
      // (yes, you can really open '/foo' using '/../../../foo')
      // so we adopt the same
      skips = 0;
    }
  }

  FSID parent = Path_last(path)->node;

  int i, n = PointerVector_len(&rpath);
  printf_dbg("(resolving %s: %d components left to resolve)\n", _unix_path, n);
  for (i = n-1; i >= 0; i--) {
    char *name = PointerVector_nth(&rpath, i);
    FSID child = nexusfs_lookup(parent, name);
    printf_dbg("(resolving %s: looking up %s at port=%d,node=%lld,name=%s)\n", 
	       _unix_path, name, Path_last(path)->node.port, 
	       (long long) Path_last(path)->node.nodeid, 
	       Path_last(path)->fname);
    if (FSID_getError(child) && i != 0) {
      // any error except for last element: unwind
      PointerVector_dealloc(&rpath);
      free(unix_path);
      Path_clear(path);
      printf_dbg("(resolving %s: got error %d)\n", _unix_path, 
		 FSID_getError(child));
      return FSID_getError(child);
    }
    Path_append(path, child, name);
    printf_dbg("(resolving %s: got port=%d,node=%lld,name=%s)\n", _unix_path,
	       Path_last(path)->node.port, 
	       (long long) Path_last(path)->node.nodeid, 
	       Path_last(path)->fname);
    parent = child;
  }
  PointerVector_dealloc(&rpath);
  free(unix_path);
  printf_dbg("(resolving %s: done)\n", _unix_path);
  return 0;
}

