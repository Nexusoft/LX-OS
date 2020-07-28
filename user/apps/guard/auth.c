#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef NEXUS
#include <nexus/namespace.h>
#include <nexus/file.h>
#endif

//#include "auth.h"
#include <nexus/guard.h>
#include <nexus/formula.h>
//#include "cred.h"
//#include "opencred.h"

/*
term_auth *new_auth_ipc_bychan(char *svcname) {

}

term_auth *new_auth_ipc_bychan(int chan) {

}
*/

#ifdef DO_DEPRECATED
term_auth *new_auth_callback(credential_query *q) {
	term_auth *auth = malloc(sizeof(struct term_auth));
	memset(auth, 0, sizeof(struct term_auth));

	auth->name = strdup("<callback>");
	auth->query = q;
	return auth;
}
#endif

// (local) clock authority: handles f that look like [[ clk < X ]] or [[ clk > X ]]

static char *skipws(char *s) {
	while (s && isspace(*s)) s++;
	return s;
}

static char *rtrim(char *s) {
	while (s && isspace(*s)) s--;
	return s;
}

int parse_formula(form *f) {
#if DO_BROKEN
	if (f->op.tag != F_PRED)
		return 0;

	char *p = f->pred.word;
	p = skipws(p);
	if (strncmp(p, "clk", 3))
		return 0;
	p = skipws(p+3);
	int tgt = 0;
	if (*p == '>') tgt = 1;
	else if (*p == '<') tgt = -1;
	else return 0;
	p = skipws(p+1);
	char *end;
	int hr = strtol(p, &end, 10);
	if (end == p)
		return 0;
	p = skipws(end);
	if (!strncmp(p, "pm", 2))
		hr += 12;
	else if (!strncmp(p, "am", 2))
		;
	else
		return 0;
	p = skipws(p+2);
	if (*p)
		return 0;
	return tgt*hr;
#else
	return 0;
#endif
}

int clock_check(struct opencred *oc) {
	int hr = parse_formula((form *)oc->f);
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int sec = tv.tv_sec;
	sec -= 1174017600; // offset since Friday morning
	sec = sec % (24*60*60);
	if (hr < 0) {
		// make sure we are before |hr| hours
		hr = -hr;
		if (sec < hr*60*60) return 0;
		else return -1;
	} else {
		// make sure we are after hr hours
		if (sec > hr*60*60) return 0;
		else return -1;
	}
}

int cred_clock_open(struct opencred *oc) {
	form *f = (void *)oc->cred->data;
	oc->f = form_dup(f);
	oc->start = clock_check;
	oc->stop = clock_check;
	return 0;
}

Cred* query_clock(term_auth *auth, form *f) {
	int hr = parse_formula(f);
	if (!hr)
		return NULL;
	Cred *cred = malloc(sizeof(struct cred));
	cred->tag = -1; // custom
	cred->data = (char *)f;
	cred->open = cred_clock_open;
	return cred;
}

term_auth *new_auth_clock() {
	term_auth *auth = malloc(sizeof(struct term_auth));
	memset(auth, 0, sizeof(struct term_auth));

	auth->name = strdup("<clock>");
	auth->query = query_clock;
	return auth;
}


// (soon-to-be-remote) keyed authority: handles f that look like key:K says ...

struct cred_ipc_data {
	term_auth *auth;
	form *f;
};


int cred_ipc_check_and_hold(struct opencred *oc) {
	struct cred_ipc_data *data = (void *)oc->cred->data;
	printf("calling check_and_hold on channel %d, formula:\n", data->auth->ipc_chan);
#ifdef DO_BROKEN
	form_print(data->f);
#endif
	printf("\n");
	return 0;
}
int cred_ipc_release_and_verify(struct opencred *oc) {
	struct cred_ipc_data *data = (void *)oc->cred->data;
	printf("calling release_and_verify on channel %d, formula:\n", data->auth->ipc_chan);
#ifdef DO_BROKEN
	form_print(data->f);
#endif
	printf("\n");
	return 0;
}

int cred_ipc_open(struct opencred *oc) {
	struct cred_ipc_data *data = (void *)oc->cred->data;

	if (data->auth->ipc_chan < 0) {
		printf("opening connection to '%s'\n", data->auth->svcname);
		data->auth->ipc_chan = 1234;
	}
	if (data->auth->ipc_chan < 0)
		return -1;
	if (!data->auth->verified) {
		printf("calling get_auth(%s) on channel %d\n", data->auth->name, data->auth->ipc_chan);
		data->auth->verified = 1;
	}

	oc->f = form_dup(data->f);
	oc->start = cred_ipc_check_and_hold;
	oc->stop = cred_ipc_release_and_verify;
	return 0;
}

Cred* query_ipc(term_auth *auth, form *f) {
#ifdef DO_BROKEN
	if (f->op.tag != F_SAYS)
		return NULL;
	if (f->op.left->op.tag != F_PRIN)
		return NULL;
	if (strcmp(auth->name, f->op.left->prin.word))
		return NULL;
	Cred *cred = malloc(sizeof(struct cred));
	cred->tag = -1; // custom
	struct cred_ipc_data *data = malloc(sizeof(struct cred_ipc_data));
	data->auth = auth;
	data->f = form_dup(f);
	cred->data = (char *)data;
	cred->open = cred_ipc_open;
	return cred;
#else
	return NULL;
#endif
}

term_auth *new_auth_ipc_byname(char *svc, char *prin) {
	term_auth *auth = malloc(sizeof(struct term_auth));
	memset(auth, 0, sizeof(struct term_auth));

	auth->name = strdup(prin);
	auth->svcname = strdup(svc);
	auth->ipc_chan = -1;
	auth->query = query_ipc;
	return auth;
}

// proc authority: handles f that look like [[procexpr]]
// where proxexpr is is "procterm op procterm"
// where procterm is "constant" or "pattern" or "filepath"

char *parse_procterm(char *p, char **term) {
	if (*p == '/') {
		// a path
		char *c = strchr(p, ' ');
		if (!c)
			return NULL;
		*term = malloc(c - p + 1);
		memcpy(*term, p, c-p);
		(*term)[c-p] = '\0';
		p = c+1;
	} else if (*p == '"') {
		char *c = strchr(p+1, '"');
		if (!c) return NULL;
		*term = malloc(c - p + 2);
		memcpy(*term, p, c-p+1);
		(*term)[c-p+1] = '\0';
		p = c+1;
	} else
		return NULL;
	return p;
}

int parse_procexpr(form *f, char **retleft, char **retright, char *retop) {
#ifdef DO_BROKEN
	if (f->op.tag != F_PRED)
		return -1;
	char *p = f->pred.word;
	p = parse_procterm(skipws(p), retleft);
	if (!p) {
		return -1;
	}
	printf("left = %s\n", *retleft);
	p = skipws(p);
	if (*p == '>') *retop = *p;
	else if (*p == '<') *retop = *p;
	else if (*p == '=') *retop = *p;
	else {
		free(*retleft);
		return -1;
	}
	p++;
	p = parse_procterm(skipws(p), retright);
	printf("right = %s\n", *retright);
	if (!p) {
		free(*retleft);
		return -1;
	}
	p = skipws(p);
	if (*p) {
		free(*retleft);
		free(*retright);
		return -1;
	}
	return 0;
#else
	return -1;
#endif
}

struct cred_proc_data {
	int lock[2];
#ifdef NEXUS
	NodeID nodeid[2];
	int ver[2];
#endif
};

int proc_evalterm(struct cred_proc_data *ocd, char *term, char **val, int *len, int idx) {
	if (*term == '/') {
		// a file
		// in order to do proper locking, we should find the channel ourselves, then lock it, etc.
		int fd = open(term, O_RDONLY);
		if (fd < 0)
			return -1;
#ifdef NEXUS
#ifdef HAVE_DEPRECATED
		if (fd_toNodeID(fd, &ocd->nodeid[idx]) != 0) {
			printf("can't lookup\n");
			return -1;
		}
		//get version
#else
		// XXX recreate the required functionality
		fprintf(stderr, "Use of deprecated function fd_to_NodeID. Aborting\n");
		return -1;	
#endif
#endif
		int size = lseek(fd, 0, SEEK_END);
		lseek(fd, 0, SEEK_SET);
		*val = malloc(size);
		int got = 0;
		while (got < size) {
			int v = read(fd, (*val)+got, size-got);
			if (v <= 0) {
				free(*val);
				close(fd);
				return -1;
			}
			got += v;
		}
		close(fd);
		*len = size;
		ocd->lock[idx] = 1;
	} else if (*term == '"') {
		// a constant
		*val = strdup(term+1);
		(*val)[strlen(*val)-1] = '\0'; // get rid of the quote
		*len = strlen(*val);
	} else {
		return -1;
	}
	return 0;
}

int proc_check_start(struct opencred *oc) {
	char *left = NULL, *right = NULL, op;
	char *leftval = NULL, *rightval = NULL;
	int leftlen, rightlen;
	int ret = -1;

	int err = parse_procexpr((form *)oc->f, &left, &right, &op);
	if (err)
		return -1;

	err = proc_evalterm((struct cred_proc_data *)oc->priv, left, &leftval, &leftlen, 0);
	if (err) goto fail;
	err = proc_evalterm((struct cred_proc_data *)oc->priv, right, &rightval, &rightlen, 1);
	if (err) goto fail;

	if (op == '=')
		ret = !((leftlen == rightlen) && !memcmp(leftval, rightval, leftlen));
	else 
		ret = -1;

fail:
	if (left) free(left);
	if (right) free(right);
	if (leftval) free(leftval);
	if (rightval) free(rightval);

	return ret;
}

int proc_check_stop(struct opencred *oc) {
	struct cred_proc_data *ocd = oc->priv;
	int i;
	for (i = 0; i < 2; i++) {
		if (!ocd->lock[i]) continue;
		ocd->lock[i] = 0;
#ifdef NEXUS
	//get version and compare against old version
#endif
	}
	return 0;
}

int cred_proc_open(struct opencred *oc) {
	form *f = (void *)oc->cred->data;
	oc->f = form_dup(f);
	oc->start = proc_check_start;
	oc->stop = proc_check_stop;
	struct cred_proc_data *private = malloc(sizeof(struct cred_proc_data));
	memset(private, 0, sizeof(struct cred_proc_data));
	oc->priv = private;
	return 0;
}

Cred* query_proc(term_auth *auth, form *f) {
	char *left, *right, op;
	int err = parse_procexpr(f, &left, &right, &op);
	if (err < 0)
		return NULL;
	free(left); free(right);
	Cred *cred = malloc(sizeof(struct cred));
	cred->tag = -1; // custom
	cred->data = (char *)f;
	cred->open = cred_proc_open;
	return cred;
}

term_auth *new_auth_procfs(void) {
	term_auth *auth = calloc(1, sizeof(struct term_auth));

	auth->name = strdup("<proc>");
	auth->query = query_proc;
	return auth;
}

