
struct opencred *cred_open(Cred *cred) {
	struct opencred *oc;
       
	oc = nxcompat_calloc(1, sizeof(struct opencred));
	oc->cred = cred;
	if (cred->open(oc)) {
		nxcompat_printf("[guard] error opening credential\n");
		nxcompat_free(oc);
		return NULL;
	}
	
	return oc;
}

void cred_close(struct opencred *oc) {
	if (oc->f) 
		form_free(oc->f);
	nxcompat_free(oc);
}

void cred_free(Cred *cred) {
	// todo: free the data too
	nxcompat_free(cred);
}


// Bogus creds (for testing)

int cred_bogus_open(struct opencred *oc) {
	oc->f = form_from_der((Formula *)oc->cred->data);
	return !(oc->f);
}

int cred_bogus_encode(Cred *cred, unsigned char *buf, int len) {
  int derlen = der_msglen(cred->data);
  if (len >= derlen)
    memcpy(buf + len - derlen, cred->data, derlen);
  return derlen;
}

int cred_bogus_decode(Cred *cred, unsigned char **buf, unsigned char *end) {
  int derlen = der_msglen(*buf);
  if (*buf + derlen > end)
    return -1;
  cred->data = nxcompat_alloc(derlen);
  memcpy(cred->data, *buf, derlen);
  *buf += derlen;
  return 0;
}

Cred *new_cred_bogus(Formula *f) {
  Cred *cred = nxcompat_alloc(sizeof(struct cred));
  cred->tag = CRED_BOGUS;
  cred->data = (char *) f->body;
  cred->open = cred_bogus_open;
  return cred;
}


// SignedFormula creds

int cred_signed_open(struct opencred *oc) {
	if (signedform_verify((SignedFormula *)oc->cred->data) != 0)
	  return -1;
	Formula *f = signedform_get_formula((SignedFormula *)oc->cred->data);
	if (!f)
	  return -1;
	oc->f = form_from_der(f);
	return !(oc->f);
}

int cred_signed_encode(Cred *cred, unsigned char *buf, int len) {
  int derlen = der_msglen(cred->data);
  if (len >= derlen)
    memcpy(buf + len - derlen, cred->data, derlen);
  return derlen;
}

int cred_signed_decode(Cred *cred, unsigned char **buf, unsigned char *end) {
  int derlen = der_msglen(*buf);
  if (*buf + derlen > end)
    return -1;
  cred->data = nxcompat_alloc(derlen);
  memcpy(cred->data, *buf, derlen);
  *buf += derlen;
  return 0;
}

Cred *new_cred_signed(SignedFormula *f) {
  Cred *cred = nxcompat_alloc(sizeof(struct cred));
  cred->tag = CRED_SIGNED;
  cred->data = (char *) f->body;
  cred->open = cred_signed_open;
  return cred;
}

int cred_label_open(struct opencred *oc) {
    struct FSID *labelid = (FSID *)oc->cred->data;
    if (!labelid)
      return -1;
#ifdef __NEXUSKERNEL__
#ifdef DO_LABELSTORE
    Form *f = labelstore_read(*labelid);
#else
    Form *f = NULL;
#endif
    oc->f = f;
    if (!f) return -1;
    return 0;
#else
    int len = LabelStore_Label_Read(*labelid, NULL, 0, NULL);
    if (len <= 0)
      return -1;
    unsigned char *buf = nxcompat_alloc(len);
    int len2 = LabelStore_Label_Read(*labelid, buf, len, NULL);
    if (len != len2) {
      nxcompat_free(buf);
      return -1;
    }
    Form *f = form_from_der((Formula *)buf);
    nxcompat_free(buf);
    oc->f = f;
    if (!f) return -1;
    return 0;
#endif
}

int cred_label_encode(Cred *cred, unsigned char *buf, int len) {
  int enclen = sizeof(FSID);
  if (len >= enclen)
    memcpy(buf + len - enclen, cred->data, enclen);
  return enclen;
}

int cred_label_decode(Cred *cred, unsigned char **buf, unsigned char *end) {
  int enclen = sizeof(FSID);
  if (*buf + enclen > end)
    return -1;
  cred->data = nxcompat_alloc(enclen);
  memcpy(cred->data, *buf, enclen);
  *buf += enclen;
  return 0;
}

Cred *new_cred_label(FSID labelid) {
  Cred *cred = nxcompat_alloc(sizeof(struct cred));
  cred->tag = CRED_LABEL;
  FSID *labelidp = nxcompat_alloc(sizeof(FSID));
  *labelidp = labelid;
  cred->data = (char *)labelidp;
  cred->open = cred_label_open;
  return cred;
}

// custom callback creds, usually installed by server using guard_addauth()

static int cred_encode(Cred *cred, unsigned char *buf, int len) {
  int bodylen;
  switch(cred->tag) {
    case CRED_BOGUS:
      bodylen = cred_bogus_encode(cred, buf, len);
      break;
    case CRED_SIGNED:
      bodylen = cred_signed_encode(cred, buf, len);
      break;
    case CRED_LABEL:
      bodylen = cred_label_encode(cred, buf, len);
      break;
    default:
      return -1;
  }
  if (bodylen < 0) return -1;
  bodylen += der_integer_encode(buf, len-bodylen, cred->tag);
  return bodylen + der_tag_encode(buf, len-bodylen, bodylen, DER_ASN1_SEQUENCE);
}

static int creds_encode(Cred **cred, int ncreds, unsigned char *buf, int len) {
  int bodylen = 0, sublen = 0;
  int i;
  for (i = ncreds-1; i >= 0; i--) {
    bodylen += sublen = cred_encode(cred[i], buf, len - bodylen);
    if (sublen < 0) return -1;
  }
  return bodylen + der_tag_encode(buf, len-bodylen, bodylen, DER_ASN1_SEQUENCE);
}


int creds_serialize(Cred **cred, int ncreds, unsigned char *buf, int *len) {
  int needed = creds_encode(cred, ncreds, buf, *len);
  if (needed < 0) return -1;
  if (needed < *len && needed > 0)
    memmove(buf, buf + *len - needed, needed);
  *len = needed;
  return 0;
}

int integer_decode(unsigned char **der, char *end, int *val) {
	unsigned char *endbody;
	int asntag = der_unwrap(der, end, &endbody);
	if (asntag != DER_ASN1_INTEGER) return 0;
	return der_integer_demangle(der, endbody, val);
}

Cred *cred_decode(unsigned char **derstart, unsigned char *derend) {
  unsigned char *endbody;
  int asntag = der_unwrap(derstart, derend, &endbody);
  if (asntag <= 0) return NULL;
  if (asntag != DER_ASN1_SEQUENCE) return NULL;

  Cred *cred = nxcompat_alloc(sizeof(struct cred));

  if (integer_decode(derstart, derend, &cred->tag)) return NULL;
  switch(cred->tag) {
    case CRED_BOGUS:
      cred->open = cred_bogus_open;
      if (cred_bogus_decode(cred, derstart, derend)) {
	// todo: clean up
	return NULL;
      }
      break;
    case CRED_SIGNED:
      cred->open = cred_signed_open;
      if (cred_signed_decode(cred, derstart, derend)) {
	// todo: clean up
	return NULL;
      }
      break;
    case CRED_LABEL:
      cred->open = cred_label_open;
      if (cred_label_decode(cred, derstart, derend)) {
	// todo: clean up
	return NULL;
      }
      break;
    default:
      // todo: clean up
      return NULL;
  }
  *derstart = endbody;
  return cred;
}

Cred **creds_decode(unsigned char **derstart, unsigned char *derend, 
		    int *numcreds) {

  PointerVector vec;
  PointerVector_init(&vec, 16, POINTERVECTOR_ORDER_PRESERVING);

  // should be a sequence of credentials
  unsigned char *endbody; 
  int asntag = der_unwrap(derstart, derend, &endbody); 
  if (asntag <= 0) return NULL;
  if (asntag != DER_ASN1_SEQUENCE) return NULL;

  while (*derstart < endbody) {
    Cred *cred = cred_decode(derstart, endbody);
    if (!cred) {
      // todo: clean up
      return NULL;
    }
    PointerVector_append(&vec, cred);
  }
  int i, n = PointerVector_len(&vec);
  Cred **ret = nxcompat_alloc(n * sizeof(Cred *));
  for (i = 0; i < n; i++) {
    ret[i] = PointerVector_nth(&vec, i);
  }

  *derstart = endbody;
  *numcreds = n;
  return ret;
}

Cred **creds_deserialize(unsigned char *buf, int len, int *numcreds) {
  unsigned char *derstart = buf;
  if (len < 6) return NULL;
  int derlen = der_msglen(buf);
  if (len < derlen) return NULL;
  unsigned char *derend = derstart + derlen;

  Cred **creds = creds_decode(&derstart, derend, numcreds);
  if (derstart != derend)
    return NULL; // todo: clean up
  return creds;
}

#ifdef __NEXUSKERNEL__
// deep copy of userspace _Grounds object
_Grounds *peek_grounds(Map *map, _Grounds *upg, int maxsize, int *err)
{
#define FAIL(x) do { x; printk_red("(peek grounds failed on line %d)\n", __LINE__); goto peek_grounds_fail; } while (0)

  if (!upg) {
    *err = 0;
    return NULL;
  }

  _Grounds *kpg = nxcompat_alloc(sizeof(_Grounds));
  if (!kpg) {
    *err = -SC_NOMEM;
    return NULL;
  }
  //if (!map) map = nexusthread_current_map();

  Formula **args = NULL;
  Cred **leaves = NULL;
  int nargs = 0; // pulled so far
  int nleaves = 0; // pulled so far
  char *hints = NULL;
 
  // pull counts and embeded pointers
  if (maxsize >= 0 && (maxsize -= sizeof(_Grounds)) < 0)
    FAIL(*err = -SC_NOMEM);
  if(peek_user(map, (unsigned int) upg, kpg, sizeof(_Grounds)) < 0)
    FAIL(*err = -SC_ACCESSERROR);

  // sanity check on counts and pointers
  if (kpg->argc < 0 || kpg->leaves < 0 || !kpg->hints)
    FAIL(*err = -SC_INVALID);

  if (maxsize >= 0 &&
      (maxsize -= (kpg->argc*sizeof(Formula *)
		   + kpg->numleaves*sizeof(Cred *)
		   + kpg->numleaves*sizeof(Cred))) < 0)
    FAIL(*err = -SC_NOMEM);

  // pull hints
  kpg->hints = peek_strdup(map, (unsigned int)kpg->hints, err);
  if (*err) FAIL();
  if (maxsize >= 0 && (maxsize -= strlen(kpg->hints)+1) < 0)
    FAIL(*err = -SC_NOMEM);

  // pull args
  if (!kpg->argc) {
    kpg->args = NULL;
  } else {
    // pull argument array
    args = nxcompat_alloc(kpg->argc * sizeof(Formula *));
    if (!args) FAIL(*err = -SC_NOMEM);
    *err = peek_user(map, (unsigned int)kpg->args, args, kpg->argc * sizeof(Formula *));
    if (*err < 0) FAIL();
    kpg->args = args;

    // pull each argument
    for (nargs = 0; nargs < kpg->argc; nargs++) {
      int stmtlen = (args[nargs] ? der_msglen_u(args[nargs]->body) : 0);
      if (stmtlen <= 0)
	FAIL(*err = -SC_INVALID);
      if (maxsize >= 0 && (maxsize -= stmtlen) < 0)
	FAIL(*err = -SC_NOMEM);
      Formula *stmt = nxcompat_alloc(stmtlen);
      if (!stmt) FAIL(*err = -SC_NOMEM);
      *err = peek_user(map, (unsigned int)args[nargs], stmt, stmtlen);
      if (*err < 0) FAIL(nxcompat_free(stmt););
      args[nargs] = stmt;
    }
  }

  // pull leaves
  if (!kpg->numleaves) {
    kpg->leaves = NULL;
  } else {
    leaves = nxcompat_alloc(kpg->numleaves * sizeof(Cred *));
    if (!leaves) FAIL(*err = -SC_NOMEM);
    *err = peek_user(map, (unsigned int)kpg->leaves, leaves, kpg->numleaves * sizeof(Cred *));
    if (*err < 0) FAIL();
    kpg->leaves = leaves;

    // pull each leaf
    for (nleaves = 0; nleaves < kpg->numleaves; nleaves++) {
      Cred cred; //  = nxcompat_alloc(sizeof(Cred));
      *err = peek_user(map, (unsigned int)leaves[nleaves], &cred, sizeof(Cred));
      if (*err < 0) FAIL();
      int datalen;
      char *data;
      switch(cred.tag) {
	case CRED_BOGUS:
	  datalen = (cred.data ? der_msglen_u(cred.data) : 0);
	  if (!datalen) FAIL();
	  if (maxsize >= 0 && (maxsize -= datalen) < 0) FAIL(*err = -SC_NOMEM);
	  data = nxcompat_alloc(datalen);
	  if (!data) FAIL(*err = -SC_NOMEM);
	  *err = peek_user(map, (unsigned int)cred.data, data, datalen);
	  if (*err < 0) FAIL(nxcompat_free(data));
	  leaves[nleaves] = new_cred_bogus((Formula *)data);
	  if (!leaves[nleaves]) FAIL(nxcompat_free(data));
	  break;
	case CRED_SIGNED:
	  datalen = (cred.data ? der_msglen_u(cred.data) : 0);
	  if (!datalen) FAIL();
	  if (maxsize >= 0 && (maxsize -= datalen) < 0) FAIL(*err = -SC_NOMEM);
	  data = nxcompat_alloc(datalen);
	  if (!data) FAIL(*err = -SC_NOMEM);
	  *err = peek_user(map, (unsigned int)cred.data, data, datalen);
	  if (*err < 0) FAIL(nxcompat_free(data));
	  leaves[nleaves] = new_cred_signed((SignedFormula *)data);
	  if (!leaves[nleaves]) FAIL(nxcompat_free(data));
	  break;
	case CRED_LABEL:
	  datalen = (cred.data ? sizeof(FSID) : 0);
	  if (!datalen) FAIL();
	  if (maxsize >= 0 && (maxsize -= datalen) < 0) FAIL(*err = -SC_NOMEM);
	  data = nxcompat_alloc(datalen);
	  if (!data) FAIL(*err = -SC_NOMEM);
	  *err = peek_user(map, (unsigned int)cred.data, data, datalen);
	  if (*err < 0) FAIL(nxcompat_free(data));
	  leaves[nleaves] = new_cred_label(*(FSID *)data);
	  if (!leaves[nleaves]) FAIL(nxcompat_free(data));
	  break;
	default:
	  FAIL(*err = -SC_INVALID;);
      }
    }
  }

  return kpg;

peek_grounds_fail:
  if (leaves) {
    while (nleaves-- > 0)
      cred_free(leaves[nleaves]);
    nxcompat_free(leaves);
  }
  if (args) {
    while (nargs-- > 0)
      nxcompat_free(args[nargs]);
    nxcompat_free(args);
  }
  if (hints)
    nxcompat_free(hints);
  nxcompat_free(kpg);
  return NULL;
}
#endif // __NEXUSKERNEL__

void grounds_free(_Grounds *pg) {
  if (pg->hints) nxcompat_free(pg->hints);
  if (pg->args) {
    while (pg->argc-- > 0)
      if (pg->args[pg->argc]) nxcompat_free(pg->args[pg->argc]);
    nxcompat_free(pg->args);
  }
  if (pg->leaves) {
    while (pg->numleaves-- > 0)
      if (pg->leaves[pg->numleaves]) cred_free(pg->leaves[pg->numleaves]);
    nxcompat_free(pg->leaves);
  }
  nxcompat_free(pg);
}

// todo: cleanup on error paths

char *grounds_serialize(_Grounds *pg, int *len) {
  // compute size
  int i, slen = 0, flen = 0, clen = 0;

  slen = strlen(pg->hints);

  for (i = 0; i < pg->argc; i++)
    flen += der_msglen(pg->args[i]->body);

  if (creds_serialize(pg->leaves, pg->numleaves, NULL, &clen)) return NULL;
  
  int buflen = 4 + slen + 4 + flen + 4 + clen;

  char *buf = nxcompat_alloc(buflen);
  char *p = buf;

  *(int *)p = slen;
  p += 4;
  memcpy(p, pg->hints, slen);
  p += slen;

  *(int *)p = pg->argc;
  p += 4;
  for (i = 0; i < pg->argc; i++) {
    int l = der_msglen(pg->args[i]->body);
    memcpy(p, pg->args[i]->body, l);
    p += l;
  }

  *(int *)p = pg->numleaves;
  p += 4;
  if (creds_serialize(pg->leaves, pg->numleaves, p, &clen)) return NULL;
  p += clen;
  assert(p == buf + buflen);
  *len = buflen;
  return buf;
}

_Grounds *grounds_deserialize(char *buf, int len) {
  if (len < 4 + 4 + 4)
    return NULL;
  len -= 4 + 4 + 4;

  _Grounds *pg = nxcompat_alloc(sizeof(_Grounds));

  unsigned char *p = buf;

  int slen = *(int *)p;
  p += 4; 
  len -= slen;
  if (slen < 0 || len < 0) return NULL;
  pg->hints = nxcompat_alloc(slen+1);
  memcpy(pg->hints, p, slen);
  pg->hints[slen] = '\0';
  p += slen;

  pg->argc = *(int *)p;
  p += 4;
  if (pg->argc < 0) return NULL;
  else if (pg->argc == 0) pg->args = NULL;
  else {
    pg->args = nxcompat_alloc(pg->argc * sizeof(Formula *));
    int i, flen;
    for (i = 0; i < pg->argc; i++) {
      if (len < 6) return NULL;
      flen = der_msglen(p);
      len -= flen;
      if (len < 0) return NULL;
      pg->args[i] = nxcompat_alloc(flen);
      memcpy(pg->args[i], p, flen);
      p += flen;
    }
  }

  pg->numleaves = *(int *)p;
  p += 4;
  if (pg->numleaves < 0) return NULL;
  else if (pg->numleaves == 0) pg->leaves = NULL;
  else {
    int nc;
    pg->leaves = creds_deserialize(p, len, &nc);
    if (!pg->leaves || nc != pg->numleaves) return NULL;
  }

  return pg;
}
