syscall LabelStore {
  // kwalsh: error values in this file make no sense: this isn't the namespace,
  // it is a label store.
  
  decls {
    includefiles { "<nexus/defs.h>",
		   "<nexus/policy.h>", 
		   "<nexus/namespace.h>", 
		   "<nexus/fs.h>" }

    // a labelstore reference is just an fsid
    // typedef FSID LabelStore;

    // a label reference is just an fsid as well (the kernel tracks the parent,
    // i.e. the labelstore in which the label is stored; user can too if desired)
    // typedef FSID LabelID;

    includefiles { "<nexus/guard.h>" }

    // Policies for all label-store and label operations.  Note that read and
    // export are separate, so that a policy can reveal labels without
    // allowing copying (preserving repudiability).  Also, insert and import
    // are separate so that a policy can allow A to insert "A says" but not to
    // echo "B says" (preserving accountability). Copy is just a combination of
    // export (from the source) and import (to the destination).
    typedef enum {
#define OP_LS_FIRST OP_LS_SET_POLICY
	  OP_LS_SET_POLICY = 0,       // label_store_set_policy()
	  OP_LS_DESTROY,          // label_store_destroy()
	  OP_LS_INSERT,           // label_say()
	  OP_LS_IMPORT,           // label_internalize and label_copy (dest)
	  OP_LS_DELETE,           // unlink(label)
	  OP_LS_ENUMERATE,        // readdir()
	  OP_LS_READ,             // open(label)
	  OP_LS_EXPORT            // label_externalize and label_copy (source)
#define OP_LS_LAST OP_LS_EXPORT
    } LabelStoreOperation;    // operations that have guards

    typedef enum {
      LABELTYPE_BOOTHASH = 1,
      LABELTYPE_SCHEDULER = 2,
    } KernelLabelType;

    enum { // use enum, b/c we can't use #defines in idl
      LABELSTORE_MAX_STORENAMELEN = 255,
      LABELSTORE_MAX_STMTLEN = 1024*1024, 
      LABELSTORE_MAX_GROUNDS = 1024*1024, 
    };

    void labelstore_enumerate_print(char *filename);
    int labelstore_enumerate_match(char *filename, Formula *tomatch);
    Formula *labelstore_enumerate_get(char *filename, int i);
    int labelstore_enumerate_get_num(char *filename);
    FSID write_label(char *filename, Form *f);
    FSID lookup_label(char *filename);

    struct dumb {
#ifdef __NEXUSKERNEL__
    };

    Form *labelstore_read(FSID labelid);

    struct dumber {
#endif // __NEXUSKERNEL__
    };

  }

  decls __callee__ {
    includefiles { "<nexus/formula.h>" }
    includefiles { "<nexus/synch-inline.h>" }
    includefiles { "<nexus/user_compat.h>" }
    struct silly {
#define LOCAL_DEBUG_LEVEL DEBUG_LEVEL_WARN
    };
    includefiles { "<nexus/debug.h>" }

    static char *label_policy_name(LabelStoreOperation op) {
      switch(op) {
	case OP_LS_SET_POLICY: return "LabelStore_SetPolicy";
	case OP_LS_DESTROY: return "LabelStore_Destroy";
	case OP_LS_INSERT: return "LabelStore_Insert";
	case OP_LS_IMPORT: return "LabelStore_Import";
	case OP_LS_DELETE: return "LabelStore_Delete";
	case OP_LS_ENUMERATE: return "LabelStore_Enumerate";
	case OP_LS_READ: return "LabelStore_Read";
	case OP_LS_EXPORT: return "LabelStore_Export";
	default: return NULL;
      }
    }

    static Sema ls_mutex = SEMA_MUTEX_INIT;

    // We just use the kernelfs data structures to store labels
    int check_policy(GenericFS_Dir *store, _Grounds *upg, LabelStoreOperation op) {
      char *opname = label_policy_name(op);
      if (!opname) return -FS_INVALID;
      GenericFS_Dir *policy = GenericFS_finddir(store, "policy");
      GenericFS_File *pol = GenericFS_findfile(policy, opname);
     
      if (pol == NULL || pol->len <= 0) {
	dprintf(INFO, "null policy: allow all access");
	return 0; // null policy: allow all access
      }
      _Policy *p = (_Policy *)pol->data;

      _Grounds *kpg = NULL;
      if (upg) {
	int err;
	kpg = peek_grounds(nexusthread_current_map(), upg, LABELSTORE_MAX_GROUNDS, &err);
	if (err) {
	  dprintf(WARN, "peek_grounds failed");
	  return err;
	}
      }

      Guard *g = guard_create();
      guard_setdebug(g, GUARD_DEBUG_ALL);
      if (guard_setgoal(g, &p->gf)) {
	if (kpg) grounds_free(kpg);
	return -SC_BADPOLICY;
      }

      Form *body = form_newdata(F_TERM_SVAR, strdup(opname), -1);
      Form *req = form_fmt("%{term} says %{Stmt}", ipd_get_speaker(nexusthread_current_ipd()), body);

      int ret = guard_check(g, req, kpg);

      if (kpg) grounds_free(kpg);
      return ret;
    }
    
    Form *labelstore_read(FSID labelid) {
      P(&ls_mutex);
      GenericFS_File *label = GenericFS_getfile(labelid);
      if(label == NULL) {
	V(&ls_mutex);
	printk_red("invalid storeid or labelid");
	return NULL;
      }
      Form *f = form_from_der((Formula *)label->data);
      V(&ls_mutex);
      if (!f)
	printk_red("invalid formula in label");
      return f;
    }

  }
  
  decls __caller__ {
    includefiles { "<stdlib.h>" }
  }    	   

  interface
  int Get_IPD_Name(int tgt_ipd_id, unsigned char *buff, int bufflen, _Grounds *pg){

    // todo: check grounds

    IPD *ipd = ipd_find(tgt_ipd_id);
    if (!ipd)
      return -1;

    Form *prin = ipd_get_speaker(ipd);
    Formula *der = form_to_der(prin);
    int derlen = der_msglen(der->body);

    dprintf(INFO, "poking into %p (%d bytes)\n", buff, bufflen);
    if(buff != NULL){
      dprintf(INFO, "%d bytes in name\n", derlen);
      int readlen = (bufflen > derlen) ? derlen : bufflen;
      dprintf(INFO, "%d bytes for readlen\n", readlen);
      poke_user(nexusthread_current_map(), (unsigned int)buff, (void *)der, readlen);
    }
   
    return derlen;
  }

 
  decls __callee__ {
    struct ThreadIterateCtx {
      Form *tail;
      int count;
      int limit;
    };
    static void convert_thread_schedstate(BasicThread *t, void *_ctx) {
      struct ThreadIterateCtx *ctx = (struct ThreadIterateCtx *)_ctx;
      Form *curr = NULL;
#if 0
      assert(t->type == USERTHREAD);
      t = (BasicThread *)((UThread*)t)->kthread;
      printk_red("convert id=%d %p\n", nexusthread_id(t), t);
#endif
      switch(t->sched_type) {
      case SCHEDTYPE_INTERVAL:
	curr = term_fmt("SchedStateInfo(%{int},\"Interval\",%{int})",
			nexusthread_id(t), t->interval.numerator);
	break;
      case SCHEDTYPE_ROUNDROBIN:
	curr = term_fmt("SchedStateInfo(%{int},\"RoundRobin\")",
			nexusthread_id(t));
	break;
      default:
	assert(0);
      }

      if(ctx->limit == 0 || ctx->count < ctx->limit) {
	if(ctx->tail == NULL) {
	  ctx->tail = 
	    form_new(F_LIST_CONS, curr, 0, form_new(F_LIST_NONE, 0, 0, 0));
	} else {
	  ctx->tail = form_new(F_LIST_CONS, curr, 0, ctx->tail);
	}
      }
      ctx->count++;
    }

    static Formula *generate_kernel_stmt(KernelLabelType kind, char *err_str, void *args) {
      Formula *kstmt;
      Form *stmt = NULL;
      switch(kind) {
      case LABELTYPE_BOOTHASH: {
	Form *nsk = ipd_get_nsk_form(nexusthread_current_ipd());
	Form *prin = ipd_get_speaker(nexusthread_current_ipd());
	stmt = form_fmt("%{term} says BootHash(%{term}) = %{bytes:20}",
			      nsk, prin, Map_getHashValue(nexusthread_current_map()));
	break;
      }
      case LABELTYPE_SCHEDULER: {
	Form *nsk = ipd_get_nsk_form(nexusthread_current_ipd());
	Form *prin = ipd_get_speaker(nexusthread_current_ipd());
	struct ThreadIterateCtx ctx;
	ctx.tail = NULL;
	ctx.count = 0;
	ctx.limit = 0;
	assert(0);
	//BROKEN: iterate over all threads (simple to recreate)
	// ipd_iterate_threads(nexusthread_current_ipd(), convert_thread_schedstate, &ctx);
	assert(ctx.tail != NULL);
	stmt = form_fmt("%{term} says SchedState(%{term}) = %{term}",
			nsk, prin, form_new(F_TERM_TSET, ctx.tail, 0, 0));
	break;
      }
      default:
	sprintf(err_str, "bad kind (%d)", kind);
	return NULL;
      }
      if (!stmt) {
	printk_red("malformed statement\n");
	sprintf(err_str, "malformed statement");
	return NULL;
      }
      kstmt = form_to_der(stmt);
	
      if (!kstmt) {
	printk_red("bad speaker encoding\n");
	sprintf(err_str, "bad speaker encoding");
	return NULL;
      }
      return kstmt;
    }
  }

  // kind = 1 ==> label with boot time hash
  // kind = 2 ==> ...
  interface
  FSID Nexus_Label(FSID storeid, int kind, char *uname, void *args, _Grounds *pg) {
    Formula *kstmt = NULL;

    int err;
    char *name = peek_strdup(nexusthread_current_map(), (unsigned int)uname, &err);
    if (err) return FSID_ERROR(-err);
    if (strlen(name) < 1) return FSID_ERROR(FS_INVALID);
    
    // todo: check stored policy vs. grounds (as INSERT)
    char err_str[80];
    kstmt = generate_kernel_stmt(kind, err_str, args);
    if(kstmt == NULL) {
      nxcompat_free(name);
      FAILRETURN(FSID_ERROR(FS_INVALID), "%s", err_str);
    }

    P(&ls_mutex); 
    GenericFS_Dir *store = GenericFS_getdir(storeid);
    if(store == NULL) {
      V(&ls_mutex); 
      nxcompat_free(kstmt);
      nxcompat_free(name);
      return FSID_ERROR(FS_INVALID);
    }

    GenericFS_File *label = GenericFS_mkfree(store, name, kstmt->body, der_msglen(kstmt->body));
    nxcompat_free(name);
    FSID id = (label ? label->id : FSID_ERROR(FS_INVALID));
    V(&ls_mutex); 
    return id;
  }

  // same as Nexus_Label, but returns a signed version instead of inserting into label store
  interface
  int Nexus_Get_Label(int kind, void *args, char *buff, int bufflen) {
    Formula *kstmt = NULL;

    char err_str[64];
    kstmt = generate_kernel_stmt(kind, err_str, args);
    if(kstmt == NULL) {
      FAILRETURN(-FS_INVALID, "%s", err_str);
    }

    KVKey_nsk *nsk = ipd_get_nsk(nexusthread_current_ipd());
    if (!nsk) {
      FAILRETURN(-FS_INVALID, "missing nsk");
    }

    SignedFormula *sf = formula_sign(kstmt, nsk);
    if (!sf) {
      FAILRETURN(-1, "could not sign");
    }

    int len = der_msglen(sf->body);

    dprintf(INFO, "poking into %p (%d bytes)\n", buff, bufflen);
    if(buff != NULL){
      dprintf(INFO, "%d bytes in label\n", len);
      int readlen = (bufflen > len) ? len : bufflen;
      dprintf(INFO, "%d bytes for readlen\n", readlen);
      if (poke_user(nexusthread_current_map(), (unsigned int)buff, (void *)sf, readlen))
	len = -FS_ACCESSERROR;
    }

    return len;
  }

  interface
  FSID Store_Create(char *uname) {
    IPD *ipd = nexusthread_current_ipd();
    if (!ipd->labelstores_node)
      return FSID_ERROR(FS_INVALID);

    int err;
    char *name = peek_strdup(nexusthread_current_map(), (unsigned int)uname, &err);
    if (err) return FSID_ERROR(-err);
    if (strlen(name) < 1) return FSID_ERROR(FS_INVALID);

    P(&ls_mutex);
    if (GenericFS_finddir(ipd->labelstores_node, name)) {
      V(&ls_mutex);
      nxcompat_free(name);
      return FSID_ERROR(FS_ALREADYPRESENT);
    }

    GenericFS_Dir *ls = GenericFS_mkdir(ipd->labelstores_node, name);
    GenericFS_mkdir(ls, "policy");
    FSID id = ls->id;
    V(&ls_mutex);

    return id;
  }

  interface
  int Store_Delete(FSID storeid, _Grounds *pg) {
    // todo: check policy (also: sanity check that id really points to a labelstore)
    P(&ls_mutex);
    GenericFS_Dir *ls = GenericFS_getdir(storeid);
    if (!ls) {
      V(&ls_mutex);
      return -FS_INVALID;
    }
    GenericFS_rmdir(ls);
    V(&ls_mutex);
    return 0;
  }
  
  interface
  int Store_Set_Policy(FSID storeid, LabelStoreOperation op, _Policy *newpol, _Grounds *pg) {
    // todo: check policy (also: sanity check that id really points to a labelstore)
    char *opname = label_policy_name(op);
    if (!opname) return -FS_INVALID;

    int stmtlen = (newpol ? der_msglen_u(newpol->gf.body) : 0);
    if(!stmtlen || stmtlen > LABELSTORE_MAX_STMTLEN) return -FS_INVALID;
    
    _Policy *knewpol = nxcompat_alloc(stmtlen);
    if(knewpol == NULL) return -FS_NOMEM;

    if(peek_user(nexusthread_current_map(), (unsigned int)newpol, knewpol, stmtlen) < 0) {
      nxcompat_free(knewpol);
      return -FS_INVALID;
    }

    P(&ls_mutex);
    GenericFS_Dir *ls = GenericFS_getdir(storeid);
    if (!ls) {
      V(&ls_mutex);
      return -FS_INVALID;
    }
    GenericFS_Dir *policy = GenericFS_finddir(ls, "policy");

    GenericFS_File *pol = GenericFS_findfile(policy, opname);
    if (pol) {
      nxcompat_free(pol->data);
      pol->len = stmtlen;
      pol->data = (char *)knewpol;
    } else {
      pol = GenericFS_mkfree(policy, opname, (char *)knewpol, stmtlen);
    }
    V(&ls_mutex);
    return 0;
  }
  
  //Readdir on /[IPD]/labels enumerates the stores
  //Readdir on /[IPD]/labels/[store]/ enumerates a store
  //Readdir on /[IPD]/labels/[store]/policy/ enumerates a store's policies
  
  interface
  FSID Label_Create(FSID storeid, char *uname, Formula *ustmt, _Grounds *pg) {
    int stmtlen = der_msglen_u(ustmt->body);

    int err;
    char *name = peek_strdup(nexusthread_current_map(), (unsigned int)uname, &err);
    if (err) return FSID_ERROR(-err);
    if (strlen(name) < 1) return FSID_ERROR(FS_INVALID);
    
    if(!stmtlen || stmtlen > LABELSTORE_MAX_STMTLEN){
      printk_red("LabelStore_Label_Create(); statement_len too long");
      nxcompat_free(name);
      return FSID_ERROR(FS_INVALID);
    }

    Formula *kstmt = nxcompat_alloc(stmtlen);
    if(kstmt == NULL){
      printk_red("LabelStore_Label_Create(); out of memory");
      nxcompat_free(name);
      return FSID_ERROR(FS_INVALID);
    }
    if(peek_user(nexusthread_current_map(), (unsigned int)ustmt, kstmt, stmtlen) < 0) {
      nxcompat_free(kstmt);
      nxcompat_free(name);
      return FSID_ERROR(FS_INVALID);
    }

    Form *f = form_from_der(kstmt); // todo: sanity check the formula 
    nxcompat_free(kstmt);
    if (!f) {
      nxcompat_free(name);
      return FSID_ERROR(FS_INVALID);
    }

    f = form_fmt("%{term} says ( %{term} says %{Stmt} )", 
		 ipd_get_nsk_form(nexusthread_current_ipd()),
		 ipd_get_speaker(nexusthread_current_ipd()), f);
    if (!f) {
      printk_red("ipd does not have a valid nsk installed\n");
      nxcompat_free(name);
      return FSID_ERROR(FS_INVALID);;
    }
    kstmt = form_to_der(f);
    form_free(f);
    if (!kstmt) {
      printk_red("bad speaker encoding\n");
      nxcompat_free(name);
      return FSID_ERROR(FS_INVALID);;
    }

    P(&ls_mutex); 
    GenericFS_Dir *store = GenericFS_getdir(storeid);
    if(store == NULL) {
      V(&ls_mutex); 
      nxcompat_free(kstmt);
      nxcompat_free(name);
      return FSID_ERROR(FS_INVALID);
    }

    GenericFS_File *label = GenericFS_mkfree(store, name, kstmt->body, der_msglen(kstmt->body));
    nxcompat_free(name);
    FSID id = (label ? label->id : FSID_ERROR(FS_INVALID));
    V(&ls_mutex); 
    if (label == NULL) nxcompat_free(kstmt);
    return id;
  }
  
  interface
  FSID Label_Copy(FSID dest_storeid, char *uname, FSID src_labelid, _Grounds *pg) {
    int err;
    char *name = peek_strdup(nexusthread_current_map(), (unsigned int)uname, &err);
    if (err) return FSID_ERROR(-err);
    if (strlen(name) < 1) return FSID_ERROR(FS_INVALID);
    
    P(&ls_mutex); 
    GenericFS_Dir *store = GenericFS_getdir(dest_storeid);
    if(store == NULL) {
      V(&ls_mutex); 
      nxcompat_free(name);
      return FSID_ERROR(FS_INVALID);
    }

    GenericFS_File *src_label = GenericFS_getfile(src_labelid);
    if (src_label == NULL) {
      V(&ls_mutex); 
      nxcompat_free(name);
      return FSID_ERROR(FS_INVALID);
    }

    char *data = nxcompat_alloc(src_label->len);
    memcpy(data, src_label->data, src_label->len);
    GenericFS_File *label = GenericFS_mkfree(store, name, data, src_label->len);
    nxcompat_free(name);
    FSID id = (label ? label->id : FSID_ERROR(FS_INVALID));
    V(&ls_mutex);
    if (label == NULL) nxcompat_free(data);
    return id;
  }
  
  interface
  int Label_Delete(FSID labelid, _Grounds *pg) {
    P(&ls_mutex);
    GenericFS_File *label = GenericFS_getfile(labelid);
    if (label == NULL) {
      V(&ls_mutex); 
      return -FS_INVALID;
    }
    GenericFS_rm(label);
    V(&ls_mutex);
    return 0;
  }
  
  //Read on /[IPD]/labels/[store]/[label] shows the label's contents

  interface
  int Label_Externalize(FSID labelid, char *buff, int bufflen, _Grounds *pg) {

    P(&ls_mutex);
    GenericFS_File *label = GenericFS_getfile(labelid);
    if (label == NULL) {
      V(&ls_mutex); 
      return -FS_INVALID;
    }

    /* int err = ls_check_policy(store, label, pg, OP_LS_READ);
    if (err) FAILRETURN(err, "Label_Read policy check failed"); */
    
    //printk_red("Label_Read for label: %c%c%c%c... (%d)\n", label->file_data[0], label->file_data[1], label->file_data[2], label->file_data[3], label->file_data_len);

    KVKey_nsk *nsk = ipd_get_nsk(nexusthread_current_ipd());
    if (!nsk) {
      V(&ls_mutex);
      FAILRETURN(-FS_INVALID, "missing nsk");
    }
    Formula *f = (Formula *)label->data;
    // there are three variants of labels:
    //  - those generated by nexus itself (label: nsk says something)
    //    exported as {nsk says BootHash(X) = Y}_nsk
    //  - those generated by subprincipals (label: nsk.ipd says something)
    //    exported as {nsk.ipd says BootHash(X) = Y}_nsk
    //  - those imported from foreign keys (label: nsk says K says something)
    //    exported as {nsk says K says BootHash(X) = Y}_nsk
    SignedFormula *sf = formula_sign(f, nsk);
    if (!sf) {
      V(&ls_mutex);
      FAILRETURN(-FS_INVALID, "could not sign");
    }

    int len = der_msglen(sf->body);

    dprintf(INFO, "poking into %p (%d bytes)\n", buff, bufflen);
    if(buff != NULL){
      dprintf(INFO, "%d bytes in label\n", len);
      int readlen = (bufflen > len) ? len : bufflen;
      dprintf(INFO, "%d bytes for readlen\n", readlen);
      if (poke_user(nexusthread_current_map(), (unsigned int)buff, (void *)sf, readlen))
	len = -FS_ACCESSERROR;
    }

    V(&ls_mutex);
    return len;
  }

  interface
  int Sign(Formula *ustmt, char *buff, int bufflen) {

    int stmtlen = der_msglen_u(ustmt->body);
    if(!stmtlen || stmtlen > LABELSTORE_MAX_STMTLEN){
      printk_red("LabelStore_Label_Create(); statement_len too long");
      return -1;
    }

    Formula *kstmt = nxcompat_alloc(stmtlen);
    if(kstmt == NULL){
      printk_red("LabelStore_Sign(); out of memory");
      return -1;
    }
    if(peek_user(nexusthread_current_map(), (unsigned int)ustmt, kstmt, stmtlen) < 0) {
      nxcompat_free(kstmt);
      return -1;
    }

    Form *f = form_from_der(kstmt); // todo: sanity check the formula 
    nxcompat_free(kstmt);
    if (!f) {
      return -1;
    }

    f = form_fmt("%{term} says %{Stmt}", ipd_get_speaker(nexusthread_current_ipd()), f);
    if (!f) {
      printk_red("ipd does not have a valid nsk installed\n");
      return -1;
    }
    kstmt = form_to_der(f);
    form_free(f);
    if (!kstmt) {
      printk_red("bad speaker encoding\n");
      return -1;
    }

    KVKey_nsk *nsk = ipd_get_nsk(nexusthread_current_ipd());
    if (!nsk) {
      FAILRETURN(-FS_INVALID, "missing nsk");
    }

    // there are three variants of labels:
    //  - those generated by nexus itself (label: nsk says something)
    //    exported as {nsk says BootHash(X) = Y}_nsk
    //  - those generated by subprincipals (label: nsk.ipd says something)
    //    exported as {nsk.ipd says BootHash(X) = Y}_nsk
    //  - those imported from foreign keys (label: nsk says K says something)
    //    exported as {nsk says K says BootHash(X) = Y}_nsk
    // ??? is this still accurate?
    SignedFormula *sf = formula_sign(kstmt, nsk);
    if (!sf) {
      FAILRETURN(-1, "could not sign");
    }

    int len = der_msglen(sf->body);

    dprintf(INFO, "poking into %p (%d bytes)\n", buff, bufflen);
    if(buff != NULL){
      dprintf(INFO, "%d bytes in label\n", len);
      int readlen = (bufflen > len) ? len : bufflen;
      dprintf(INFO, "%d bytes for readlen\n", readlen);
      if (poke_user(nexusthread_current_map(), (unsigned int)buff, (void *)sf, readlen))
	len = -FS_ACCESSERROR;
    }

    return len;
  }

  //interface
  //FSID Label_Internalize(FSID storeid, char *uname, char *buff, int bufflen, Proof creds, int cred_len);
 
  //Label_Read is mainly here to demo policy checking, since FS permissions
  //don't exactly exist yet... 
  interface
  int Label_Read(FSID labelid, unsigned char *buff, int bufflen, _Grounds *pg){

    P(&ls_mutex);
    GenericFS_File *label = GenericFS_getfile(labelid);
    if(label == NULL) {
      V(&ls_mutex);
      FAILRETURN(-FS_INVALID, "invalid storeid or labelid");
    }

    int err = check_policy(label->parent, pg, OP_LS_READ);
    if (err) {
      V(&ls_mutex);
      FAILRETURN(-SC_NOPERM, "Label_Read policy check failed");
    }
    
    //printk_red("Label_Read for label: %c%c%c%c... (%d)\n", label->file_data[0], label->file_data[1], label->file_data[2], label->file_data[3], label->file_data_len);
   
    dprintf(INFO, "poking into %p (%d bytes)\n", buff, bufflen);
    int len = label->len;
    if(buff != NULL){
      dprintf(INFO, "%d bytes in label\n", len);
      int readlen = (bufflen > len ? len : bufflen);
      dprintf(INFO, "%d bytes for readlen\n", readlen);
      if (poke_user(nexusthread_current_map(), (unsigned int)buff, (void *)label->data, readlen))
	len = -FS_ACCESSERROR;
    }
   
    V(&ls_mutex);
    return len;
  }
}
