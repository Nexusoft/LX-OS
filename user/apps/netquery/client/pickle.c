NQ_Transaction NQ_Request_unpickle_transaction(unsigned char **data, int *datalen, int *err) {
  NQ_Transaction transaction = NQ_Request_unpickle_uuid(data, datalen, err);
  assert(transaction.type == NQ_UUID_TRANSACTION);
  return transaction;
}


//
// This file is included in net.c instead of via the Makefile
//

#ifdef NET_DEBUG
#define REQUEST_LOG(a) { a }
#else
#define REQUEST_LOG(a)
#endif

int NQ_Request_unpickle_bytes(unsigned char **data, int *len, int *err, int numbytes, unsigned char *output){
  *err = 0;
  if(*len >= numbytes){
    memcpy(output, *data, numbytes);
    *data = &((*data)[numbytes]);
//    printf("---- unpickling (%d left) -----\n", *len);
//    print_hex(output, numbytes);
//    printf("\n");
    *len -= numbytes;
    return numbytes;
  } else {
//    printf("unpickling failed: %d > %d\n", numbytes, *len);
  }
  *err = -1;
  return 0;
}

void NQ_Request_pickle_bytes(NQ_RingBuffer *buff, unsigned char *data, int len){
//  printf("---- pickling -----\n");
//  print_hex(data, len);
//  printf("\n");
  NQ_RingBuffer_write(buff, data, len);
}

// Pickle helper functions


#define MAKE_PICKLE(type, name) \
  void NQ_Request_pickle_##name(NQ_RingBuffer *buff, type output) { \
    NQ_Request_pickle_bytes(buff, (unsigned char *)&output, sizeof(output)); \
  }
#define MAKE_UNPICKLE(type, name) \
  type NQ_Request_unpickle_##name(unsigned char **data, int *len, int *err) { \
    type output; \
    NQ_Request_unpickle_bytes(data, len, err, sizeof(output), (unsigned char *)&output); \
    return output; \
  }

#define DEFINE_PICKLE(type, name) \
  MAKE_PICKLE(type, name);	  \
  MAKE_UNPICKLE(type, name);

DEFINE_PICKLE(int, int)
DEFINE_PICKLE(NQ_UUID, uuid)
DEFINE_PICKLE(NQ_Host, host)

#define CHECK_ERR_AND_RESET(reaction) if(*err < 0){ reaction; } *err = -1

#if 0
NQ_Principal *NQ_Request_unpickle_principal(unsigned char **data, int *len, int *err){
  int princ_len;
  NQ_Principal *ret;
  
  princ_len = NQ_Request_unpickle_int(data, len, err);
  CHECK_ERR_AND_RESET(return NULL);
  if(*len < princ_len){ return NULL; }

  ret = NQ_Principal_import(*data, princ_len, NULL);
//  printf("---- unpickling principal (%s) -----\n", (ret == NULL)?"failed":"succeeded");
//  print_hex(*data, princ_len);
//  printf("\n");
  *data = &((*data)[princ_len]);
  *len -= princ_len;
  if(ret == NULL) { return NULL; }
  
  *err = 0;
  return ret;
}
#endif

NQ_Principal *NQ_Request_unpickle_principal_hash(unsigned char **data, int *len, int *err, NQ_Socket *sock, NQ_Request_Data *req){
  int princ_len;
  NQ_Principal *ret;

  princ_len = NQ_Request_unpickle_int(data, len, err);
  CHECK_ERR_AND_RESET(return NULL);
  if(*len < princ_len){ return NULL; }

  if(princ_len == 0) {
    ret = &NQ_principal_null;
  } else {
    ret = NQ_Principal_import_hash(*data, princ_len);
  }
  if(!ret){
    return NULL;
  } else {
    *data = &((*data)[princ_len]);
    *len -= princ_len;
    *err = 0;  
  }
  return ret;
}

void NQ_Request_pickle_principal_hash(NQ_RingBuffer *buff, NQ_Principal *principal){
  unsigned char *data = NULL;
  int len = NQ_Principal_export_hash(principal, &data);
  // printf("Pickle principal hash len = %d\n", len);
  NQ_Request_pickle_int(buff, len);
  NQ_Request_pickle_bytes(buff, data, len);
}

NQ_Attribute_Name *NQ_Request_unpickle_attribute_name(unsigned char **data, int *len, int *err, NQ_Socket *sock, NQ_Request_Data *req){
  NQ_Principal *owner;
  NQ_Attribute_Type type;
  int namelen;
  NQ_Attribute_Name *ret;
  
  owner = NQ_Request_unpickle_principal_hash(data, len, err, sock, req); 
//  printf("principal unpickled: %d left (err: %d)\n", *len, *err);
  CHECK_ERR_AND_RESET(return NULL);
    
  type = NQ_Request_unpickle_int(data, len, err);
//  printf("type (%d) unpickled: %d left (err: %d)\n", type, *len, *err);
  CHECK_ERR_AND_RESET(NQ_Principal_delete(owner);return NULL);

  namelen = NQ_Request_unpickle_int(data, len, err);
//  printf("namelen (%d) unpickled: %d left (err: %d)\n", namelen, *len, *err);
  CHECK_ERR_AND_RESET(NQ_Principal_delete(owner);return NULL);
  
  ret = malloc(sizeof(NQ_Attribute_Name) + namelen+1);
  ret->owner = owner;
  ret->type = type;
  NQ_Request_unpickle_bytes(data, len, err, namelen, (unsigned char *)ret->name);
//  printf("name unpickled: %d left (err: %d)\n", *len, *err);
  CHECK_ERR_AND_RESET(free(ret);NQ_Principal_delete(owner);return NULL);
  ret->name[namelen] = '\0';
  
  *err = 0;
  return ret;
}

void NQ_Request_pickle_attribute_name(NQ_RingBuffer *buff, NQ_Attribute_Name *name){
  NQ_Request_pickle_principal_hash(buff, name->owner);
  NQ_Request_pickle_int(buff, name->type);
  NQ_Request_pickle_int(buff, strlen(name->name)+1);
  NQ_Request_pickle_bytes(buff, (unsigned char *)name->name, strlen(name->name)+1);
}

NQ_Tuple NQ_Net_Tuple_create(NQ_Transaction transaction, NQ_Host home, NQ_Principal *actor){
  int ret;
  unsigned char *data;
  unsigned int datalen;
  NQ_Tuple tuple;
  
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  PING();
  NQ_Request_pickle_uuid(&output, transaction);
  PING();
  NQ_Request_pickle_principal_hash(&output, actor);
  PING();
  REQUEST_LOG(printf("NQ_Net_Tuple_create(");NQ_Host_print(home);printf(")\n");)
  ret = NQ_Request_issue(home, &output, NQ_REQUEST_TUPLE_CREATE, &data, &datalen);
  NQ_RingBuffer_destroy(&output);
  if((ret >= 0)&&(datalen >= sizeof(NQ_Tuple))){
    memcpy(&tuple, data, sizeof(NQ_Tuple));
  } else {
    NQ_UUID_clr(&tuple);
  }
  return tuple;
}
void NQ_Batch_Tuple_create(NQ_Transaction transaction, NQ_Host home, NQ_Principal *actor, NQ_Net_Batch *batch){
  int ret;
  // XXX need to match this up with the normal tuple create pickle
  
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  PING();
  NQ_Request_pickle_uuid(&output, transaction);
  PING();
  NQ_Request_pickle_principal_hash(&output, actor);
  PING();
  REQUEST_LOG(printf("NQ_Batch_Tuple_create(");NQ_Host_print(home);printf(")\n");)
    ret = NQ_Request_issue_batch(home, &output, NQ_REQUEST_TUPLE_CREATE, 0, batch, NULL, NULL);
  NQ_RingBuffer_destroy(&output);
}
NQ_Tuple NQ_Batch_Tuple_create_finish(NQ_Net_Batch *batch){
  unsigned char *retdata;
  unsigned int retlen;
  unsigned int type;
  int ret;
  NQ_Tuple tuple;
  ret = NQ_Net_Batch_finish(batch, &retdata, &retlen, &type);
  
  if(type != (NQ_REQUEST_TUPLE_CREATE | NQ_REQUEST_RESPONSE)){
    printf("Got %x, expected %x\n", type, (NQ_REQUEST_TUPLE_CREATE | NQ_REQUEST_RESPONSE));
    ret = -ERR_BATCH_READ_OUT_OF_ORDER;  
  }

  if(ret){
    printf("NQ_Batch_Tuple_create_finish() error: %d\n", ret);
  }

  if((ret >= 0)&&(retlen >= sizeof(NQ_Tuple))){
    memcpy(&tuple, retdata, sizeof(NQ_Tuple));
  } else {
    NQ_UUID_clr(&tuple);
  }
  if(retdata){ free(retdata); }
  
  return tuple;
}
int NQ_Request_Tuple_create(NQ_Socket *sock, NQ_Request_Data *req){
  // XXX need to match this up with the batch tuple create pickle
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  NQ_Transaction transaction;
  NQ_Principal *actor = NULL;
  NQ_Tuple tuple;
  NQ_RingBuffer output, *response = NULL;
  int err;
  
  transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -20; goto nq_req_tup_del_att_err; }
  actor = NQ_Request_unpickle_principal_hash(&data, &datalen, &err, sock, req);
  if(err < 0){ err = -30; goto nq_req_tup_del_att_err; }
  REQUEST_LOG(printf("NQ_Request_Tuple_create()\n");)
  
  tuple = NQ_Local_Tuple_create(transaction, actor);
  err = 0;
  NQ_RingBuffer_init(&output);
  NQ_RingBuffer_write(&output, (unsigned char *)&tuple, sizeof(NQ_Tuple));
  response = &output;
  
nq_req_tup_del_att_err:
  if(err != 0) {
    printf("%s: err = %d\n", __FUNCTION__, err);
  }
  if(actor != NULL){
    NQ_Principal_delete(actor);
  }
  NQ_Request_respond(sock, response, req, err);
  if(response){
    NQ_RingBuffer_destroy(response);
  }
  return err;
}

static void delete_build(NQ_RingBuffer *output, NQ_Transaction transaction, NQ_Principal *actor, NQ_Tuple tuple) {
  NQ_Request_pickle_uuid(output, transaction);
  NQ_Request_pickle_principal_hash(output, actor);
  NQ_Request_pickle_uuid(output, tuple);
}

int NQ_Net_Tuple_delete(NQ_Transaction transaction, NQ_Principal *actor, NQ_Tuple tuple){
  int ret;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  delete_build(&output, transaction, actor, tuple);
  REQUEST_LOG(printf("NQ_Net_Tuple_delete(");NQ_Host_print(tuple.home);printf(")\n");)
  ret = NQ_Request_issue(tuple.home, &output, NQ_REQUEST_TUPLE_DELETE, NULL, NULL);
  NQ_RingBuffer_destroy(&output);
  return ret;
}

void NQ_Batch_Tuple_delete(NQ_Transaction transaction, NQ_Principal *actor, NQ_Net_Batch *batch, NQ_Tuple tuple) {
  int ret;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  delete_build(&output, transaction, actor, tuple);
  REQUEST_LOG(printf("NQ_Batch_Tuple_delete(");NQ_Host_print(tuple.home);printf(")\n"););
  ret = NQ_Request_issue_batch(actor->home, &output, NQ_REQUEST_TUPLE_DELETE, 0, batch, NULL, NULL);
  NQ_RingBuffer_destroy(&output);
}
int NQ_Batch_Tuple_delete_finish(NQ_Net_Batch *batch) {
  unsigned char *retdata;
  unsigned int retlen;
  unsigned int type;
  int ret;
  ret = NQ_Net_Batch_finish(batch, &retdata, &retlen, &type);
  
  if(type != (NQ_REQUEST_TUPLE_DELETE | NQ_REQUEST_RESPONSE)){
    printf("Got %x, expected %x\n", type, (NQ_REQUEST_TUPLE_DELETE | NQ_REQUEST_RESPONSE));
    ret = -ERR_BATCH_READ_OUT_OF_ORDER;  
  }

  if(ret){
    printf("NQ_Batch_Tuple_delete_finish() error: %d\n", ret);
  }

  assert(retlen == 0 && retdata == NULL);
  return ret;
}

int NQ_Request_Tuple_delete(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  NQ_Transaction transaction;
  NQ_Principal *actor = NULL;
  NQ_Tuple tuple;
  int err;
  
  REQUEST_LOG(printf("NQ_Request_Tuple_add_attribute()\n");)
  
  transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -20; goto nq_req_tup_del_att_err; }
  actor = NQ_Request_unpickle_principal_hash(&data, &datalen, &err, sock, req);
  if(err < 0){ err = -30; goto nq_req_tup_del_att_err; }
  tuple = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -40; goto nq_req_tup_del_att_err; }
  if(!NQ_Net_is_local(tuple.home)){ err = -1; goto nq_req_tup_del_att_err; }
  
  err = NQ_Local_Tuple_delete(transaction, actor, tuple);
  
nq_req_tup_del_att_err:
  if(err != 0) {
    printf("%s: err = %d\n", __FUNCTION__, err);
  }
  if(actor != NULL){
    NQ_Principal_delete(actor);
  }
  NQ_Request_respond(sock, NULL, req, err);
  return err;
}
int NQ_Net_Tuple_add_attribute(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name){
  int ret;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, transaction);
  NQ_Request_pickle_uuid(&output, tuple);
  NQ_Request_pickle_attribute_name(&output, name);
  REQUEST_LOG(printf("NQ_Net_Tuple_add_attribute(");NQ_Host_print(name->owner->home);printf(")\n");)
  ret = NQ_Request_issue_async(tuple.home, &output, NQ_REQUEST_TUPLE_ADD_ATT, 0);
  NQ_RingBuffer_destroy(&output);
  return ret;
}
int NQ_Request_Tuple_add_attribute(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  NQ_Transaction transaction;
  NQ_Attribute_Name *name = NULL;
  NQ_Tuple tuple;
  int err;
  
  REQUEST_LOG(printf("NQ_Request_Tuple_add_attribute()\n");)
  
  transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -20; goto nq_req_tup_del_att_err; }
  tuple = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -40; goto nq_req_tup_del_att_err; }
  if(!NQ_Net_is_local(tuple.home)){ err = -1; goto nq_req_tup_del_att_err; }
  name = NQ_Request_unpickle_attribute_name(&data, &datalen, &err, sock, req);
  if(err < 0){
    goto nq_req_tup_del_att_err;
  }
  
  err = NQ_Local_Tuple_add_attribute(transaction, tuple, name);
  
nq_req_tup_del_att_err:
  if(err != 0) {
    printf("%s: err = %d\n", __FUNCTION__, err);
  }
  if(name != NULL){
    NQ_Principal_delete(name->owner);
    free(name);
  }
  return err;
}

static void tuple_remove_attribute_build(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name, NQ_RingBuffer *output) {
  NQ_Request_pickle_uuid(output, transaction);
  NQ_Request_pickle_uuid(output, tuple);
  NQ_Request_pickle_attribute_name(output, name);
}

int NQ_Net_Tuple_remove_attribute(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name){
  int ret;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  tuple_remove_attribute_build(transaction, tuple, name, &output);
  REQUEST_LOG(printf("NQ_Net_Tuple_remove_attribute(");NQ_Host_print(name->owner->home);printf(")\n"););
  ret = NQ_Request_issue_async(tuple.home, &output, NQ_REQUEST_TUPLE_DEL_ATT, 0);
  NQ_RingBuffer_destroy(&output);
  return ret;
}

void NQ_Batch_Tuple_remove_attribute(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name, NQ_Net_Batch *batch){
  int ret;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  tuple_remove_attribute_build(transaction, tuple, name, &output);
  REQUEST_LOG(printf("NQ_Batch_Tuple_remove_attribute(");NQ_Host_print(name->owner->home);printf(")\n"););
#if 0
  ret = NQ_Request_issue_batch(tuple.home, &output, NQ_REQUEST_TUPLE_DEL_ATT, 0, batch, NULL, NULL);
#else
  // batch unnecessary since remove_attribute is non-blocking, unconditional request
  ret = NQ_Request_issue_async(tuple.home, &output, NQ_REQUEST_TUPLE_DEL_ATT, 0);
#endif
  NQ_RingBuffer_destroy(&output);
}

int NQ_Batch_Tuple_remove_attribute_finish(NQ_Net_Batch *batch) {
#if 0
  unsigned char *retdata;
  unsigned int retlen;
  unsigned int type;
  int ret;
  ret = NQ_Net_Batch_finish(batch, &retdata, &retlen, &type);
  
  if(type != (NQ_REQUEST_TUPLE_DEL_ATT | NQ_REQUEST_RESPONSE)){
    printf("Got %x, expected %x\n", type, (NQ_REQUEST_TUPLE_DEL_ATT | NQ_REQUEST_RESPONSE));
    ret = -ERR_BATCH_READ_OUT_OF_ORDER;  
  }

  if(ret){
    printf("NQ_Batch_Tuple_remove_attribute_finish() error: %d\n", ret);
  }

  assert(retlen == 0 && retdata == NULL);
  return ret;
#else
  // batch unnecessary since remove_attribute is non-blocking, unconditional request
  return 0;
#endif
}

int NQ_Request_Tuple_remove_attribute(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  NQ_Transaction transaction;
  NQ_Attribute_Name *name = NULL;
  NQ_Tuple tuple;
  int err;
  
  REQUEST_LOG(printf("NQ_Request_Tuple_remove_attribute()\n");)
  
  transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -20; goto nq_req_tup_del_att_err; }
  tuple = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -40; goto nq_req_tup_del_att_err; }
  if(!NQ_Net_is_local(tuple.home)){ err = -1; goto nq_req_tup_del_att_err; }
  name = NQ_Request_unpickle_attribute_name(&data, &datalen, &err, sock, req);
  if(err < 0){ err = -30; goto nq_req_tup_del_att_err; }
  
  err = NQ_Local_Tuple_remove_attribute(transaction, tuple, name);
  
nq_req_tup_del_att_err:
  if(err != 0) {
    printf("%s: err = %d\n", __FUNCTION__, err);
  }
  if(name != NULL){
    NQ_Principal_delete(name->owner);
    free(name);
  }
  return err;
}

int NQ_Net_Transaction_preregister(NQ_Host target, NQ_Transaction transaction){
  if( !NQ_Host_eq(transaction.home, NQ_Net_get_localhost()) ) {
    // if we get a handle to a remote transaction, it must already be
    // registered over there
    // fprintf(stderr, "preregistering non-local transaction: noop\n");
    return 0;
  }
  if(NQ_Transaction_client_registered(transaction, target) > 0){
    NQ_RingBuffer output;
    // call register_client first, since it's possible for the async call to result in a callback before register_client finishes registering
    NQ_Transaction_register_client(transaction, target);
    NQ_RingBuffer_init(&output);
    NQ_Request_pickle_uuid(&output, transaction);
    NQ_Request_issue_async(target, &output, NQ_REQUEST_TRANSACTION_R_PREREGISTER, 0);
    NQ_RingBuffer_destroy(&output);
    return 0;
  }
  return -1;
}

void NQ_Request_Transaction_preregister(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  int err;
  NQ_Transaction transaction;
  
  transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -ERR_UNABLE_TO_UNPICKLE(0); return; }
  
  NQ_Transaction_install_remote(transaction);
}

int NQ_Net_Attribute_operate(
  NQ_Transaction transaction,
  NQ_Principal *actor,
  NQ_Attribute_Name *name, NQ_Tuple tuple, 
  NQ_Attribute_Operation op, 
  char **iobuffer, int *iolength,
  NQ_Principal **output_attributed_to){
  int ret;
  NQ_RingBuffer output;
  // XXX need to match up with batch attribute_operate

  NQ_Net_Transaction_preregister(name->owner->home, transaction);
  
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, transaction);
  NQ_Request_pickle_principal_hash(&output, actor);
  NQ_Request_pickle_attribute_name(&output, name);
  NQ_Request_pickle_uuid(&output, tuple);
  NQ_Request_pickle_int(&output, op);
  NQ_Request_pickle_int(&output, *iolength);
  NQ_Request_pickle_bytes(&output, (unsigned char *)*iobuffer, *iolength);
  *iobuffer = NULL;
  *iolength = 0;
  REQUEST_LOG(printf("NQ_Net_Attribute_operate(%d)\n", op));
  unsigned char *io = NULL;
  unsigned int len = 0;
  ret = NQ_Request_issue(name->owner->home, &output, NQ_REQUEST_ATTRIBUTE_OP, &io, &len);
  unsigned char *data = io;

  if(output_attributed_to != NULL) {
    *output_attributed_to =
      NQ_Request_unpickle_principal_hash(&data, (int*)&len, &ret, NULL, NULL);
  }
  if(ret == 0) {
    // callers assume that iobuffer returns to beginning of newly-allocated memory block
    // XXX memmove would be faster
    if(len > 0) {
      *iobuffer = malloc(len);
      memcpy(*iobuffer, data, len);
    } else {
      *iobuffer = NULL;
    }
    *iolength = len;
    free(io);
  }

  NQ_RingBuffer_destroy(&output);
  return ret;
}

int NQ_Batch_Attribute_operate(
  NQ_Transaction transaction, 
  NQ_Principal *actor,
  NQ_Attribute_Name *name, NQ_Tuple tuple, 
  NQ_Attribute_Operation op, 
  char **iobuffer, int *iolength,
  NQ_Net_Batch *batch,
  NQ_Batch_Handler handler, void *handler_state){
  int ret;
  NQ_RingBuffer output;
  
  NQ_Net_Transaction_preregister(name->owner->home, transaction);

  // XXX need to match up with normal attribute_operate
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, transaction);
  NQ_Request_pickle_principal_hash(&output, actor);
  NQ_Request_pickle_attribute_name(&output, name);
  NQ_Request_pickle_uuid(&output, tuple);
  NQ_Request_pickle_int(&output, op);
  NQ_Request_pickle_int(&output, *iolength);
  NQ_Request_pickle_bytes(&output, (unsigned char *)*iobuffer, *iolength);
  REQUEST_LOG(printf("NQ_Batch_Attribute_operate(%d)\n", op);)
  ret = NQ_Request_issue_batch(name->owner->home, &output, NQ_REQUEST_ATTRIBUTE_OP, 0, batch, handler, handler_state);
  NQ_RingBuffer_destroy(&output);
  return ret;
}
int NQ_Batch_Attribute_operate_finish(char **iobuffer, int *iolength, NQ_Principal **output_attributed_to, NQ_Net_Batch *batch){
  unsigned int type;
  int ret = 0;
  unsigned char *data = NULL;
  unsigned int len = 0;
  ret = NQ_Net_Batch_finish(batch, &data, &len, &type);

  *output_attributed_to = NQ_Request_unpickle_principal_hash(&data, (int*)&len, &ret, NULL, NULL);

  if(ret == 0) {
    // callers assume that iobuffer returns to beginning of newly-allocated memory block
    // XXX memmove would be faster
    *iobuffer = malloc(len);
    memcpy(*iobuffer, data, len);
    *iolength = len;
    free(data);
  }

  
  if(type != (NQ_REQUEST_ATTRIBUTE_OP | NQ_REQUEST_RESPONSE)){
    printf("Got %x, expected %x\n", type, (NQ_REQUEST_ATTRIBUTE_OP | NQ_REQUEST_RESPONSE));
    ret = -ERR_BATCH_READ_OUT_OF_ORDER;  
    free(*iobuffer);
  }

  if( (NQ_ATTR_GET_TX_STATE(ret) & NQ_ATTR_TX_STATE_VALID)) {
    if(NQ_ATTR_GET_TX_STATE(ret) & NQ_ATTR_TX_STATE_HAS_PENDING_TRIGGERS) {
      printf("not sure what to do in this batch state!\n");
      assert(0);
    }
    // NQ_Transaction_update_shadow_state(transaction, (NQ_ATTR_GET_TX_STATE(rv) & NQ_ATTR_TX_STATE_HAS_PENDING_TRIGGERS));
  }
  
  return NQ_ATTR_GET_ERRCODE(ret);
}

int NQ_Request_Attribute_operate(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  NQ_Transaction transaction;
  NQ_Principal *actor;
  NQ_Attribute_Name *name = NULL;
  NQ_Tuple tuple;
  NQ_Attribute_Operation op;
  int io_len;
  unsigned char *io = NULL;
  int err;
  NQ_RingBuffer output;
  
  PING();
  
  transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -20; goto nq_req_att_op_err; }
  PING();
  actor = NQ_Request_unpickle_principal_hash(&data, &datalen, &err, sock, req); 
  if(err < 0){ err = -25; fprintf(stderr, "could not attribute_operate: invalid principal\n"); goto nq_req_att_op_err; }
  name = NQ_Request_unpickle_attribute_name(&data, &datalen, &err, sock, req);
  if(err < 0){ err = -30; goto nq_req_att_op_err; }
  PING();
  if(!NQ_Net_is_local(name->owner->home)){ 
    printf("Request to operate from nonlocal owner: ");NQ_Host_print(name->owner->home);printf(" != localhost:"); NQ_Host_print(NQ_Net_get_localhost());printf("\n");
    err = -1; goto nq_req_att_op_err; 
  }
  tuple = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  PING();
  if(err < 0){ err = -40; goto nq_req_att_op_err; }
  op = NQ_Request_unpickle_int(&data, &datalen, &err);
  PING();
  if(err < 0){ err = -50; goto nq_req_att_op_err; }
  io_len = NQ_Request_unpickle_int(&data, &datalen, &err);
  PING();
  if(err < 0){ err = -60; goto nq_req_att_op_err; }
  if(io_len > 0) {
    io = malloc(io_len);
    NQ_Request_unpickle_bytes(&data, &datalen, &err, io_len, io);
  } else {
    io = NULL;
  }
  PING();
  if(err < 0){ err = -70; goto nq_req_att_op_err; }

  REQUEST_LOG(printf("NQ_Request_Attribute_operate(%d on %s@", op, name->name);NQ_Host_print(name->owner->home);printf(")\n");)
  
  // get rid of type pun warning
  char *_io = (char *)io;
  PING();

  NQ_Principal *output_attributed_to = NULL;
  err = NQ_Local_Attribute_operate(transaction, actor, name, tuple, op, (char **)&_io, &io_len, &output_attributed_to);
  PING();
  free(io);
  io = (unsigned char *)_io;

  //and return.
  NQ_RingBuffer_init(&output);

  if(output_attributed_to == NULL) {
    NQ_Request_pickle_principal_hash(&output, &NQ_principal_null);
  } else {
    NQ_Request_pickle_principal_hash(&output, output_attributed_to);
    NQ_Principal_delete(output_attributed_to);
  }

  if(io_len > 0){
    NQ_Request_pickle_bytes(&output, io, io_len);
  }
  PING();

  NQ_Transaction_Real *t_real = NQ_Transaction_get_any(transaction);
  short tx_state = NQ_ATTR_TX_STATE_VALID |
    ( NQ_Transaction_has_pending_triggers(t_real) ? 
      NQ_ATTR_TX_STATE_HAS_PENDING_TRIGGERS : 0 );
  NQ_Request_respond(sock, &output, req, NQ_ATTR_BUILD_RESULT(err, tx_state));
  PING();
  NQ_RingBuffer_destroy(&output);
  NQ_Principal_delete(name->owner);
  free(name);
  if(err != 0) {
    printf("%s: op = %d, err = %d\n", __FUNCTION__, op, err);
  }
  NQ_Transaction_Real_put(t_real);
  return err;
  
nq_req_att_op_err:
  if(err != 0) {
    printf("%s: err = %d\n", __FUNCTION__, err);
  }
  if(name != NULL){
    NQ_Principal_delete(name->owner);
    free(name);
  }
  NQ_Request_respond(sock, NULL, req, NQ_ATTR_BUILD_RESULT(err, 0));
  return -1;
}
void NQ_Batch_Transaction_begin(NQ_Host host, NQ_Net_Batch *batch){
  int err;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  REQUEST_LOG(printf("NQ_Net_Transaction_begin_batch()\n");)
    err = NQ_Request_issue_batch(host, &output, NQ_REQUEST_TRANSACTION_START, 0, batch, NULL, NULL);
  NQ_RingBuffer_destroy(&output);
}
NQ_Transaction NQ_Batch_Transaction_begin_finish(NQ_Net_Batch *batch){
  unsigned int type;
  unsigned int datalen;
  unsigned char *data;
  int ret;
  NQ_Transaction trans;
  ret = NQ_Net_Batch_finish(batch, &data, &datalen, &type);

  if(!ret){
    if(type != (NQ_REQUEST_TRANSACTION_START | NQ_REQUEST_RESPONSE)){
      printf("Got %x, expected %x\n", type, (NQ_REQUEST_TUPLE_CREATE | NQ_REQUEST_RESPONSE));
      ret = -ERR_BATCH_READ_OUT_OF_ORDER;  
    }
  }
  
  if((ret >= 0)||(datalen != sizeof(NQ_Transaction))){
    memcpy(&trans, data, sizeof(NQ_Transaction));
    //NQ_UUID_print(&ret);printf("<--- transaction!\n");
  } else {
    NQ_UUID_clr(&trans);
    printf("NQ_Batch_Transaction_begin_finish() error: %d (%d/%lu bytes read)\n", ret, datalen, (unsigned long)sizeof(NQ_Transaction));
  }
  if(data){ free(data); }
  
  return trans;
}
NQ_Transaction NQ_Net_Transaction_begin(NQ_Host host){
  NQ_Transaction ret;
  unsigned int datalen;
  unsigned char *data;
  int err;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  PING();
  REQUEST_LOG(printf("NQ_Net_Transaction_begin()\n");)
  err = NQ_Request_issue(host, &output, NQ_REQUEST_TRANSACTION_START, &data, &datalen);
  PING();
  NQ_RingBuffer_destroy(&output);
  if((err >= 0)&&(datalen >= sizeof(NQ_Transaction))){
    memcpy(&ret, data, sizeof(NQ_Transaction));
    //NQ_UUID_print(&ret);printf("<--- transaction!\n");
  } else {
    NQ_UUID_clr(&ret);
    printf("Error on transaction!\n");
  }
  return ret;
}
int NQ_Request_Transaction_begin(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen;
  unsigned char *data;
  datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);;
  data = req->data;
  NQ_Transaction transaction;
  int err;
  NQ_RingBuffer output, *response = NULL;
  
  REQUEST_LOG(printf("NQ_Request_Transaction_begin()\n");)
  
  transaction = NQ_Local_Transaction_begin();
  
  err = 0;
  NQ_RingBuffer_init(&output);
  NQ_RingBuffer_write(&output, (unsigned char *)&transaction, sizeof(NQ_Tuple));
  response = &output;
  
  if(err != 0){ printf("%s: err = %d\n", __FUNCTION__, err); }
  NQ_Request_respond(sock, response, req, err);
  if(response){
    NQ_RingBuffer_destroy(response);
  }
  return err;
}
int NQ_Batch_Transaction_abort(NQ_Transaction transaction, NQ_Net_Batch *batch){
  int ret;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  REQUEST_LOG(printf("NQ_Batch_Transaction_abort()\n");)
  ret = NQ_Request_issue_batch(transaction.home, &output, NQ_REQUEST_TRANSACTION_ABORT, 0, batch, NULL, NULL);
  NQ_RingBuffer_destroy(&output);
  return ret;
}
int NQ_Net_Transaction_abort(NQ_Transaction transaction){
  int ret;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, transaction);
  REQUEST_LOG(printf("NQ_Net_Transaction_abort()\n");)
  ret = NQ_Request_issue(transaction.home, &output, NQ_REQUEST_TRANSACTION_ABORT, NULL, NULL);
  NQ_RingBuffer_destroy(&output);
  return ret;
}
int NQ_Request_Transaction_abort(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  NQ_Transaction transaction;
  int err;
  NQ_Request_Data *reqdup = NULL;
  
  REQUEST_LOG(printf("NQ_Request_Transaction_abort()\n");)
  
  transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -30; goto nq_req_trans_abort_err; }
  
  reqdup = malloc(sizeof(NQ_Request_Data));
  //this will only be used for the header and for the localrequest pointer if applicable
  memcpy(reqdup, req, sizeof(NQ_Request_Data));
  reqdup->data = NULL; 
  
  err = NQ_Local_Transaction_abort(transaction, sock, reqdup);
  
  if(!err){
    return 0; //no error means that abort will eventually call NQ_Request_Transaction_step_finish() above.
  }
nq_req_trans_abort_err:
  if(err != 0) {
    printf("%s: err = %d\n", __FUNCTION__, err);
  }
  if(reqdup){
    free(reqdup);
  }
  NQ_Request_respond(sock, NULL, req, err);
  return err;
}
int NQ_Net_Transaction_test(NQ_Transaction transaction){
  static int transaction_count = 0;
  int ret;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, transaction);
  REQUEST_LOG(printf("NQ_Net_Transaction_test()\n");)
    // printf("Net_Transaction_test(%d)\n", transaction_count);
  ret = NQ_Request_issue(transaction.home, &output, NQ_REQUEST_TRANSACTION_TEST, NULL, NULL);
  // printf("Result = %d\n", ret);
  NQ_RingBuffer_destroy(&output);
  // printf("Net_Transaction_test out(%d)\n", transaction_count);
  transaction_count++;
  return ret;
}
int NQ_Request_Transaction_test(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  NQ_Transaction transaction;
  int err;
  NQ_Request_Data *reqdup = NULL;
  
  REQUEST_LOG(printf("NQ_Request_Transaction_test()\n");)
  
  transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -30; goto nq_req_trans_test_err; }
  
  PING();
  reqdup = malloc(sizeof(NQ_Request_Data));
  //this will only be used for the header and for the localrequest pointer if applicable
  memcpy(reqdup, req, sizeof(NQ_Request_Data));
  reqdup->data = NULL; 

  err = NQ_Local_Transaction_test(transaction, sock, reqdup);
  PING();
  if(!err){
    return 0; //no error means that test will eventually call NQ_Request_Transaction_step_finish() above.
  }
  
nq_req_trans_test_err:
  if(err != 0) {
    printf("%s: err = %d\n", __FUNCTION__, err);
  }
  if(reqdup){
    free(reqdup);
  }
  NQ_Request_respond(sock, NULL, req, err);
  return err;
}
int NQ_Batch_Transaction_commit(NQ_Transaction transaction, NQ_Net_Batch *batch){
  int ret;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, transaction);
  REQUEST_LOG(printf("NQ_Batch_Transaction_commit()\n");)
  ret = NQ_Request_issue_batch(transaction.home, &output, NQ_REQUEST_TRANSACTION_COMMIT, 0, batch, NULL, NULL);
  NQ_RingBuffer_destroy(&output);
  return ret;
}
int NQ_Net_Transaction_commit(NQ_Transaction transaction){
  int ret;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, transaction);
  REQUEST_LOG(printf("NQ_Net_Transaction_commit()\n");)
  ret = NQ_Request_issue(transaction.home, &output, NQ_REQUEST_TRANSACTION_COMMIT, NULL, NULL);
  // printf("Result = %d\n", ret);
  NQ_RingBuffer_destroy(&output);
  return ret;

}

int NQ_Request_Transaction_commit(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  NQ_Transaction transaction;
  int err;
  NQ_Request_Data *reqdup = NULL;
  
  REQUEST_LOG(printf("NQ_Request_Transaction_commit()\n"););
  
  transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -ERR_UNABLE_TO_UNPICKLE(0); goto nq_req_trans_commit_err; }
  
  // printf("Commit uuid="); NQ_UUID_print(&transaction); printf("\n");
  reqdup = malloc(sizeof(NQ_Request_Data));
  //this will only be used for the header and for the localrequest pointer if applicable
  memcpy(reqdup, req, sizeof(NQ_Request_Data));
  reqdup->data = NULL;

  err = NQ_Local_Transaction_commit(transaction, sock, reqdup);
  if(!err){
    return 0; //no error means that test will eventually call NQ_Request_Transaction_step_finish() above.
  }
  
nq_req_trans_commit_err:
  if(err != 0) {
    printf("%s: err = %d\n", __FUNCTION__, err);
  }
  if(reqdup){
    free(reqdup);
  }
  NQ_Request_respond(sock, NULL, req, err);
  return err;
}

int NQ_Net_Transaction_remote_resp(NQ_Transaction transaction, NQ_Host host, unsigned int op, int err){
  int ret;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, transaction);
  NQ_Request_pickle_host(&output, NQ_Net_get_localhost());
  //This should be safe to issue asynchronously, since the triggering operation's completion
  //message will not be sent until AFTER the asynchronous event is sent. (since there's only one pipe)
  REQUEST_LOG(printf("NQ_Net_Transaction_remote[_resp](host:");NQ_Host_print(host);printf(", op:%x, err:%d)\n", op, err);)
  ret = NQ_Request_issue_async(host, &output, op, err);
  NQ_RingBuffer_destroy(&output);
  return ret;
}
int NQ_Net_Transaction_remote(NQ_Transaction transaction, NQ_Host host, unsigned int op){
  NQ_Net_Transaction_remote_resp(transaction, host, op, 0);
  return 0;
}

int NQ_Request_Transaction_remote(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  NQ_Transaction transaction;
  NQ_Host correspondent;
  int err;
  
  
  transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -30; goto nq_req_trans_remote_err; }
  correspondent = NQ_Request_unpickle_host(&data, &datalen, &err);
  if(err < 0){ err = -40; goto nq_req_trans_remote_err; }
  
  if(NQ_Net_is_local(correspondent)){
    //TRANSACTION_R operations are solely to deal with remote transactions.  Consequently, one of these will never
    //come from the local box.  However, if someone's connected to us in client mode... things'll be different. 
    //If that happens, the code needs some way to refer to the client.  It'll be using our identifier, so let's
    //reassign it to an identifier based on the address/port it's connecting from.
    NQ_Peer *peer = NQ_Socket_userdata(sock);
    if(peer == NULL){
      peer = NQ_Peer_make(sock);
      peer->id.addr = NQ_Socket_peer(sock);
      peer->id.port = NQ_Socket_peerport(sock);
      NQ_Socket_set_userdata(sock, peer);
    }
    correspondent = peer->id;
  }
  
  REQUEST_LOG(printf("NQ_Request_Transaction_remote(");NQ_Host_print(correspondent);printf("<==");NQ_Host_print(((NQ_Peer *)NQ_Socket_userdata(sock))->id);printf(", op:%x, err:%d)\n", req->header.type, req->header.error);)
  
  // these are all asynchronous calls.  responses must come in the form of new messages.
  switch(req->header.type){
    case NQ_REQUEST_TRANSACTION_R_REGISTER:
      err = NQ_Transaction_register_client(transaction, correspondent);
      break;
    default:
      err = -1;
      break;
  }
    
nq_req_trans_remote_err:
  return err;
}

int NQ_Net_Transaction_set_remote_state(NQ_Transaction transaction, NQ_Host host, int state) {
  int err = 0;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, transaction);
  NQ_Request_pickle_int(&output, state);
  int ret = NQ_Request_issue_async(host, &output, 
			       NQ_REQUEST_TRANSACTION_R_REGISTER_SET_STATE, err);
  NQ_RingBuffer_destroy(&output);
  return ret;
}

int NQ_Request_Transaction_set_remote_state(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  NQ_Transaction transaction;
  int state;
  int err;
  
  transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -30; goto nq_req_trans_set_remote_state_err; }
  state = NQ_Request_unpickle_int(&data, &datalen, &err);
  if(err < 0) { err = -40; goto nq_req_trans_set_remote_state_err; }

  err = NQ_Local_Transaction_set_remote_state(transaction, state);
  if(err != 0) {
    goto nq_req_trans_set_remote_state_err;
  }
  return 0;
nq_req_trans_set_remote_state_err:
  if(err != 0) {
    printf("%s: err = %d\n", __FUNCTION__, err);
  }
  return err;
}

#include <nq/remote_trigger.h>

void NQ_Request_pickle_trigger_description(NQ_RingBuffer *output, NQ_Trigger_Description *description){
  if(description->name){
    NQ_Request_pickle_int(output, 1);
    NQ_Request_pickle_attribute_name(output, description->name);
  } else {
    NQ_Request_pickle_int(output, 0);
  }
  NQ_Request_pickle_uuid(output, description->tuple);
  NQ_Request_pickle_int(output, description->type);
  NQ_Request_pickle_int(output, description->upcall_type);
}
NQ_Trigger_Description *NQ_Request_unpickle_trigger_description(unsigned char **data, int *len, int *err, NQ_Socket *sock, NQ_Request_Data *req){
  NQ_Trigger_Description *description = malloc(sizeof(NQ_Trigger_Description));
  int includes_name;
  
  bzero(description, sizeof(NQ_Trigger_Description));
  
  *err = -1;
  includes_name = NQ_Request_unpickle_int(data, len, err);
  CHECK_ERR_AND_RESET(goto unpickle_trigger_description_err);

  if(includes_name){
    description->name = NQ_Request_unpickle_attribute_name(data, len, err, sock, req);
  }
  description->tuple = NQ_Request_unpickle_uuid(data, len, err);
  CHECK_ERR_AND_RESET(goto unpickle_trigger_description_err);
  
  description->type = NQ_Request_unpickle_int(data, len, err);
  CHECK_ERR_AND_RESET(goto unpickle_trigger_description_err);
  
  description->upcall_type = NQ_Request_unpickle_int(data, len, err);
  CHECK_ERR_AND_RESET(goto unpickle_trigger_description_err);

  *err = 0;
unpickle_trigger_description_err:
  if(err < 0){
    if(description->name){
      NQ_Attribute_Name_free(description->name);
    }
    if(description){
      free(description);
    }
    description = NULL;
  }
  return description;
}

void NQ_Batch_Trigger_create(NQ_Transaction transaction, NQ_Principal *actor, NQ_Trigger_Description *description, NQ_Trigger_Callback cb, void *userdata, NQ_Net_Batch *batch){
  NQ_Trigger local_trigger, *state = NULL;
  NQ_Host host;
  int remote = 0;
  
  if( ( 
        (description->name) &&
        (!NQ_Net_is_local(description->name->owner->home))
      ) || (
        (!description->name) &&
        (!NQ_Net_is_local(description->tuple.home))
    ) ){
    remote = 1;
  }
  
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, transaction);
  NQ_Request_pickle_principal_hash(&output, actor);
  NQ_Request_pickle_trigger_description(&output, description);

  if(!remote) {
    printf("local remote trigger not supported!\n");
    assert(0);
  }

  if(remote){
    local_trigger = NQ_Remote_Trigger_start_create(description, cb, userdata);
    state = malloc(sizeof(NQ_Trigger));
    memcpy(state, &local_trigger, sizeof(NQ_Trigger));
    NQ_Request_pickle_uuid(&output, local_trigger);
  } else {
    NQ_Request_pickle_bytes(&output, (unsigned char *)&userdata, sizeof(userdata));
  }
  if(description->name){
    host = description->name->owner->home;
  } else {
    host = description->tuple.home;
  }
  REQUEST_LOG(printf("NQ_Batch_Trigger_create()\n");)
  NQ_Request_issue_batch_stateful(host, &output, NQ_REQUEST_TRIGGER_CREATE, 0, batch, state, NULL, NULL);
  NQ_RingBuffer_destroy(&output);
}

NQ_Trigger NQ_Batch_Trigger_create_finish(NQ_Transaction transaction, NQ_Net_Batch *batch){
  unsigned char *ret_data;
  unsigned int ret_size;
  unsigned int type;
  int ret;
  NQ_Trigger ret_trigger = NQ_uuid_null;
  void *state;
  NQ_Trigger *local_trigger;
  
  ret = NQ_Net_Batch_finish_stateful(batch, &ret_data, &ret_size, &type, &state);
  if((type == (NQ_REQUEST_TRIGGER_CREATE | NQ_REQUEST_RESPONSE))&&(ret_size >= sizeof(NQ_Trigger))){
    memcpy(&ret_trigger, ret_data, sizeof(NQ_Trigger));
  }
  if(state != NULL){
    local_trigger = (NQ_Trigger *)state;
    return NQ_Remote_Trigger_finish_create(transaction, ret_trigger, *local_trigger);
  } else {
    return ret_trigger;
  }
}

NQ_Trigger NQ_Net_Trigger_create(NQ_Transaction transaction, NQ_Principal *actor, NQ_Trigger_Description *description, NQ_Trigger_Callback cb, void *userdata){
  NQ_Trigger local_trigger;
  NQ_Trigger ret_trigger = NQ_uuid_null;
  unsigned char *ret_data;
  unsigned int ret_size;
  NQ_Host host;
  int remote = 0;
  
  if( ( 
        (description->name) &&
        (!NQ_Net_is_local(description->name->owner->home))
      ) || (
        (!description->name) &&
        (!NQ_Net_is_local(description->tuple.home))
    ) ){
    remote = 1;
  }
  
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, transaction);
  NQ_Request_pickle_principal_hash(&output, actor);
  NQ_Request_pickle_trigger_description(&output, description);

  if(!remote) {
    printf("local remote trigger not supported!\n");
    assert(0);
  }

  if(remote){
    local_trigger = NQ_Remote_Trigger_start_create(description, cb, userdata);
    NQ_Request_pickle_uuid(&output, local_trigger);
  } else {
    NQ_Request_pickle_bytes(&output, (unsigned char *)&userdata, sizeof(userdata));
  }
  if(description->name){
    host = description->name->owner->home;
  } else {
    host = description->tuple.home;
  }
  REQUEST_LOG(printf("NQ_Net_Trigger_create()\n");)
  NQ_Request_issue(host, &output, NQ_REQUEST_TRIGGER_CREATE, &ret_data, &ret_size);
  if(ret_size >= sizeof(NQ_Trigger)){
    memcpy(&ret_trigger, ret_data, sizeof(NQ_Trigger));
  }
  NQ_RingBuffer_destroy(&output);
  if(remote){
    return NQ_Remote_Trigger_finish_create(transaction, ret_trigger, local_trigger);
  } else {
    return ret_trigger;
  }
}

int NQ_Request_Trigger_create(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  int err;
  NQ_Transaction transaction;
  NQ_Principal *actor = NULL;
  NQ_Trigger_Description *description = NULL;
  NQ_Trigger cb_id;
  NQ_Trigger local_id = NQ_uuid_null;
  NQ_RingBuffer output;
  int remote = (sock != NULL);
  
  transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -10; goto nq_req_trigger_create_err; }

  actor = NQ_Request_unpickle_principal_hash(&data, &datalen, &err, sock, req);
  if(err < 0){ err = -20; goto nq_req_trigger_create_err; }

  description = NQ_Request_unpickle_trigger_description(&data, &datalen, &err, sock, req);
  if(err < 0){ err = -30; goto nq_req_trigger_create_err; }

  if(remote){
    cb_id = NQ_Request_unpickle_uuid(&data, &datalen, &err);
    if(err < 0){ err = -40; goto nq_req_trigger_create_err; }

    local_id = NQ_Remote_Trigger_register(transaction, actor, description, cb_id);
  } else {
    printf("local triggers not supported\n");
    assert(0);
#if 0
    void *userdata;
    
    NQ_Request_unpickle_bytes(&data, &datalen, &err, sizeof(userdata), (unsigned char *)&userdata);
    if(err < 0){ err = -60; goto nq_req_trigger_create_err; }    
    
    local_id = NQ_Local_Trigger_create(transaction, actor, description, userdata);
#endif
  }

nq_req_trigger_create_err:
  if(actor){
    NQ_Principal_delete(actor);
  }
  if(description){
    if(description->name){
      NQ_Attribute_Name_free(description->name);
    }
    free(description);
  }
  NQ_RingBuffer_init(&output);
  NQ_RingBuffer_write(&output, (unsigned char *)&local_id, sizeof(NQ_Trigger));
  NQ_Request_respond(sock, &output, req, err);
  NQ_RingBuffer_destroy(&output);
  return err;
}

int NQ_Net_Trigger_delete(NQ_Transaction transaction, NQ_Principal *actor, NQ_Trigger trigger_id){
  NQ_Trigger remote_trigger;
  int ret;
  NQ_RingBuffer output;
  
  if(trigger_id.type == NQ_UUID_TRIGGER_REMOTE){
    remote_trigger = NQ_Remote_Trigger_delete(transaction, trigger_id);
  } else {
    remote_trigger = trigger_id;
  }
  
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, transaction);
  NQ_Request_pickle_principal_hash(&output, actor);
  NQ_Request_pickle_uuid(&output, remote_trigger);
  REQUEST_LOG(printf("NQ_Net_Trigger_delete()\n");)
  ret = NQ_Request_issue(remote_trigger.home, &output, NQ_REQUEST_TRIGGER_DELETE, NULL, NULL);
  NQ_RingBuffer_destroy(&output);
  return ret;
}
int NQ_Request_Trigger_delete(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  int err;
  NQ_Transaction transaction;
  NQ_Principal *actor = NULL;
  NQ_Trigger local_id;
  
  transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -10; goto nq_req_trigger_create_err; }
  actor = NQ_Request_unpickle_principal_hash(&data, &datalen, &err, sock, req);
  if(err < 0){ err = -20; goto nq_req_trigger_create_err; }
  local_id = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -30; goto nq_req_trigger_create_err; }

  if(sock){
    NQ_Remote_Trigger_unregister(transaction, actor, local_id);
  } else {
    NQ_Trigger_delete(transaction, actor, local_id);
  }

nq_req_trigger_create_err:
  if(actor){
    NQ_Principal_delete(actor);
  }
  NQ_Request_respond(sock, NULL, req, err);
  return err;
}
int NQ_Request_Trigger_fire(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  int err;
  NQ_Transaction transaction;
  NQ_Trigger_Fire_Info *fire_info = malloc(sizeof(NQ_Trigger_Fire_Info));
    //  NQ_Trigger trigger;

    //int type, request_id, arg;
  //fire_info->sock = sock;
  fire_info->req = malloc(sizeof(NQ_Request_Data));
  memcpy(fire_info->req, req, sizeof(NQ_Request_Data));
  fire_info->req->data = NULL; 

  transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -10; goto nq_req_trigger_fire_err; }
  fire_info->type = NQ_Request_unpickle_int(&data, &datalen, &err);
  if(err < 0){ err = -15; goto nq_req_trigger_fire_err; }
  fire_info->host = NQ_Request_unpickle_host(&data, &datalen, &err);
  if(err < 0){ err = -17; goto nq_req_trigger_fire_err; }
  fire_info->trigger_id = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err < 0){ err = -20; goto nq_req_trigger_fire_err; }
  fire_info->request_id = NQ_Request_unpickle_int(&data, &datalen, &err);
  if(err < 0){ err = -30; goto nq_req_trigger_fire_err; }
  fire_info->arg = NQ_Request_unpickle_int(&data, &datalen, &err);
  if(err < 0){ err = -40; goto nq_req_trigger_fire_err; }

  err = NQ_Remote_Trigger_fire(transaction, fire_info);

nq_req_trigger_fire_err:
  return err;
}

void NQ_Net_GC_touch_uuid(NQ_UUID uuid){
  int ret;
  NQ_RingBuffer output;
  
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, uuid);
  REQUEST_LOG(printf("NQ_Net_GC_touch_uuid()\n");)
  ret = NQ_Request_issue_async(uuid.home, &output, NQ_REQUEST_GCOLLECT_TOUCH_UUID, 0);
  NQ_RingBuffer_destroy(&output);
}

void NQ_Net_GC_touch_attribute_value(NQ_Tuple tuple, NQ_Attribute_Name *name){
  int ret;
  NQ_RingBuffer output;
  
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, tuple);
  NQ_Request_pickle_attribute_name(&output, name);
  REQUEST_LOG(printf("NQ_Net_GC_touch_attribute_value()\n");)
  ret = NQ_Request_issue_async(name->owner->home, &output, NQ_REQUEST_GCOLLECT_TOUCH_ATTRIBUTE, 0);
  NQ_RingBuffer_destroy(&output);
}

int NQ_Request_GC_touch(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  int err;
  NQ_UUID id;
  NQ_Attribute_Name *name;
  
  REQUEST_LOG(printf("NQ_Request_GC_touch()\n");)
  
  switch(req->header.type){
    case NQ_REQUEST_GCOLLECT_TOUCH_UUID:
      id = NQ_Request_unpickle_uuid(&data, &datalen, &err);
      if(err < 0){ err = -20; break; }
      NQ_Local_GC_touch_uuid(id);
      err = 0;
      break;
    case NQ_REQUEST_GCOLLECT_TOUCH_ATTRIBUTE:
      id = NQ_Request_unpickle_uuid(&data, &datalen, &err);
      if(err < 0){ err = -20; break; }
      
      name = NQ_Request_unpickle_attribute_name(&data, &datalen, &err, sock, req);
      if(err < 0){ err = -30; break; }
      
      NQ_Local_GC_touch_attribute_value(id, name);
      err = 0;
      break;
  }
  
  return err;
}

int NQ_Request_Internal_hello(NQ_Socket *sock, NQ_Request_Data *req){
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  int err;
  NQ_Host host;
  NQ_Peer *peer = NQ_Socket_userdata(sock);
  NQ_Peer *otherpeer;
  
  host = NQ_Request_unpickle_host(&data, &datalen, &err);
  
  printf("Connection from: "); NQ_Host_print(host); printf("\n");
  fflush(stdout);
  otherpeer = queue_find(NQ_peers, (PFany)&NQ_Peer_find, &host);
  assert((!otherpeer) || (otherpeer == peer));

  peer->id = host;  
  
  return 0;
}

void NQ_Request_Transaction_invalidate_shadow_state(NQ_Socket *sock, NQ_Request_Data *req) {
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  NQ_Transaction transaction;
  int err;
  transaction = NQ_Request_unpickle_transaction(&data, &datalen, &err);
  if(err < 0) {
    goto out_error;
  }
  err = NQ_Local_Transaction_invalidate_shadow_state(transaction);

 out_error:
  if(err != 0) {
    // printf("NQ_Request_Transaction_invalidate_shadowstate: err = %d\n", err);
  }
  NQ_Request_respond(sock, NULL, req, err);
}

int NQ_Net_Transaction_invalidate_shadow_state(NQ_Transaction transaction) {
  int ret;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, transaction);
  ret = NQ_Request_issue(transaction.home, &output, NQ_REQUEST_TRANSACTION_INVALIDATE_SHADOWSTATE, NULL, NULL);
  NQ_RingBuffer_destroy(&output);
  return ret;
}

int NQ_Net_Enumerate_Tuples(NQ_Host host, NQ_Tuple **out, int *out_count) {
  // enumerate all tuples on the server
  int ret;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  unsigned char *outbuffer = NULL;
  unsigned char *data;
  unsigned int out_length;
  int len;
  ret = NQ_Request_issue(host, &output, NQ_REQUEST_ENUMERATE_TUPLES, &outbuffer, &out_length);
  assert(out_length == 0 || ((out_length - sizeof(int)) % sizeof(NQ_Tuple)) == 0);
  data = outbuffer;
  len = out_length;

  if(ret != 0) {
    goto done;
  }
  *out_count = NQ_Request_unpickle_int(&data, &len, &ret);
  if(ret != 0) {
    printf("err unpickling data\n");
    goto done;
  }
  // printf("Got %d tuples\n", *out_count);
  *out = malloc(*out_count * sizeof(NQ_Tuple));
  int i;
  for(i=0; i < *out_count; i++) {
    (*out)[i] = NQ_Request_unpickle_uuid(&data, &len, &ret);
    if(ret != 0) {
      printf("err unpickling uuid\n");
      free(*out);
      goto done;
    }
  }

 done:
  if(outbuffer != NULL) free(outbuffer);
  NQ_RingBuffer_destroy(&output);
  return ret;
}

int NQ_Request_Enumerate_Tuples(NQ_Socket *sock, NQ_Request_Data *req) {
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  int err = NQ_Local_Enumerate_Tuples(&output);
  NQ_Request_respond(sock, &output, req, err);
  NQ_RingBuffer_destroy(&output);
  return 0;
}

int NQ_Net_Enumerate_Attributes(NQ_Host host, NQ_Tuple tuple, NQ_Attribute_Name ***out, int *out_count) {
  // enumerate all tuples on the server
  int ret;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  unsigned char *outbuffer = NULL;
  unsigned char *data;
  unsigned int out_length;
  int len;

  NQ_Request_pickle_uuid(&output, tuple);
  ret = NQ_Request_issue(host, &output, NQ_REQUEST_ENUMERATE_ATTRIBUTES, &outbuffer, &out_length);

  data = outbuffer;
  len = out_length;

  if(ret != 0) {
    goto done;
  }
  *out_count = NQ_Request_unpickle_int(&data, &len, &ret);
  if(ret != 0) {
    printf("err unpickling data\n");
    goto done;
  }
  // printf("Got %d attributes\n", *out_count);
  *out = malloc(*out_count * sizeof(NQ_Attribute_Name*));
  int i;
  for(i=0; i < *out_count; i++) {
    (*out)[i] = NQ_Request_unpickle_attribute_name(&data, &len, &ret, NULL, NULL);
    if(ret != 0) {
      printf("err unpickling attr name\n");
      // XXX mem leak here
      free(*out);
      goto done;
    }
  }

 done:
  if(outbuffer != NULL) free(outbuffer);
  NQ_RingBuffer_destroy(&output);
  return ret;
}

int NQ_Request_Enumerate_Attributes(NQ_Socket *sock, NQ_Request_Data *req) {
  unsigned char *data = req->data;
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  int err = 0;
  NQ_Tuple tuple = NQ_Request_unpickle_uuid(&data, &datalen, &err);
  if(err != 0) {
    fprintf(stderr, "could not pickle tuple\n");
    return err;
  }

  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  NQ_Local_Enumerate_Attributes(tuple, &output);
  NQ_Request_respond(sock, &output, req, err);
  NQ_RingBuffer_destroy(&output);
  return 0;
}

int NQ_Net_Enumerate_Triggers(NQ_Host host, NQ_Trigger_Desc_and_Dest **out, int *out_count) {
  // Enumerate all triggers not associated with a specific tuple
  int ret;
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  unsigned char *outbuffer = NULL;
  unsigned char *data;
  unsigned int out_length;
  int len;
  ret = NQ_Request_issue(host, &output, NQ_REQUEST_ENUMERATE_TRIGGERS, &outbuffer, &out_length);
  data = outbuffer;
  len = out_length;

  if(ret != 0) {
    goto done;
  }
  *out_count = NQ_Request_unpickle_int(&data, &len, &ret);
  if(ret != 0) {
    printf("err unpickling data\n");
    goto done;
  }
  // printf("Got %d tuples\n", *out_count);
  *out = malloc(*out_count * sizeof(NQ_Trigger_Desc_and_Dest));
  int i;
  for(i=0; i < *out_count; i++) {
    (*out)[i].desc = NQ_Request_unpickle_trigger_description(&data, &len, &ret, NULL, NULL);
    if(ret != 0) {
      printf("err unpickling description\n");
      free(*out);
      goto done;
    }
    (*out)[i].cb_id = NQ_Request_unpickle_uuid(&data, &len, &ret);
    if(ret != 0) {
      printf("err unpickling uuid\n");
      free(*out);
      goto done;
    }
  }

 done:
  if(outbuffer != NULL) free(outbuffer);
  NQ_RingBuffer_destroy(&output);
  return ret;
}

int NQ_Request_Enumerate_Triggers(NQ_Socket *sock, NQ_Request_Data *req) {
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  int err = NQ_Local_Enumerate_Triggers(&output);
  NQ_Request_respond(sock, &output, req, err);
  NQ_RingBuffer_destroy(&output);
  return 0;
}

#if 0
int NQ_Net_Enumerate_Tuple_Triggers(NQ_Host host, NQ_Trigger_Description **out, int *out_count) {
  xxx;
}

int NQ_Request_Enumerate_Tuple_Triggers(NQ_Socket *sock, NQ_Request_Data *req) {
  xxx;
}
#endif
