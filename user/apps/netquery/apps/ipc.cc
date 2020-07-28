#include <nq/util.hh>
#include <iostream>
#include "ipc.hh"
#include <errno.h>

using namespace std;

IPC_ServiceDesc::CommandDesc::CommandDesc(int command_num) : 
  m_command_num(command_num) {
  // nothing
}

IPC_ServiceDesc::CommandDesc::~CommandDesc() {
  // nothing
}

void IPC_ServiceDesc::add_command(CommandDesc *new_desc) {
  m_command_map[new_desc->m_command_num] = new_desc;
}

const IPC_ServiceDesc::CommandDesc *IPC_ServiceDesc::find_command(int command_num) const {
  IPC_Command_Map::const_iterator it = m_command_map.find(command_num);
  if(it == m_command_map.end()) {
    cerr << "could not find command " << command_num << "\n";
    return NULL;
  } else {
    return it->second;
  }
}

//////////// IPC_ServerInstance
IPC_ServerInstance::IPC_ServerInstance(IPC_Server *server, SSL_ServerConnection *conn) :
  m_state(WAITING_FOR_COMMAND), m_server(server), m_conn(conn), 
  m_command_callback(*this, &IPC_ServerInstance::more_command_data_handler),
  m_response_callback(*this, &IPC_ServerInstance::continue_response_handler),
  m_command_event(conn->m_fd, eventxx::READ, m_command_callback) {
  server->m_all_instances.insert(this);

  // start read poll event;
  server->m_dispatcher->add(m_command_event);
}

int IPC_ServerInstance::peek_command(void *data, int offset, int maxlen) {
  int real_len = MIN( (size_t) maxlen, m_command_buf.size() - offset );
  memcpy(data, vector_as_ptr(m_command_buf) + offset, real_len);
  return real_len;
}

int IPC_ServerInstance::peek_command(void *data, int maxlen) {
  return peek_command(data, 0, maxlen);
}

void IPC_ServerInstance::advance_command_buf(int len) {
  assert( (size_t) len <= m_command_buf.size());
  m_command_buf.erase(m_command_buf.begin(), m_command_buf.begin() + len);
}

void IPC_ServerInstance::finish_command(int command_len) {
  advance_command_buf(sizeof(CommandHeader) + command_len);
}

void IPC_ServerInstance::send_response(const DataBuffer &response) {
  assert(m_state == WAITING_FOR_COMMAND);
  assert(m_response_buf.size() == 0);

  m_response_buf = response;
  
  set_state(SENDING_RESPONSE);
  continue_response();
}

#define READ_CHUNK_SIZE (512)

void IPC_ServerInstance::more_command_data_handler(int fd, eventxx::type t) {
  assert(fd == m_conn->m_fd);
  more_command_data();
  m_server->m_dispatcher->add(m_command_event);
}

void IPC_ServerInstance::more_command_data() {
  while(1) {
    unsigned char buf[READ_CHUNK_SIZE];
    int len = m_conn->read(buf, READ_CHUNK_SIZE);
    if(len <= 0) {
      break;
    }
    int i;
    for(i=0; i < len; i++) {
      m_command_buf.push_back(buf[i]);
    }
  }
  try_process_next_command();
}

void IPC_ServerInstance::try_process_next_command() {
  CommandHeader header;
  if( peek_command(&header, sizeof(header)) != sizeof(header) ) {
    // not enough data for length
    return;
  }
  const IPC_ServiceDesc::CommandDesc *h = m_server->m_service_desc->find_command(header.type);
  assert(h != NULL);
  h->unmarshall_and_do(this, sizeof(header));
}

void IPC_ServerInstance::continue_response_handler(int fd, eventxx::type t) {
  assert(fd == m_conn->m_fd);
  continue_response();
}

void IPC_ServerInstance::continue_response() {
  assert(m_state == SENDING_RESPONSE);

  DataBuffer full_response;
  ResponseHeader hdr;
  hdr.len = m_response_buf.size();

  vector_push( full_response, hdr );
  vector_push( full_response, vector_as_ptr(m_response_buf), m_response_buf.size() );

  int curr_len = full_response.size();
  int err = m_conn->write( vector_as_ptr(full_response), curr_len );
  if(err == 0) {
    THROW("ssl error");
  } else if(err < 0) {
    // Schedule more work for later
    err = m_conn->get_error();
    register_ssl_once(static_cast<SSL_Connection*>(m_conn), err, m_response_callback);
    // Since we don't use partial write mode, we don't manipulate
    // m_response_pos. We always write the full contents of the buffer.
    return;
  }
  // we don't use partial write mode
  assert(err == curr_len);
  finish_response();
}

void IPC_ServerInstance::finish_response() {
  m_response_buf.clear();
  set_state(WAITING_FOR_COMMAND);
}

void IPC_ServerInstance::set_state(State new_state) {
  State old_state = m_state;
  m_state = new_state;

  switch(old_state) {
  case WAITING_FOR_COMMAND:
    switch(new_state) {
    case SENDING_RESPONSE:
      // do nothing
      break;
    default:
      goto bad_state;
    }
    break;
  case SENDING_RESPONSE:
    switch(new_state) {
    case WAITING_FOR_COMMAND:
      // do nothing
      break;
    default:
      goto bad_state;
    }
    break;

  default:
  bad_state:
    THROW("Bad state transition");
  }
}

IPC_ServerInstance::~IPC_ServerInstance() {
  m_server->m_all_instances.erase(this);
  cerr << "Error: Does not yet remove poll entries from dispatcher\n";
  assert(0);
}

//////////// IPC_Server

IPC_Server::IPC_Server(const IPC_ServiceDesc *service_desc, int fd, eventxx::dispatcher *dispatcher) : 
  SSL_Listener(fd, dispatcher),
  m_service_desc(service_desc) {
  // nothing
}

void IPC_Server::accepted_connection(SSL_ServerConnection *new_conn) {
  std::cerr << "Accepted new connection\n";
  IPC_ServerInstance *instance;
  instance = new IPC_ServerInstance (this, new_conn);
  // processing done completely by allocation
}

//////////// IPC_Client

IPC_Client::IPC_Client(const IPC_ServiceDesc *service_desc, eventxx::dispatcher *dispatcher, int fd, const struct sockaddr_in &addr) :
  SSL_ClientConnection(dispatcher, fd, addr, true),
  m_service_desc(service_desc)
{
}

static void check_block(SSL_Connection *conn, int err) {
  if(err <= 0) {
    int ssl_err = conn->get_error();
    if(ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
      cerr << "would have blocked ; non-blocking not implemented!\n";
    }
    cerr << "SSL error " << ssl_err << " !\n";
    assert(0);
  }
}

static void read_all(SSL_Connection *conn, DataBuffer *response, int len) {
  int loc = 0;
  int remainder = len;
  do {
     int err = conn->read(response, remainder);
    check_block(conn, err);
    assert(err > 0);
    loc += err;
    remainder = len - loc;
  } while(remainder > 0);
}

void IPC_Client::send(int type, const DataBuffer &command_packet, DataBuffer *response) {
  CommandHeader header;
  int cmd_len = command_packet.size();
  header.type = type;
  header.len = cmd_len;
  // nonblocking mode not currently supported
  int err;
  err = write(&header, sizeof(header));
  check_block(this, err);
  if(cmd_len > 0) {
    err = write(vector_as_ptr(command_packet), cmd_len);
    check_block(this, err);
  }

  ResponseHeader resp_header;
  DataBuffer header_buf;
  read_all(this, &header_buf, sizeof(resp_header));
  assert(header_buf.size() == sizeof(resp_header));
  memcpy(&resp_header, vector_as_ptr(header_buf), sizeof(resp_header));
  read_all(this, response, resp_header.len);
}
