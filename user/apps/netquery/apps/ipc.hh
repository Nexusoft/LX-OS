#ifndef _IPC_HH_
#define _IPC_HH_

#include <map>
#include <set>
#include <vector>

#include "eventxx"
#include "ssl.hh"

struct IPC_ServerInstance;
struct IPC_Server;

struct IPC_ServiceDesc {
  struct CommandDesc {
    int m_command_num;
    CommandDesc(int command_num);
    virtual ~CommandDesc();

    // unmarshall_and_do() uses peek_command() to decode the
    // command. If full command is received, it advances the command buffer.
    virtual void unmarshall_and_do(IPC_ServerInstance *instance, int data_offset) const = 0;
  };
  typedef std::map<int, CommandDesc *> IPC_Command_Map;

  IPC_Command_Map m_command_map;

  void add_command(CommandDesc *new_desc);
  const CommandDesc *find_command(int command_num) const;
};

struct CommandHeader {
  int type;
  int len;
} __attribute__((packed));

struct ResponseHeader {
  int len;
};

struct IPC_ServerInstance {
  typedef struct eventxx::mem_cb<IPC_ServerInstance, void (IPC_ServerInstance::*)(int, eventxx::type)> EventCallback;

  enum State {
    WAITING_FOR_COMMAND,
    // THINKING,
    SENDING_RESPONSE, // write poll handler only active here
  };

  State m_state;
  IPC_Server *m_server;
  SSL_ServerConnection *m_conn;

  DataBuffer m_command_buf;
  DataBuffer m_response_buf;

  EventCallback m_command_callback;
  EventCallback m_response_callback;
  eventxx::event<EventCallback> m_command_event;

  IPC_ServerInstance(IPC_Server *server, SSL_ServerConnection *conn);
  ~IPC_ServerInstance();

  int peek_command(void *data, int maxlen);
  int peek_command(void *data, int offset, int maxlen);
  void advance_command_buf(int len);
  void finish_command(int command_len); // len excludes the common header

  void send_response(const DataBuffer &response);

private:
  void try_process_next_command();
  void more_command_data_handler(int fd, eventxx::type t);
  void more_command_data();

  void continue_response_handler(int fd, eventxx::type t);
  void continue_response();
  void finish_response();
  void set_state(State new_state);
};

struct IPC_Server : SSL_Listener {
  const IPC_ServiceDesc *m_service_desc;

  typedef std::set<IPC_ServerInstance *> InstanceSet;
  InstanceSet m_all_instances; // modified by constructor / destructor of IPC_ServerInstance

  IPC_Server(const IPC_ServiceDesc *service_desc, int fd, eventxx::dispatcher *dispatcher);
  // from SSL_Listener
  virtual void accepted_connection(SSL_ServerConnection *new_conn);
};

struct IPC_Client : SSL_ClientConnection {
  const IPC_ServiceDesc *m_service_desc;

  IPC_Client(const IPC_ServiceDesc *service_desc, eventxx::dispatcher *dispatcher, int fd, const struct sockaddr_in &addr);

  void send(int type, const DataBuffer &command_packet, DataBuffer *response);
};

#endif // _IPC_HH_
