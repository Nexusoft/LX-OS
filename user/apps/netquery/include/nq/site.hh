#ifndef __NQ_SITE_HH__
#define __NQ_SITE_HH__

#include <nq/net_elements.hh>

struct Router;

struct T_Site : T_Tuple {
  T_Vector< Ref<T_CompositeElement> > hosts;
  T_Vector< Ref<T_CompositeElement> > switches;
  T_Vector< Ref<T_CompositeElement> > routers;

  inline T_Site(Transaction &transaction) :
    T_Tuple(transaction), 
    hosts(this, "T_Site.hosts"),
    switches(this, "T_Site.switches"),
    routers(this, "T_Site.routers")
  { }

  inline T_Site(Transaction &transaction, const NQ_Tuple &tid) : 
    T_Tuple(transaction, tid), 
    hosts(this, "T_Site.hosts"),
    switches(this, "T_Site.switches"),
    routers(this, "T_Site.routers")
  { }

  void tspace_create(void) throw(NQ_Access_Exception);
};

// Composite element constructors
struct Host {
  T_CompositeElement *composite_element;
  T_ProtocolEndpoint *tcp_endpoint;
  T_Interface *nic;
  T_ProcessList *process_list;

  Host(Transaction &transaction);
  Host(Transaction &transaction, NQ_Tuple tid);

  // Local fields
  T_ProtocolEndpoint *get_tcp_stack(void);
  T_Interface *get_nic(void);

  static T_Process *get_process(Transaction *t, ExtRef<T_ProcessList> process_list, int id, bool create = false);

#if 0
  void set_identity(unsigned char *certificate, int cert_len);
  void set_certificate_chain(std::vector<unsigned char *certificate, int cert_len);
#endif
};

NQ_Tuple NQ_get_host_tid(void);

struct Switch {
  T_CompositeElement *composite_element;
  T_SwitchFabric *fabric;
  std::vector<T_Interface*> interfaces;
  T_ProtocolEndpoint *tcp_endpoint;
  T_FirewallTable *firewall_table;

  Switch(Transaction &transaction, int num_interfaces);
  Switch(Transaction &transaction, NQ_Tuple tid);

  T_Interface *add_port(void);
  T_Interface *get_port(int interface_num);

  void add_firewall(void);
};

struct Router {
  T_CompositeElement *composite_element;
  T_SwitchFabric *fabric;
  std::vector<T_Interface*> interfaces;
  T_ProtocolEndpoint *tcp_endpoint;

  Router(Transaction &transaction, int num_interfaces);
  Router(Transaction &transaction, NQ_Tuple tid);

  T_Interface *add_if(void);
  T_Interface *get_if(int interface_num);
  inline size_t get_num_if() {
    return interfaces.size();
  }

  void set_name(const std::string &str);
  
  void add_forwarding_entry(uint32_t ip_prefix, int32_t ip_prefix_len, int if_num);
  void clear_forwarding_entries(void);

  void print(std::ostream &os);
};

void add_forwarding_entry(T_SwitchFabric *fabric, uint32_t ip_prefix, int32_t ip_prefix_len, T_Interface *interface);
void del_forwarding_entry(T_SwitchFabric *fabric, uint32_t ip_prefix, int32_t ip_prefix_len);

void NQ_export_host_tid(Host *h);
NQ_Tuple NQ_get_host_tid(void);
#endif // __NQ_SITE_HH__
