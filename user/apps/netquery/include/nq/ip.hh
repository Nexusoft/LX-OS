#ifndef _NQ_IP_H_
#define _NQ_IP_H_

#include <vector>
#include <nq/exceptions.hh>
#include <nq/marshall.hh>
#include <nq/attribute.hh>

struct MAC_Address;

std::ostream &operator<<(std::ostream &os, const MAC_Address &v);

struct MAC_Address {
#define ETH_ADDR_LEN (6)
  unsigned char m_addr[ETH_ADDR_LEN];
  MAC_Address() {
    memset(m_addr, 0, ETH_ADDR_LEN);
  }
  MAC_Address(const unsigned char *addr) {
    memcpy(m_addr, addr, ETH_ADDR_LEN);
  }
  bool operator<(const MAC_Address &a) const {
    return memcmp(m_addr, a.m_addr, ETH_ADDR_LEN) < 0;
  }
  bool operator==(const MAC_Address &a) const {
    return memcmp(m_addr, a.m_addr, ETH_ADDR_LEN) == 0;
  }
  bool operator==(const unsigned char *addr) const {
    return *this == MAC_Address(addr);
  }
  template<class T> bool operator!=(const T &addr) const {
    return !(*this == addr);
  }
  bool is_broadcast(void) const {
    const char broadcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    return memcmp(m_addr, broadcast, ETH_ADDR_LEN) == 0;
  }
  bool is_valid(void) const {
    const char invalid[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    return memcmp(m_addr, invalid, ETH_ADDR_LEN) != 0;
  }
  void set_buf(unsigned char *dest) const {
    memcpy(dest, m_addr, ETH_ADDR_LEN);
  }

  void print(void) {
    std::cout << *this;
  }
#undef ETH_ADDR_LEN

  static inline 
  MAC_Address *tspace_unmarshall(Transaction &transaction, CharVector_Iterator &curr, 
				 const CharVector_Iterator &end) 
    throw(NQ_Schema_Exception)
  {
    return unmarshall_flat_object<MAC_Address>(curr, end);
  }

  static inline void tspace_marshall(const MAC_Address &val, std::vector<unsigned char> &buf) {
    ::marshall_flat_object(val, buf);
  }

  static inline int tspace_marshall_size(void) {
    return sizeof(MAC_Address);
  }
};

struct MAC_Address_Hash {
   size_t operator()(const MAC_Address &f) const {
    return (size_t)SuperFastHash((char*)&f, sizeof(f));
  }
};

struct EndpointIdentifier;
enum LayerIdentifierType {
  LAYER_IDENTIFIER_ETH, LAYER_IDENTIFIER_IP, LAYER_IDENTIFIER_TCP,
};

struct LayerIdentifier {
  uint32_t type; // enum LayerIdentifierType
  union LayerData {
    struct {
      unsigned char mac_address[6];
    } mac;
    struct {
      uint32_t ip_address;
    } ip;
    struct {
      uint16_t port_num;
    } tcp;
  } data;

  bool operator==(const LayerIdentifier &r) const;
  inline bool operator!=(const LayerIdentifier &r) const {
    return !(*this == r);
  }

  static inline LayerIdentifier *
  tspace_unmarshall(Transaction &transaction, std::vector<unsigned char>::const_iterator &curr, 
		    const std::vector<unsigned char>::const_iterator &end)
    throw(NQ_Schema_Exception) {
    return unmarshall_flat_object<LayerIdentifier>(curr, end);
  }

  static inline void tspace_marshall(const LayerIdentifier &val, 
				     std::vector<unsigned char> &buf) {
    marshall_flat_object<LayerIdentifier>(val, buf);
  }
};

std::ostream &operator<<(std::ostream &os, const LayerIdentifier &id);

static inline LayerIdentifier IPLayer(uint32_t ip_address) {
  LayerIdentifier rv;
  rv.type = LAYER_IDENTIFIER_IP;
  rv.data.ip.ip_address = ip_address;
  return rv;
}

static inline LayerIdentifier TCPLayer(uint16_t port_num) {
  LayerIdentifier rv;
  rv.type = LAYER_IDENTIFIER_TCP;
  rv.data.tcp.port_num = port_num;
  return rv;
}

static inline LayerIdentifier EthLayer(const MAC_Address &addr) {
  LayerIdentifier rv;
  rv.type = LAYER_IDENTIFIER_ETH;
  memcpy(rv.data.mac.mac_address, addr.m_addr, sizeof(addr.m_addr));
  return rv;
}

struct EndpointIdentifier {
// Layers are ordered by containment. E.g., TCP is contained within
// IP, so TCP comes after IP in the vector.
  std::vector<LayerIdentifier> layers;

  bool operator==(const EndpointIdentifier &r) const;
  bool operator!=(const EndpointIdentifier &r) const;

  static EndpointIdentifier *
  tspace_unmarshall(Transaction &transaction, std::vector<unsigned char>::const_iterator &curr, 
		    const std::vector<unsigned char>::const_iterator &end)
    throw(NQ_Schema_Exception);

  static void tspace_marshall(const EndpointIdentifier &val, 
			      std::vector<unsigned char> &buf);
};

std::ostream &operator<<(std::ostream &os, const EndpointIdentifier &id);

namespace NQ_DefaultValues {
  extern struct EndpointIdentifier null_endpoint;
}

typedef T_Scalar<EndpointIdentifier, NQ_DefaultValues::null_endpoint > T_EndpointIdentifier;

//// Helper functions

static inline
EndpointIdentifier IP_TCP(uint32_t ip_address, uint16_t port_num) {
  EndpointIdentifier rv;
  rv.layers.push_back(IPLayer(ip_address));
  rv.layers.push_back(TCPLayer(port_num));
  return rv;
}

#endif // _NQ_IP_H_
