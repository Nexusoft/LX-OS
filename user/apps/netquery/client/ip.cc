#include <iomanip>
#include <nq/ip.hh>

namespace NQ_DefaultValues {
  struct EndpointIdentifier null_endpoint;
}

bool LayerIdentifier::operator==(const LayerIdentifier &r) const {
  if(type != r.type) {
    return false;
  }
  switch(this->type) {
  case LAYER_IDENTIFIER_IP:
    return data.ip.ip_address == r.data.ip.ip_address;
  case LAYER_IDENTIFIER_TCP:
    return data.tcp.port_num == r.data.tcp.port_num;
  default:
    assert(0);
    return false;
  }
}

bool EndpointIdentifier::operator==(const EndpointIdentifier &r) const {
  if(layers.size() != r.layers.size()) {
    return false;
  }
  size_t i;
  for(i=0; i < layers.size(); i++) {
    if(layers[i] != r.layers[i]) {
      return false;
    }
  }
  return true;
}
bool EndpointIdentifier::operator!=(const EndpointIdentifier &r) const {
  return !(*this == r);
}

EndpointIdentifier *
EndpointIdentifier::tspace_unmarshall(Transaction &transaction, std::vector<unsigned char>::const_iterator &curr, 
		  const std::vector<unsigned char>::const_iterator &end)
  throw(NQ_Schema_Exception)
{
  EndpointIdentifier *rv = new EndpointIdentifier();
  rv->layers = *::tspace_unmarshall(&rv->layers, transaction, curr, end);
  return rv;
}

void EndpointIdentifier::tspace_marshall(const EndpointIdentifier &val, 
		     std::vector<unsigned char> &buf) {
  ::tspace_marshall(val.layers, buf);
}

std::ostream &operator<<(std::ostream &os, const LayerIdentifier &id) {
  switch((enum LayerIdentifierType)id.type) {
  case LAYER_IDENTIFIER_IP:
    os << "IP: " << std::setbase(16) << id.data.ip.ip_address << std::setbase(10);
    break;
  case LAYER_IDENTIFIER_TCP:
    os << "TCP: " << id.data.tcp.port_num;
    break;
  case LAYER_IDENTIFIER_ETH:
    os << "ETH: " << MAC_Address(id.data.mac.mac_address);
    break;
  }
  return os;
}

std::ostream &operator<<(std::ostream &os, const EndpointIdentifier &id) {
  size_t i;
  os << " <EndpointIdentifier " << id.layers.size() << " ";
  for(i=0; i < id.layers.size(); i++) {
    os << "[" << i << "]: " << id.layers[i] << "\n";
  }
  os << " >\n";
  return os;
}
