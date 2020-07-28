#include <nq/exceptions.hh>
#include <typeinfo>

std::ostream &operator<<(std::ostream &os, const NQ_Exception &e) {
  os << "<" << typeid(e).name() << " \"" << e.msg << "\" >";
  return os;
}

