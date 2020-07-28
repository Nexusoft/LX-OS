#ifndef _BOOST_UTIL_HH_
#define _BOOST_UTIL_HH_

#include <boost/iostreams/device/mapped_file.hpp>
#include <boost/regex.hpp>
#include <nq/boost_util.hh>
#include <string>

template <class F> 
static inline void forlines(const std::string &fname, F &f) {
  static std::string _line("^.+?$");
  static const boost::regex line_pattern(_line);

  try {
    boost::iostreams::mapped_file_source mf(fname);
    boost::cregex_iterator lines(mf.begin(), mf.end(), line_pattern);
    boost::cregex_iterator end;

    for( ; lines != end; lines++) {
      bool keep_going = f(std::string((*lines)[0]));
      if(!keep_going) break;
    }
  } catch(std::ios_base::failure f) {
    std::cerr << "Caught " << f.what() << "\n";
  }  
}

#endif // _BOOST_UTIL_HH_
