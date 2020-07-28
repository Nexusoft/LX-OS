#include <nq/netquery.h>
#include <nq/marshall.hh>
#include <nq/tuple.hh>
#include <iostream>
#include <ext/hash_map>
#include <ext/hash_set>

using namespace __gnu_cxx;
using namespace std;

static bool trust_all(NQ_Tuple tid, KnownClass *obj_class) {
  // trust everything
  return true;
}
static bool trust_attrval_all(NQ_Attribute_Name *name, NQ_Tuple tid, NQ_Principal *principal) {
	  return true;
}


namespace NQ_Output {
  string OutputContext::tid_to_alias(NQ_Tuple tid) {
    size_t k;
    for(k=0; k < tuple_aliases.size(); k++) {
      if(tid == tuple_aliases[k].tuple) {
	return tuple_aliases[k].name;
      }
    }
    return default_alias;
  }

  bool check_printable(char *str) {
    unsigned int i;
    for(i=0; i < strlen(str); i++) {
      if( !(isprint(str[i])||isspace(str[i])) ) {
	return false;
      }
    }
    return true;
  }

  void output_name(ostream &os, const NQ_Attribute_Name &name,
		   bool show_speaker, bool show_type) {
    os << name.name;
    if(show_speaker || show_type) {
      os << " [";
      if(show_speaker) {
	os << " owner: " << *name.owner;
      }
      if(show_type) {
	os << " type: " << name.type;
      }
      os << " ]";
    }
  }

  template<class T> void output_join(ostream &os, vector<T> v) {
    for(typename vector<T>::iterator i = v.begin(); i != v.end(); i++) {
      os << *i;
      if(i + 1 != v.end()) {
	os << ", ";
      }
    }
  }

  void OutputContext::output_trigger(ostream &os, const NQ_Trigger_Desc_and_Dest &desc, bool show_tuple_name, bool show_attr_name) {
    os << "<";
    if(show_tuple_name) {
      string tid_str;
      if(desc.desc->tuple == NQ_uuid_null) {
	tid_str = "*";
      } else {
	tid_str = tid_to_alias(desc.desc->tuple);
      }
      assert(tid_str != "");
      os << tid_str;
      os << ", ";
    }
    if(show_attr_name) {
      if(desc.desc->name != NULL) {
	output_name(os, *desc.desc->name, false, false);
      } else {
	os << "*";
      }
      os << ", ";
    }

    os << "[";
    vector<string> types;
    if(desc.desc->upcall_type & NQ_TRIGGER_UPCALL_SYNC_VETO) {
      types.push_back(string("ask-veto"));
    }
    if(desc.desc->upcall_type & NQ_TRIGGER_UPCALL_SYNC_VERDICT) {
      types.push_back(string("ask-delay"));
    }
    if(desc.desc->upcall_type & NQ_TRIGGER_UPCALL_ASYNC_VERDICT) {
      types.push_back(string("fyi"));
    }
    if(desc.desc->upcall_type & NQ_TRIGGER_UPCALL_ASYNC_COMMIT_DONE) {
      types.push_back(string("commit"));
    }
    assert(types.size() > 0);
    output_join(os, types);
    os << "]";

    os << ", => "  << desc.cb_id.home << ">";
  }

  void OutputContext::output_tuple(std::ostream &os, NQ_Transaction transaction, NQ_Tuple tuple) {
    vector<NQ_Attribute_Name *> attrs;
    int j;
    int err = 0;

    os << "{\n";
    switch(parse_type) {
    case ENUMERATE_ATTRIBUTES: {
      NQ_Attribute_Name **_attrs;
      int attr_count;
      err = NQ_Enumerate_Attributes(home, tuple, &_attrs, &attr_count);
      for(int i=0; i < attr_count; i++) {
	attrs.push_back(NQ_Attribute_Name_dup(_attrs[i]));
      }
      assert(attrs.size() == (size_t)attr_count);
      free(_attrs);
      break;
    }
    case REFLECTION: {
      cerr << "Not implemented\n";
      assert(0);
      Transaction txn(transaction, trust_all, trust_attrval_all, home);
      T_Tuple *obj;
      txn.find_tuple(obj, tuple);
      T_Tuple::AttributeMap::iterator i;
      for( i = obj->attribute_map.begin(); i != obj->attribute_map.end(); i++ ) {
	attrs.push_back(NQ_Attribute_Name_dup(i->second->name));
      }
      break;
    }
    }
    if(err != 0) {
      cerr << "\tError enumerating attributes!\n";
      os << "}\n";
      return;
    }
    for(j=0; j < (int)attrs.size(); j++) {
      NQ_Attribute_Name *name = attrs[j];
      os << "\t";
      output_name(os, *name, show_speaker, show_type);

      switch(attrs[j]->type) {
      case NQ_ATTRIBUTE_RAW: {
	os << " = ";
	char *data = NULL;
	int len = 0;
	NQ_Principal *attributed_to = NULL;
	err = NQ_Attribute_operate(transaction, &NQ_default_owner, 
				   attrs[j], tuple, 
				   NQ_OPERATION_READ, &data, &len,
				   &attributed_to);
	if(err != 0) {
	  os << "<READ ERR>";
	} else {
	  if(show_speaker) {
	    os << *attributed_to << " says ";
	  }
	  char *str = data + sizeof(int);
	  if( (unsigned)len > sizeof(int) && 
	      ({
		unsigned slen = *(unsigned *)data;
		(slen <= (unsigned) len) && (str[slen - 1] == '\0') && 
		  (strlen(str) == (slen - 1)) && check_printable(str);
	      }) ) {
	    os <<  '"' << str << '"';
	  } else {
	    if(len == 30) {
	      // assume that it is a tid
	      NQ_Tuple tid;
	      DataBuffer d((unsigned char *)data, len);
	      CharVector_Iterator begin = d.begin();
	      tid = *tspace_unmarshall(&tid, *(Transaction*)0, begin, d.end());
	      if(tid == NQ_uuid_null) {
		os << "(null)";
	      } else {
		string tid_str = tid_to_alias(tid);
		os << tid_str;
	      }
	    } else {
	      os << "<BIN DATA>[" << len << "]";
	    }
	  }
	}
	break;
      }
      default:
	//os << "<cannot display type>";
	break;
      }
      if(show_triggers) {
	NQ_Trigger_Description_Set tuple_triggers = 
	  all_tuple_triggers[tuple].match(name);
	{
	  NQ_Trigger_Description_Set wildcard = 
	    all_tuple_triggers[NQ_uuid_null].match(name);
	  tuple_triggers.insert(wildcard.begin(), wildcard.end());
	}

	if(tuple_triggers.size() > 0) {
	  os << "\t|| Triggers: ";
	  for(NQ_Trigger_Description_Set::iterator i = tuple_triggers.begin();
	      i != tuple_triggers.end(); i++) {
	    const NQ_Trigger_Desc_and_Dest *d = &*i;
	    if ((*d).desc->tuple == NQ_uuid_null) {
	      // wildcard match
	      output_trigger(os, *d, true, false);
	    } else {
	      output_trigger(os, *d, false, false);
	    }

	    NQ_Trigger_Description_Set::iterator next = i;
	    next++;
	    if(next != tuple_triggers.end()) {
	      os << ", ";
	    }
	  }
	}
      }
      os << "\n";
    }
    os << "}\n";
  }

  void OutputContext::add_tid_alias(const NQ_Tuple &tid, const string &name) {
    for(size_t i=0; i < tuple_aliases.size(); i++) {
      if(tuple_aliases[i].tuple == tid) {
	if(tuple_aliases[i].name != name) {
	cerr << "add_tid_alias: tuple already there\n";
	cerr << "... and name mismatches\n";
	return;
	}
      }
    }
    tuple_aliases.push_back(TupleAlias(tid, name));
    // cerr << "Add alias "  << tid << " => " << name << "\n";
  }
}
