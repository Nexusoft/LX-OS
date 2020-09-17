// main.cc            see license.txt for copyright and terms of use
// entry-point module for a program that parses C++

#include <iostream.h>     // cout, cerr
#include <stdlib.h>       // exit, getenv, abort, realpath
#include <fstream.h>      // ofstream
#include <libgen.h>      // dirname
#include <assert.h>
#include <vector>

#include "trace.h"        // traceAddSys
#include "parssppt.h"     // ParseTreeAndTokens, treeMain
#include "srcloc.h"       // SourceLocManager
#include "ckheap.h"       // malloc_stats
#include "cc_env.h"       // Env
#include "cc_ast.h"       // C++ AST (r)
#include "cc_ast_aux.h"   // class LoweredASTVisitor
#include "cc_lang.h"      // CCLang
#include "parsetables.h"  // ParseTables
#include "cc_print.h"     // PrintEnv
#include "cc.gr.gen.h"    // CCParse
#include "nonport.h"      // getMilliseconds
#include "ptreenode.h"    // PTreeNode
#include "ptreeact.h"     // ParseTreeLexer, ParseTreeActions
#include "sprint.h"       // structurePrint
#include "strtokp.h"      // StrtokParse
#include "smregexp.h"     // regexpMatch
#include "cc_elaborate.h" // ElabVisitor
#include "integrity.h"    // IntegrityVisitor
#if XML
  #include "main_astxmlparse.h"// astxmlparse
  #include "cc_type_xml.h"  // TypeToXml
#endif // XML

// For chmod
#include <sys/types.h>
#include <sys/stat.h>

#include "strutil.h"

#define NEXUS_WORD_SIZE (4)
//#define MAX_TRANSFERDESCS (4)
#define MAX_TRANSFERDESCS (16)

// These must match the corresponding definitions in idl.h!!!
#define RESULT_DESCNUM (0)
#define FIRST_ARG_DESCNUM (RESULT_DESCNUM+1)

#define OUTPUT_SERVER (0x1)
#define OUTPUT_CLIENT (0x2)

const bool registerName = false;

char *outputDir = NULL;
char *outputDirPrefix = NULL;

#include "cc_flags.h"

const char *clientInitializedVar = "__clientInitializedVar";

static void wrapFunction(ostream &c_os, ostream &h_os, 
			 const string &return_type, const string &default_rv, 
			 const string &func_name, const string &body, const string &post_body) {
  string proto = return_type & " " & func_name & rostring("(void)");
  string name0 = func_name & "0";
  bool do_rv = (return_type != rostring("void"));
  h_os << proto << ";\n";
  c_os << "static " << return_type << " " << name0 << "(void) {\n";
  c_os << body << ";\n";
  if(do_rv) {
    c_os << "	return " << default_rv << ";\n";
  }
  c_os << "}\n\n";
  c_os << proto << " {\n";
  string rval = "";
  if(do_rv) {
    c_os << return_type << " rv;\n";
    rval = "rv = ";
  }
  c_os << "	" << rval << name0 << "();\n";
  c_os << "	" << post_body;
  if(do_rv) {
    c_os << "	" << "return rv;\n";
  }
  c_os << "}\n\n";
}

bool param_isPointer(const ASTTypeId &param);
bool isVoid(TypeSpecifier *ts) {
  if(ts->isTS_simple()) {
    TS_simple *tss = ts->asTS_simple();
    return tss->id == ST_VOID;
  }
  return false;
}

int paramList_count(FakeList<ASTTypeId> *list) {
  int count = 0;
  FAKELIST_FOREACH_NC(ASTTypeId, list, item) {
    count++;
  }
  return count;
}

FakeList<ASTTypeId> *ParamList_normalize(FakeList<ASTTypeId> *list) {
  FAKELIST_FOREACH_NC(ASTTypeId, list, item) {
    if(!param_isPointer(*item) && isVoid(item->spec)) {
      //cerr << "Normalizing to void\n";
      return NULL;
    }
  }
  return list;
}

bool gen_kernel(void) {
  return tracingSys("target_kernel");
}

// don't know why I need this
//  class TypeToXml;

// get rid of ".." in paths
string get_realpath(const string &fname) {
	int i, j;
	char *s = strdup(fname.c_str());
	int n = fname.length();
	while (n >= 6) {
		// look for "blahblah/../" and splice it out
		j = (s[0] == '/' ? 1 : 0);
		for (i = 1; i < n-4; i++) {
			if (!strncmp(&s[i], "/../", 4)) {
				strcpy(&s[j], &s[i+4]);
				n = strlen(s);
			}
			else if (s[i] == '/') j = i+1;
		}
		if (i == n-4) break;
	}
	return string(s);
}

string getDirname(const string &fname) {
  int i;
  int found = 0;
  for(i=fname.length()-1; i >= 0; i--) {
    if(fname[i] == '/') {
      found = 1;
      break;
    }
  }
  if(found) {
    return fname.substring(0, i + 1);
  } else {
    // same directory
    return string("");
  }
}

// little check: is it true that only global declarators
// ever have Declarator::type != Declarator::var->type?
// .. no, because it's true for class members too ..
// .. it's also true of arrays declared [] but then inited ..
// .. finally, it's true of parameters whose types get
//    normalized as per cppstd 8.3.5 para 3; I didn't include
//    that case below because there's no easy way to test for it ..
// Intended to be used with LoweredASTVisitor
class DeclTypeChecker : private ASTVisitor {
public:
  LoweredASTVisitor loweredVisitor; // use this as the argument for traverse()

  int instances;

public:
  DeclTypeChecker()
    : loweredVisitor(this)
    , instances(0)
  {}
  virtual ~DeclTypeChecker() {}

  virtual bool visitDeclarator(Declarator *obj);
};

bool DeclTypeChecker::visitDeclarator(Declarator *obj)
{
  if (obj->type != obj->var->type &&
      !(obj->var->flags & (DF_GLOBAL | DF_MEMBER)) &&
      !obj->type->isArrayType()) {
    instances++;
    cerr << toString(obj->var->loc) << ": " << obj->var->name
         << " has type != var->type, but is not global or member or array\n";
  }
  return true;
}

class NameChecker : public ASTVisitor {
public:
  // accumulates the results
  stringBuilder sb;
public:
  NameChecker(){ }

  virtual bool visitExpression(Expression *obj)
  {
    Variable *v = NULL;
    if (obj->isE_variable()) {
      v = obj->asE_variable()->var;
    }
    else if (obj->isE_fieldAcc()) {
      v = obj->asE_fieldAcc()->field;
    }
    
    // this output format is designed to minimize the effect of
    // changes to unrelated details
    if (v
        && !streq("__testOverload", v->name)
        && !streq("dummy",          v->name)
        && !streq("__other",        v->name) // "__other": for inserted elaboration code
        && !streq("this",           v->name) // dsw: not sure why "this" is showing up
        && !streq("operator=",      v->name) // an implicitly defined member of every class
        && v->name[0]!='~'                   // don't print dtors
        ) {
      sb << " " << v->name << "=" << sourceLocManager->getLine(v->loc);
    }

    return true;
  }
};

class NameStack {
protected:
  std::vector<StringRef > stack;
  StringRef separator;
public:
  NameStack(StringRef separator) : separator(separator) {  }
  void pushName(StringRef name) {
    stack.push_back(name);
  }
  StringRef popName(void) {
    StringRef last = stack.back();
    stack.pop_back();
    return last;
  }
  string toGuard(void) {
    return toString() & "_H_";
  }

  string toString(void) {
    stringBuilder out;
    std::vector<StringRef>::iterator iter = stack.begin();
    bool first = true;
    while(iter != stack.end()) {
      if(first) {
	first = false;
      } else {
	out << separator;
      }
      out << *iter;
      iter++;
    }
    return string(out);
  }
  friend ostream &operator<<(ostream &out, NameStack &ns) {
    out << ns.toString();
    return out;
  }
};

string SD_includeFiles::originalSource(void) {
  cerr << "SD_includeFiles::originalSource(): called on function for which it is not implemented!\n";
  exit(-1);
}

string IFMR_sourceDecls::originalSource(void) {
  cerr << "IFMR_sourceDecls::originalSource(): called on function for which it is meaningless!\n";
  exit(-1);
}

string IFMR_channelDecl::originalSource(void) {
  cerr << "IFMR_channelDecl::originalSource(): called on function for which it is meaningless!\n";
  exit(-1);
}

string IFMR_interposeOn::originalSource(void) {
  cerr << "IFMR_interposeOn::originalSource(): called on function for which it is meaningless!\n";
  exit(-1);
}
string IFMR_implements::originalSource(void) {
  cerr << "IFMR_implements::originalSource(): called on function for which it is meaningless!\n";
  exit(-1);
}

string readFromLocation(SourceLoc start, SourceLoc end) {
  //string filename = string(outputDir) & "/" & sourceLocManager->getFile(start);
  string filename = sourceLocManager->getFile(start);
  //cerr <<"filename is " << filename << "\n";
  ifstream s(filename.c_str());
  int startPos = sourceLocManager->getOffset(start),
    endPos = sourceLocManager->getOffset(end),
    len = endPos - startPos;
  if(s.bad()) {
    cerr << "Could not read from " << filename << endl;
    exit(-1);
  }
  s.seekg(startPos);

  char *buf = new char[len + 1];
  buf[len] = 0;

  s.read(buf, len);
  s.close();

  return string(buf);
}

int findFirstBrace(const string &cand, int &newLineCount) {
  int start = -1, state = 0;
  newLineCount = 0;
  for(int i = 0; i < cand.length(); i++) {
    if(cand[i] == '{') {
      start = i;
      state = 1;
      break;
    }
    if(cand[i] == '\n') {
      newLineCount++;
    }
  }
  if(!state) {
    return -1;
  }
  return start;
}

string lineDirectiveFromLocation(SourceLoc loc, SourceLoc end, int tighten = 0) {
  stringBuilder sb;
  int line = sourceLocManager->getLine(loc);
  if(tighten) {
    int skipped_newlines;
    findFirstBrace(readFromLocation(loc, end), skipped_newlines);
    line += skipped_newlines;
  }
  sb << "#line " <<  line << " \"" << sourceLocManager->getFile(loc) << "\"";
  return sb;
}

static string tightenToBrace(const string & cand) {
  int start, end = -1, state = 0, ignored;
  start = findFirstBrace(cand, ignored);
  if(start >= 0) state = 1;

  if(state == 0) {
    goto error;
  }
  for(int i = cand.length() - 1; i > start; i--) {
    if(cand[i] == '}') {
      end = i;
      state = 2;
      break;
    }
  }
  if(state == 2) {
    string res = cand.substring(start, end - start + 1);
    // cerr << "SD_func result: " << res << endl;
    return res;
  } else {
  error:
    cerr << "Tried to extract function body from " << cand << " but failed, state was " << state << "\n";
    exit(-1);
  }
}

string SD_typeSpec::originalSource(void) {
  return readFromLocation(loc, closeloc);
}

string SD_decl::originalSource(void) {
  string cand = readFromLocation(loc, closeloc);
  // cerr << "Read " << cand << endl;
  return cand;
}

string SD_func::originalSource(void) {
  string cand = readFromLocation(loc, closeloc);
  return lineDirectiveFromLocation(loc, closeloc) & rostring("\n") & cand;
}

string IFMR_interface::originalSource(void) {
  return lineDirectiveFromLocation(loc, closeloc, 1) & rostring("\n") &
    tightenToBrace(readFromLocation(loc, closeloc));
}

string IFMR_decon::originalSource() {
  return lineDirectiveFromLocation(loc, closeloc, 1) & rostring("\n") &
    tightenToBrace(readFromLocation(loc, closeloc));
}

string IFMR_interposeCall::originalSource(void) {
  string cand = readFromLocation(loc, closeloc);
  return lineDirectiveFromLocation(loc, closeloc) & rostring("\n") & cand;
}

string IFMR_interposeTransfer::originalSource(void) {
  string cand = readFromLocation(loc, closeloc);
  return lineDirectiveFromLocation(loc, closeloc) & rostring("\n") & cand;
}

string LFGenerateCheck::originalSource(void) {
  return tightenToBrace(readFromLocation(loc, closeloc));
}

static D_func *bottomIfDfunc(IDeclarator const *d)
{
  IDeclarator const *prev = d;     // last non-D_name, non-D_grouping declarator seen

  for (;;) {
    IDeclarator const *next = d->getBaseC();
    if (!next) {
      break;
    }

    if (!d->isD_grouping()) {
      prev = d;
    }
    d = next;
  }

  return ((IDeclarator *)prev)->ifD_func();
}

class IDLResolveAmbiguity : public ASTVisitor {
  IDLResolveAmbiguity(void) {  }

  virtual bool visitDeclarator(Declarator *d) {
    if(d->ambiguity) {
      cerr << "Declarator has ambiguity\n";
    }
    return true;
  }
};

void ServiceDecl::createOstreams(string &server, string &client, string &header) {
	string prefix = string(gen_kernel() ? ".kernel-" : ".");
  if(!generateInterpose) {
    server = string(name) & prefix & "server.c";
    header = string(name) & prefix & "interface.h";
  } else {
    server = string(name) & prefix & "interpose.c";
    header = string(name) & prefix & "interpose.h";
  }
  client = string(name) & prefix & "client.c";
}

void SyscallDecl::createOstreams(string &server, string &client, string &header) {
	// ignore -k flag
  server = string(name) & ".kernel.c";
  client = string(name) & ".user.c";
  header = string(name) & ".interface.h";
}

string param_name(const ASTTypeId &param);
bool param_isVarLen(const ASTTypeId &param);

// class NotFound { };

template <typename KEY, typename VALUE > 
class Map {
  struct MapElement {
    KEY k;
    VALUE v;

    MapElement(const KEY &_k, const VALUE &_v) : k(_k), v(_v) { }
  };
private:
  std::vector<MapElement*> map;

public:
  std::vector<VALUE> toVector(void) {
    std::vector<VALUE> rv;
    unsigned int i;
    for(i=0; i < map.size(); i++) {
      rv.push_back(map[i]->v);
    }
    return rv;
  }
#if 0
  VALUE &operator[](const KEY &k) {
    int i;
    for(i=0; i < map.size; i++) {
      if(map[i]->k == k) {
	return map[i]->v;
      }
    }
    throw NotFound;
  }
#endif
  void insert(const KEY &k, const VALUE &v) {
    if(find(k) != NULL) {
      cerr << k << " already inserted\n";
      exit(-1);
    }
    map.push_back(new MapElement(k, v));
  }

  VALUE *find(const KEY &k) {
    int i;
    for(i=0; i < (int) map.size(); i++) {
      if(map[i]->k == k) {
	return &map[i]->v;
      }
    }
    return NULL;
  }
};

typedef Map<string, Interface *> InterfaceMap;

void interfaceSetNS(Interface *i, string ns);
string interfaceName(Interface *i);


#if 0
template <typename T>
FakeList<T>* deep_list_clone(FakeList<T> *source) {
  int first = 1;
  int count = 0;
  FakeList<T> *rv = NULL;
  FAKELIST_FOREACH_NC(T, source, item) {
    if(first) {
      rv = FakeList<T>::makeList(item->clone());
      first = 0;
    } else {
      rv = rv->prepend(item->clone());
    }
    //cerr << "(" << count++ << "," << item <<  ")" <<param_toString(*item) << "\n";
  }
  rv = rv->reverse();
  cerr << "rv=(" << rv << ")\n";
  return rv;
}
#endif

static void parse_subfile(string fname, string &ns_name, ASTList<string> &defnList, InterfaceMap *interface_map);

// PASSONE: Syntactic cleanup
class IDLTranslatorPassOne : public ASTVisitor {
private:

	// allowable formats:
	//  k:foo.h
	//  u:<foo.h>
	//  foo.h
	//  k:"foo.h"
	//  etc.
  string includeFileToString(IncludeFile *file) {
	  string s = parseQuotedString(file->fname);
	  int l = s.length();
	  bool k = (l > 2 && s[0] == 'k' && s[1] == ':');
	  bool u = (l > 2 && s[0] == 'u' && s[1] == ':');
	  bool tk = gen_kernel();
	  if (k || u) s = s.substring(2, l-2);
	  stringBuilder str1;
      // if no " or <, default to "
      if(! (s[0] == '\"' || s[0] == '<') ) { str1 << "\"" << s << "\""; }
	  else { str1 << s; }
	  if ((!k && !u) || (k && tk) || (u && !tk))
		return rostring("#include ") & str1 & rostring("\n");
	  else
		return rostring("//#include ") & str1 & rostring("\n");
  }

protected:
  GenericIDL *idl;
  GenericIDL::Kind currIDLKind;
  int outputFlag;
  InterfaceMember *curr_member;

  NameStack ns;

public:
  InterfaceMap *interface_map;
  InterfaceMap *sub_interface_map;
  std::vector <string>service_names;
  string first_idl_name;

  IDLTranslatorPassOne(void) : idl(NULL), outputFlag(0), ns("_") { 
    interface_map = new InterfaceMap();
    sub_interface_map = new InterfaceMap();
  }
  IDLTranslatorPassOne(InterfaceMap *imap) : 
    idl(NULL), 
    outputFlag(0), 
    ns("_"),
    interface_map(imap) {
    sub_interface_map = new InterfaceMap();
  }
  
#if 0
  bool visitServiceDecl(ServiceDecl *_serviceDecl) {
    idl = _serviceDecl;
    return true;
  }
  void postvisitServiceDecl(ServiceDecl *_serviceDecl) {
    idl = NULL;
  }
#endif

  bool visitIncludeFile(IncludeFile *file) {
    int count = 0;
    ASTList<IncludeFile> *target_list = NULL;
    if(outputFlag & OUTPUT_SERVER) {
      target_list = &idl->serverIncludeFileList->list;
      count++;
    }
    if(outputFlag & OUTPUT_CLIENT) {
      target_list = &idl->clientIncludeFileList->list;
      count++;
    }
    if(0 && count == 1) {
      // 3/13/07: include files are now emitted inline
      target_list->append(file->clone());
    }

    if(count == 2) {
      idl->includeDefnList.append(new string(includeFileToString(file)));
      // cout << "appending " << includeFileToString(file);
    }
    return false;
  }

protected: 
  void outputMember() {
    int count = 0;
    if(outputFlag & OUTPUT_SERVER) {
      count++;
    }
    if(outputFlag & OUTPUT_CLIENT) {
      count++;
    }
    if(count == 2) {
      // idl->includeDefnList.append(new string(curr_member->originalSource()));
      stringBuilder sb;
      sb << curr_member->originalSource();
      idl->includeDefnList.append(new string(sb));
    }
  }
public:
  virtual bool visitTypeSpecifier(TypeSpecifier *t) {
    outputMember();
    return false;
  }

  virtual bool visitFunction(Function *f) {
    outputMember();
    return false;
  }

  bool visitGenericIDL(GenericIDL *_idl) {
    idl = _idl;
    currIDLKind = idl->kind();
    ns.pushName(idl->name);

    // cerr << "set first idl name " << idl->name << endl;
    first_idl_name = idl->name;

    service_names.push_back(ns.toString());
    return true;
  }


  bool visitInterface(Interface *i) {
    int generate = 0, check = 0;
    FOREACH_ASTLIST_NC(LFGenerateCheck, i->lf_list->list, iter) {
      ASTSWITCH(LFGenerateCheck, iter.data()) {
	ASTCASE(LFGC_generate, g)
	  {
	    if(!generate) {
	      generate = 1;
	      i->generate = g;
	    } else {
	      cerr << "more than one generate\n";
	      exit(-1);
	    }
	  }
	ASTNEXT(LFGC_check, c)
	  {
	    if(!check) {
	      check = 1;
	      i->check = c;
	    } else {
	      cerr << "more than one check\n";
	      exit(-1);
	    }
	  }
	ASTDEFAULT
	  {
	    cerr << "Unknown type of lfgc!\n";
	    exit(-1);
	  }
	ASTENDCASE;
      }
    }
    switch(currIDLKind) {
    case GenericIDL::SERVICEDECL:
      if(!(generate == 1 && check == 1)) {
	cerr << "Missing either generate or check (" << generate << ", " << check << ")\n";
	exit(-1);
      }
      i->lf_list = NULL;
      break;
    case GenericIDL::SYSCALLDECL:
      if(!(generate == 0 && check == 0)) {
	cerr << "Syscall declarations cannot contain any generate or check clauses\n";
	exit(-1);
      }
      break;
    default:
      cerr << "Unknown IDL kind " << currIDLKind << "\n";
      exit(-1);
      break;
    }
    // Build parameter list
    FAKELIST_FOREACH_NC(ASTTypeId, 
			bottomIfDfunc(i->f->nameAndParams->decl)->params, 
			item) {
      if(i->allParams == NULL) {
	i->allParams = FakeList<ASTTypeId>::makeList(item->clone());
      } else {
	i->allParams = i->allParams->prepend(item->clone());
      }
      switch(item->direction) {
      case INPUT:
      new_input: {
	ASTTypeId *clone = item->clone();
	clone->direction = item->direction;
	if(i->inputParams == NULL) {
	  i->inputParams = FakeList<ASTTypeId>::makeList(clone);
	} else {
	  i->inputParams = i->inputParams->prepend(clone);
	}
	break;
	}
      case OUTPUT:
	if(i->outputParams == NULL) {
	  i->outputParams = FakeList<ASTTypeId>::makeList(item->clone());
	} else {
	  i->outputParams = i->outputParams->prepend(item->clone());
	}
	break;
      default:
	goto new_input;
      }
    }
    if(i->allParams) {
      i->allParams = ParamList_normalize(i->allParams->reverse());
    }
    if(i->inputParams) {
      i->inputParams = ParamList_normalize(i->inputParams->reverse());
    }
    if(i->outputParams) {
      i->outputParams = ParamList_normalize(i->outputParams->reverse());
    }

    interfaceSetNS(i, ns.toString());
    // static int insert_count = 0;
    // cerr << "insert " << insert_count++ << n << "\n";
    string n = ns.toString() & "_" & interfaceName(i);
    interface_map->insert(n, i);
    return true;
  }

  virtual bool visitInterfaceMember(InterfaceMember *m) {
    curr_member = m;
    if(m->isIFMR_sourceDecls()) {
      // cerr << "visit sourcedecls\n";
      IFMR_sourceDecls *decls = m->asIFMR_sourceDecls();
      switch(decls->type) {
      case BOTH:
	outputFlag = OUTPUT_SERVER | OUTPUT_CLIENT;
	break;
      case CALLER:
	outputFlag = OUTPUT_CLIENT;
	break;
      case CALLEE:
	outputFlag = OUTPUT_SERVER;
	break;
      }
    }

    /* interpose syntax validation */
    if(m->isIFMR_interposeOn()) {
      //cerr << "found interpose on \n";
      if(currIDLKind != GenericIDL::SERVICEDECL) {
	cerr << "current idl must be service for __interpose_on__\n";
	exit(-1);
      }
      idl->subType = INTERPOSE;
      // add to identifier table
      IFMR_interposeOn *interpose = m->asIFMR_interposeOn();

      string fname = parseQuotedString(interpose->filename);
	  fname = string(outputDirPrefix) & fname;
	  if (tracingSys("print_parents")) 
		  cout << get_realpath(fname) << "\n";
      string interface_ns;
      parse_subfile(fname, interface_ns, 
		    idl->interposeIncludeDefnList, sub_interface_map);
    } else if((m->isIFMR_interposeCall() || m->isIFMR_interposeTransfer()) &&
	      idl->subType != INTERPOSE) {
      cerr << "current service idl must be of interpose subtype to use __interpose__ \n";
      exit(-1);
    } else if((m->isIFMR_interface() || m->isIFMR_channelDecl()) && 
	      idl->subType == INTERPOSE) {
      cerr << "current service idl cannot be of interpose subtype to use interface \n";
      exit(-1);
    } else if(m->isIFMR_implements()) {
      //cerr << "found implements \n";
      if(currIDLKind != GenericIDL::SERVICEDECL) {
	cerr << "current idl must be service for __implements__\n";
	exit(-1);
      }
      idl->subType = IMPLEMENTS;
      // add to identifier table
      IFMR_implements *implements = m->asIFMR_implements();

      string fname = parseQuotedString(implements->filename);
      fname = string(outputDirPrefix) & fname;
      if (tracingSys("print_parents")) 
	cout << get_realpath(fname) << "\n";
      parse_subfile(fname, idl->implements_ns, 
		    idl->implementsIncludeDefnList, sub_interface_map);
      if (ns.toString() == idl->implements_ns) {
	cerr << "Class that implements cannot have same name!\n";
	exit(-1);
      }
    }
    return true;
  }
};

static void parse_subfile(string fname, string &ns_name, ASTList<string> &defnList, InterfaceMap *interface_map) {
  //cerr << "Parsing " << fname << endl;

  CCLang *lang = new CCLang();
  lang->GNU_Cplusplus();
  SemanticValue *treeTop = new SemanticValue();
  StringTable *strTable = new StringTable();
  ParseTreeAndTokens *tree= new ParseTreeAndTokens(*lang, *treeTop, *strTable, fname.c_str());
    
  CCParse *parseContext = new CCParse(*strTable, *lang);
  tree->userAct = parseContext;
  ParseTables *tables = parseContext->makeTables();
  tree->tables = tables;

  if (!toplevelParse(*tree, fname.c_str())) {
    cerr << "parse error while handling __interpose_on__ \n";
    exit(2); // parse error
  }
      

  IDLTranslatorPassOne *pass1 = new IDLTranslatorPassOne(interface_map);
  TranslationUnit *unit = (TranslationUnit*)*treeTop;

  //cerr << "Traversing " << fname << endl;
  unit->traverse(*pass1);
  //cerr << "Done traversing " << fname << endl;
  //cerr << " name = " << pass1->first_idl_name << endl;
  ns_name = pass1->first_idl_name;

  unsigned int i;
  for(i=0; i < pass1->service_names.size(); i++) {
    stringBuilder sb;
    sb << "#include \"" << getDirname(fname) << 
      pass1->service_names[i] << (gen_kernel()?".kernel-interface.h\"":".interface.h\"");
    //cerr << "sb is here " << new string(sb)<<"\n";
    defnList.append(new string(sb));
  }
}

class InterfaceListStack {
protected:
  std::vector<InterfaceList *> data;
public:
  InterfaceListStack() : data() { }
  InterfaceList *top(void) {
    return data.back();
  }
  void push(InterfaceList *l) {
    data.push_back(l);
  }
  InterfaceList *pop(void) {
    InterfaceList *rval = data.back();
    data.pop_back();
    return rval;
  }
};

bool param_isPointer(const ASTTypeId &param) {
  // cerr << param.decl->getDeclaratorIdC()->toString() << " kind is " << param.spec->kindName() << " , " << param.decl->decl->kindName() << endl;
  return param.decl->decl->isD_pointer();
}

string param_name(const ASTTypeId &param) {
  // N.B.: peels off pointer
  if(param_isPointer(param)) {
    if(param.decl->decl->asD_pointer()->base->isD_pointer()) {
      cerr << "Only one level of pointers supported\n";
      exit(-1);
    }
  }
  return param.decl->getDeclaratorIdC()->toString();
}

bool param_isEnum(const ASTTypeId &param) {
  return param.spec->ifTS_enumSpec() != NULL;
}

string typeSpecifier_name(TypeSpecifier &_spec) {
  TypeSpecifier *spec = &_spec;
 // Support TS_name, TS_elaborated, and TS_simple

  TS_name *name;
  TS_simple *simple;
  TS_enumSpec *enumspec;
  TS_elaborated *elaborated;
  if((name = spec->ifTS_name())) {
    return name->name->toString();
  } else if((simple = spec->ifTS_simple())) {
    return string(simpleTypeName(simple->id));
  } else if((enumspec = spec->ifTS_enumSpec())) {
    cerr << "enum spec not supported!\n";
    exit(-1);
    return rostring("enum ") & enumspec->name; // XXX I don't know what's happening here
  } else if((elaborated = spec->ifTS_elaborated())) {
    return string(toString(elaborated->keyword)) & " " & string(elaborated->name->toString());
  } else {
    cerr << "Unknown Type specifier!\n";
    exit(-1);
  }
}

string param_typeName(const ASTTypeId &param) {
  // NOTE!!! This function peels off all pointers
  return typeSpecifier_name(*param.spec);
}

string param_toString(const ASTTypeId &param) {
  return param_typeName(param) & " " & (param_isPointer(param) ? "* " : "") & param_name(param);
}

bool param_isVarLen(const ASTTypeId &param) {
  return param_typeName(param) == "struct VarLen";
}

bool typeSpecifier_isWordLen(TypeSpecifier *ts) {
  if(ts->isTS_simple()) {
    return simpleTypeReprSize(ts->asTS_simple()->id) <= NEXUS_WORD_SIZE;
  }
  if(ts->isTS_elaborated()) {
    return ts->asTS_elaborated()->keyword == TI_ENUM;
  }
  cerr << "unhandled wordlen " << ts->kind() << "\n";
  exit(-1);
}

bool param_isWordLen(const ASTTypeId &param) {
  if(param_isPointer(param)) {
    return true;
  }
  return typeSpecifier_isWordLen(param.spec);
}

string param_VarLen_len(const ASTTypeId &param) {
  assert(param_isVarLen(param));
  return param_name(param) & "__len";
}

string paramList_toStructMembersService(FakeList<ASTTypeId> *params) {
  stringBuilder sb;
  FAKELIST_FOREACH_NC(ASTTypeId, params, item) {
    string comment;
    string star;
#if 0
    if(param_isVarLen(*item)) {
      sb << "	int " << param_VarLen_len(*item) << "; // VarLen\n";
    } else 
#endif
      if(param_isPointer(*item)) {
      // serialized format is the same either way
      comment = string("was pointer");
      star = "*";
      goto verbatim;
    } else {
      // not pointer
      comment = string("was not pointer");
    verbatim:
      sb << "	" << param_typeName(*item) << " " << star << param_name(*item) << "; // " << comment << "\n";
    }
  }
  return string(sb);
}

string paramList_toStructMembersSyscall(FakeList<ASTTypeId> *inputParams, 
					FakeList<ASTTypeId> *outputParams) {
  stringBuilder sb;
  sb << "	// INPUT\n";
  FAKELIST_FOREACH_NC(ASTTypeId, inputParams, item) {
#if 0
    if(param_isVarLen(*item)) {
      sb << rostring("	struct VarLen ") << param_name(*item) << ";\n";
    } else
#endif
 if(param_isWordLen(*item)) {
      sb << "	" << param_typeName(*item) << " " << (param_isPointer(*item)?"*":"") << param_name(*item) << ";\n";
    } else {
      // pointer
      sb << rostring("	") << param_typeName(*item) << " *" << param_name(*item) << ";\n";
    }
  }

  sb << "	// OUTPUT\n";
  FAKELIST_FOREACH_NC(ASTTypeId, outputParams, item) {
    if(!param_isPointer(*item)) {
      cerr << "only pointer type supported as output param\n";
      exit(-1);
    }
    sb << "	" << param_typeName(*item) << " *" << param_name(*item) << ";\n";
  }

  return string(sb);
}

string paramList_toStringAsParams(FakeList<ASTTypeId> *params) {
  stringBuilder sb;
  bool first = true;
  FAKELIST_FOREACH_NC(ASTTypeId, params, item) {
    if(first) first = false;
    else sb << ", ";
    sb << param_toString(*item);
  }
  if(first) {
      //cerr << "empty param list, no args\n";
      return string("void");
  }
  return string(sb);
}

string paramList_toStringAsArgs(string prefix, FakeList<ASTTypeId> *params) {
  stringBuilder sb;
  bool first = true;
  FAKELIST_FOREACH_NC(ASTTypeId, params, item) {
    if(first) first = false;
    else sb << ", ";
    sb << prefix << param_name(*item);
  }
  if(first) {
      cerr << "empty param list, no args\n";
      return string("");
  }
  return string(sb);
}

bool paramList_hasElements(FakeList<ASTTypeId> *params) {
  bool rval = false;
  FAKELIST_FOREACH_NC(ASTTypeId, params, item) {
    rval = true;
    break;
  }
  return rval;
}

string paramList_toStringAsVarDecls(FakeList<ASTTypeId> *params) {
  stringBuilder sb;
  FAKELIST_FOREACH_NC(ASTTypeId, params, item) {
    // sb <<       "(" << counter++ << "," << item <<  ")";
    sb << "		" << param_toString(*item) << ";\n";
  }
  return string(sb);
}

enum Direction {
  TO_BUF,
  FROM_BUF,
  COMPUTE_LEN,
};

string paramList_marshallServiceHelper(FakeList<ASTTypeId> *params,
				       string buffer, string len, 
				       Direction dir) {
  stringBuilder fields;

  const rostring varPos = "__varPos";
  fields << "		int " << varPos << " = 0;\n";
  fields << "		" << varPos << " = " << varPos << "; // suppress warning\n";
  FAKELIST_FOREACH_NC(ASTTypeId, params, item) {
    string copySrc, copyLen;
    string destName;
    string this_varlen;
    destName = param_name(*item);
    copySrc = rostring("&") & param_name(*item);
    copyLen = rostring("sizeof(") & param_name(*item) & ")";

    string bufpos = rostring("&") & buffer & "->" & destName;
    string other = copySrc;

    if(dir == COMPUTE_LEN) {
      // DO NOTHING
    } else {
      string s;
      string d;

      if(dir == TO_BUF) {
	s = other;
	d = bufpos;
      } else if(dir == FROM_BUF) {
	d = other;
	s = bufpos;
      } else {
	cerr << "unknown direction" << endl;
	exit(-1);
      }
      // normal processing
      fields << rostring("		memcpy(") << d << ", " << s << ", " << copyLen << ");\n";
    }
    fields << this_varlen;
  }
  if(dir == TO_BUF || dir ==  COMPUTE_LEN) {
    fields << "		" << len << " = " << varPos << " + sizeof(*" << buffer << ");\n";
  }
  return fields;
}

string paramList_marshallService(FakeList<ASTTypeId> *params, string rbuf, string dest, string lenDest) {
  string head = rostring("") &
    "	" & dest & "->__rbuf = " & rbuf & ";\n\n";
  if(params == NULL) {
    return head & "/* No params to marshall */\n";
  } else {
    return head & paramList_marshallServiceHelper(params, dest, lenDest, TO_BUF);
  }
}

#if 0
stringBuilder sb;
  sb << "if(" << ") {\n";
  sb << "		//// Could not unmarshall\n";
  sb << "		XXX;\n";
  sb << "	}\n";
  return sb;
#endif

string paramList_unmarshallService(FakeList<ASTTypeId> *params, string source, string len, string failure) {
  string head = rostring("") &
    "	void *__rbuf;\n"
    "	__rbuf = " & source & "->__rbuf;\n";
  if(params == NULL) {
    return head & "/* No parameters to unmarshall */\n";
  } else {
    return head &
      paramList_toStringAsVarDecls(params) &
      "		if(" & len & " < sizeof(*" & source & ")) {\n" &
      "			printf(\"Source buffer length incorrect %d %d(%s:%d)\\n\",  " & len & ", sizeof(*" & source & "), __FILE__, __LINE__);\n" &
      "			" & failure & ";\n" &
      "		}\n" &
      "		{\n" & 
      "			int __computedLen;\n" &
      paramList_marshallServiceHelper(params, source, "__computedLen", COMPUTE_LEN) &
      "			if(__computedLen != " & len & ") {\n" &
      "				printf(\"%s: Computed length incorrect %d %d\\n\", funcname, __computedLen, " & len & ");\n" & 
      "				" & failure & ";\n" &
      "			}\n" &
      "		}\n" &
      paramList_marshallServiceHelper(params, source, len, FROM_BUF);
  }
}

string macroize(const string s) {
  stringBuilder rv;
  int i;
  for(i=0; i < s.length(); i++) {
    if(s[i] == '\n') {
      rv << '\\';
    }
    rv << s[i];
  }
  return rv;
}

void interfaceSetNS(Interface *i, string ns) {
  i->ns = ns;
}

string interfaceName(Interface *i) {
  if(i->name != NULL) return *i->name;
  return i->f->nameAndParams->getDeclaratorIdC()->toString();
}

string interfaceCallerName(Interface *i) {
  return i->ns & rostring("_") & interfaceName(i);
}

string interfaceCommandOrdinal_qualified(string ns, Interface *i) {
  return rostring("SYS_") & ns & "_" & interfaceName(i) & "_CMD";
}

string interfaceLastOrdinal(string ns) {
  return ns & rostring("_LAST_CMD");
}

string interfaceCommandOrdinal(Interface *i) {
  return interfaceCommandOrdinal_qualified(i->ns, i);
}

string interfacePStructName(Interface *i) {
  return i->ns & "_" & interfaceName(i) & "_Args";
}
FakeList<ASTTypeId> *interfaceInputParams(Interface *i) {
  return i->inputParams;
}
FakeList<ASTTypeId> *interfaceAllParams(Interface *i) {
  return i->allParams;
}
FakeList<ASTTypeId> *interfaceOutputParams(Interface *i) {
  return i->outputParams;
}
FakeList<ASTTypeId> *interfaceParams(Interface *i) {
  // cerr << "interface params rewritten\n";
#if 0
  return bottomIfDfunc(i->f->nameAndParams->decl)->params;
#else
  return i->allParams;
#endif
}

string interfaceRStructName(Interface *i) {
  return i->ns & "_" & interfaceName(i) & "_Result";
}

TypeSpecifier *interfaceReturnType(Interface *i, int *pointerLevels) {
  if(i->retspec != NULL) {
    if(pointerLevels != NULL)
      *pointerLevels = i->pointerLevels;
    return i->retspec;
  }

  IDeclarator *np = i->f->nameAndParams->decl;
  if(pointerLevels != NULL)
    *pointerLevels = 0;
  if(np->isD_pointer()) {
    if(np->asD_pointer()->base->isD_pointer()) {
      cerr << "Only one level of pointers supported\n";
      exit(-1);
    }
    if(pointerLevels != NULL)
      *pointerLevels = 1;
  }
  return i->f->retspec;
}
string interfaceReturnTypeName(Interface *i) {
  int pointerLevels;
  TypeSpecifier *ts = interfaceReturnType(i, &pointerLevels);
  string pointerSuffix;
  for(int i=0; i < pointerLevels; i++) {
    pointerSuffix = pointerSuffix & "*";
  }
  return typeSpecifier_name(*ts) & " " & pointerSuffix;
}

bool interfaceReturnTypeIsVoid(Interface *i) {
  TypeSpecifier *ts = interfaceReturnType(i, NULL);
  return isVoid(ts);
}

bool interfaceReturnTypeIsWordLen(Interface *i) {
  int pointerLevels;
  TypeSpecifier *ts = interfaceReturnType(i, &pointerLevels);
  if(pointerLevels > 0) {
    // is pointer
    return true;
  }
  return typeSpecifier_isWordLen(ts);
}

string interfacePStructMembersService(Interface *i) {
  return rostring("void *__rbuf;\n") &
    paramList_toStructMembersService(interfaceAllParams(i));
}

string interfaceCallerExtName(Interface *i) {
  return interfaceCallerName(i) & "_ext";
}

string interfaceCallerGenericName(Interface *i) {
  return interfaceCallerName(i) & "_generic_ext";
}
string interfaceCallerAsyncName(Interface *i) {
  return interfaceCallerName(i) & "_async";
}

string interfaceCallerExtPrototype(Interface *i) {
  return interfaceReturnTypeName(i) & " " & interfaceCallerExtName(i) & "(Connection_Handle __target_conn_handle" & 
    (paramList_hasElements(interfaceParams(i)) ? 
     rostring(", ") & paramList_toStringAsParams(interfaceParams(i)) :
     rostring("")) &
    ")";
}
string interfaceCallerGenericPrototype(Interface *i) {
  return interfaceReturnTypeName(i) & " " & interfaceCallerGenericName(i) & "(int is_async, Connection_Handle __target_conn_handle" & 
    (paramList_hasElements(interfaceParams(i)) ? 
     rostring(", ") & paramList_toStringAsParams(interfaceParams(i)) :
     rostring("")) &
    ")";
}

string interfaceCallerAsyncPrototype(Interface *i) {
  return interfaceReturnTypeName(i) & " " & interfaceCallerAsyncName(i) &
    "(" & paramList_toStringAsParams(interfaceParams(i)) & ")";
}

string interfaceCallerPrototype(Interface *i) {
  return interfaceReturnTypeName(i) & " " & interfaceCallerName(i) & "(" & paramList_toStringAsParams(interfaceParams(i)) & ")";
}
string interfaceCalleeName(Interface *i) {
  return i->ns & "_" & interfaceName(i) & "_Handler";
}
string interfaceCalleePrototype(Interface *i) {
  return interfaceReturnTypeName(i) & " " & interfaceCalleeName(i) & "(IPD_ID ipd_id /* ignored for system calls */, Call_Handle call_handle /* ignored for system calls */, char *message_data /* for zero-copy IPC */, int __is_async" & (paramList_hasElements(interfaceParams(i)) ? (rostring(", ") & paramList_toStringAsParams(interfaceParams(i))) : "") & ")";
}

string interposeCallName(Interface *i) {
  return i->ns & "_" & interfaceName(i) & "_Call_Handler";
}

string interposeTransferName(Interface *i) {
  return i->ns & "_" & interfaceName(i) & "_Transfer_Handler";
}

string interposeCallPrototype(Interface *template_i) {
  return interfaceReturnTypeName(template_i) & " " & 
    interposeCallName(template_i) & 
    "(IPD_ID ipd_id, Call_Handle call_handle, struct IEvent_Info *event_info, struct IEvent_Call_Info *call_info, enum InterposeHowHandled *howHandled" & (paramList_hasElements(interfaceParams(template_i)) ? (rostring(", ") & paramList_toStringAsParams(interfaceParams(template_i))) : "") & ")";
}

string interposeTransferPrototype(Interface *template_i) {
  return rostring("void ") & 
    interposeTransferName(template_i) & 
    rostring("(IPD_ID ipd_id, Call_Handle call_handle, struct IEvent_Info *event_info, struct IEvent_Transfer_Info *transfer_info, struct VarLen data, enum InterposeHowHandled *howHandled)");
}

class IDLTranslatorPassTwo : public ASTVisitor {
private:
	// allowable formats:
	//  k:foo.h
	//  u:<foo.h>
	//  foo.h
	//  k:"foo.h"
	//  etc.
  string includeFileToString(IncludeFile *file) {
	  string s = parseQuotedString(file->fname);
	  int l = s.length();
	  bool k = (l > 2 && s[0] == 'k' && s[1] == ':');
	  bool u = (l > 2 && s[0] == 'u' && s[1] == ':');
	  bool tk = gen_kernel();
	  if (k || u) s = s.substring(2, l-2);
	  stringBuilder str1;
      // if no " or <, default to "
      if(! (s[0] == '\"' || s[0] == '<') ) { str1 << "\"" << s << "\""; }
	  else { str1 << s; }
	  if ((!k && !u) || (k && tk) || (u && !tk))
		return rostring("#include ") & str1 & rostring("\n");
	  else
		return rostring("//#include ") & str1 & rostring("\n");
  }
protected:
  GenericIDL *idl;

  // accumulates the results
  ofstream *server, *client, *header;
  ofstream *interposeHeader;

  string headerName; // filename of header
  // current namespace
  NameStack ns;
  InterfaceMember *curr_member;
  IDLTranslatorPassOne *passOneResult;

  InterfaceListStack interfaceListStack;

  stringBuilder callerConstructor;
  stringBuilder calleeConstructor;
  stringBuilder callerDestructor;
  stringBuilder calleeDestructor;

  stringBuilder serverExports;
  stringBuilder serverStr;
  stringBuilder clientStr;

  stringBuilder commonStr;

  stringBuilder outerSwitchCases;
  stringBuilder fastSyscallProcessor;

  int outputFlag;

  // xxx: these flags may not be respected in all relevant contexts
  int generateInterface;
  int generateClient;
  int generateServer;
  int generateLFGenerate;
  int generateLFCheck;
  int generateInterpose;
  int generateImplements;

  InterfaceMap *interface_map;
  InterfaceMap *sub_interface_map;

private:

  string service_port_handle(void) {
    return ns.toString() & "_port_handle";
  }

  string service_connection_handle(void) {
    return ns.toString() & "_conn_handle";
  }

  string service_server_port_num(void) {
    return ns.toString() & "_server_port_num";
  }
  string service_client_port_num(void) {
    return ns.toString() & "_client_port_num";
  }

  string syscall_port(void) {
    return ns.toString() & "_port";
  }
  string target_service_connection_handle(void) {
    return string("__target_conn_handle");
  }
  /*
  string service_initPrototype(void) {
    return rostring("void ") & ns.toString() & rostring("_init(void)");
  }
  string service_destroyPrototype(void) {
    return rostring("void ") & ns.toString() & rostring("_destroy(void)");
  }
  */
  string serviceProcessorName(void) {
    string suffix;
    if(gen_kernel()) {
      suffix = "_kernelProcessNextCommand";
    } else {
      suffix = "_processNextCommand";
    }
    return ns.toString() & suffix;
  }

  string interposeProcessorName(void) {
    return ns.toString() & "_processCall";
  }
  string interposeProcessorPrototype(void) {
    stringBuilder sb;
    sb << "int " << interposeProcessorName() << "(IPD_ID ipd_id, Call_Handle call_handle, ServerProcessorType type, struct IEvent_Info *event_info, struct IEvent_Call_Info *call_info, struct VarLen message)";
    return string(sb);
  }
  string gen_IPC_Return(bool is_syscall, 
			string IS_ASYNC, string ACK_ASYNC,
			string CALL_HANDLE, string RESULT, string RESULT_LEN) {
    return 
      rostring("") &
      "	if(" & IS_ASYNC & ") {\n" 
      "		if(" & ACK_ASYNC & ") IPC_AsyncDone(" & CALL_HANDLE & ", IPC_ASYNC_DONE);\n"
      "	} else {\n"
      "		IPC_TransferTo(" & CALL_HANDLE & ", RESULT_DESCNUM, " & RESULT & ", 0, " & RESULT_LEN & ");\n" &
      "		IPC_CallReturn(" & CALL_HANDLE & ");\n"
      "	}\n";
  }

  string interfaceSyscallProcessorName(void) {
    return ns.toString() & "_syscallProcessor";
  }
  string interfaceSyscallProcessorPrototype(void) {
    return rostring("void ") & interfaceSyscallProcessorName() & "(char *dataBuf, int dataLen, char *__result_dest)";
  }

  void outputHeader(ofstream &out) {
    out << "//// DO NOT EDIT\n";
  }
  template <typename T> 
    void outputIncludeFile(T &out, IncludeFile &file) {
    string str = includeFileToString(&file);
    out << str;
    if (tracingSys("print_includes") && str[0] == '#') {
      char *s = strdup(str.c_str() +strlen("#include "));
      s++;
      int n = strlen(s) - 2; // drop quote and newline
      s[n] = '\0';
      int k = strlen(".interface.h");
      if (s[-1] == '"' && n > k && !strcmp(&s[n-k], ".interface.h")) {
	cout << get_realpath(string(outputDirPrefix)&string(s)) << "\n";
      }
      k = strlen(".interpose.h");
      if (s[-1] == '"' && n > k && !strcmp(&s[n-k], ".interpose.h")) {
	cout << get_realpath(string(outputDirPrefix)&string(s)) << "\n";
      }
    }
  }

  void outputIncludeFiles(ofstream &out, IncludeFileList *flist) {
    out << "//// INCLUDE FILES\n";
    FOREACH_ASTLIST_NC(IncludeFile, flist->list, iter) {
      outputIncludeFile(out, *iter.data());
    }
  }
public:
  IDLTranslatorPassTwo(IDLTranslatorPassOne *passOneResult) : 
    server(NULL), 
    client(NULL),
    header(NULL),
    ns("_"),
    passOneResult(passOneResult),
    outputFlag(0),
    generateInterface(1),
    generateClient(1),
    generateServer(1),
    generateLFGenerate(0),
    generateLFCheck(0),
    generateInterpose(0),
    generateImplements(0)
{ 
  interface_map = passOneResult->interface_map;
  sub_interface_map = passOneResult->sub_interface_map;
}

  bool visitIncludeFile(IncludeFile *file) {
    if( (outputFlag & (OUTPUT_SERVER | OUTPUT_CLIENT)) != 
	(OUTPUT_SERVER | OUTPUT_CLIENT) ) {
      // only one set, output in-line
      if(outputFlag & OUTPUT_SERVER) {
	outputIncludeFile(serverStr, *file);
      }
      if(outputFlag & OUTPUT_CLIENT) {
	outputIncludeFile(clientStr, *file);
      }
    } else {
      outputIncludeFile(serverStr, *file);
    }
    return false;
  }
  virtual bool visitGenericIDL(GenericIDL *idl) {
    this->idl = idl;
    assert(server == NULL);
    string serverName, clientName;

	bool outInterface = 0, outServer = 0, outClient = 0, outInterpose = 0;

	bool all = !tracingSys("output_specified");

    if(idl->subType == INTERPOSE) {
		generateInterface = 0;
		generateClient = 0;
		generateServer = 1;
		generateInterpose = 1;
		generateLFGenerate = 0;
		generateLFCheck = 0;
		generateImplements = 0;
        outServer = all || tracingSys("interpose.c");
        outInterpose = all || tracingSys("interpose.h");
		outClient = 0;
    } else {
	    generateLFGenerate = 1;
	    generateLFCheck = 1;
		if(idl->subType == IMPLEMENTS) {
		  generateImplements = 1;
		}
		generateServer = 1;
		generateClient = 1;
		generateInterface = 1;
		generateInterpose = 0;
	    if (idl->kind() == GenericIDL::SERVICEDECL) {
		  outInterface = all || tracingSys("interface.h");
		  outClient = all || tracingSys("client.c");
		  outServer = all || tracingSys("server.c");
	    } else {
	      outInterface = all || tracingSys("interface.h");
		  outClient = all || tracingSys("user.c");
		  outServer = all || tracingSys("kernel.c");
	    }
	}
    idl->generateInterpose = generateInterpose;
    idl->createOstreams(serverName, clientName, headerName);

#define JUNK_FILENAME "/dev/null"

    if(outServer) {
	  string fname = string(outputDirPrefix) & serverName;
      chmod(fname.c_str(), 0644);
      server = new ofstream(fname.c_str());
      chmod(fname.c_str(), 0444);
	  //cerr << "creating output file "<<fname<<" for " << idl->name << endl;
      if(server->bad()) {
	cerr << "Error while creating output files for service " << idl->name << endl;
	exit(-1);
      }
    } else {
      server = new ofstream(JUNK_FILENAME);
	  //cerr << "skipping output file "<<serverName<<" for " << idl->name << endl;
    }
    if(outClient) {
	  string fname = string(outputDirPrefix) & clientName;
      chmod(fname.c_str(), 0644);
      client = new ofstream(fname.c_str());
      chmod(fname.c_str(), 0444);
	  //cerr << "creating output file "<<fname<<" for " << idl->name << endl;
      if(client->bad()) {
	cerr << "Error while creating output files for service " << idl->name << endl;
	exit(-1);
      }
    } else {
      client = new ofstream(JUNK_FILENAME);
	  //cerr << "skipping output file "<<clientName<<" for " << idl->name << endl;
    }
    if(outInterface) {
	  string fname = string(outputDirPrefix) & headerName;
      chmod(fname.c_str(), 0644);
      header = new ofstream(fname.c_str());
      chmod(fname.c_str(), 0444);
	  //cerr << "creating output file "<<fname<<" for " << idl->name << endl;
      if(header->bad()) {
	cerr << "Error while creating output files for service " << idl->name << endl;
	exit(-1);
      }
    } else {
      header = new ofstream(JUNK_FILENAME);
	  // cerr << "skipping output file "<<headerName<<" for " << idl->name << endl;
    }

    if(outInterpose) {
	  string fname = string(outputDirPrefix) & headerName;
      chmod(fname.c_str(), 0644);
      interposeHeader = new ofstream(fname.c_str());
      chmod(fname.c_str(), 0444);
	  //cerr << "creating output file "<<fname<<" for " << idl->name << endl;
      if(interposeHeader->bad()) {
	cerr << "Error while creating output files for service " << idl->name << endl;
	exit(-1);
      }
    } else {
      interposeHeader = new ofstream(JUNK_FILENAME);
	  //cerr << "skipping output file "<<interposeHeader<<" for " << idl->name << endl;
    }

    ns.pushName(idl->name);
    outputHeader(*server);
    outputIncludeFiles(*server, idl->serverIncludeFileList);

    outputHeader(*client);
    outputIncludeFiles(*client, idl->clientIncludeFileList);

    outputHeader(*header);

    *header << "#ifndef " << ns.toGuard() << "\n";
    *header << "#define " << ns.toGuard() << " \n";
    *header << "#include <nexus/idl.h>\n\n";
    *header << "extern Port_Handle " << service_port_handle() << ";\n";
    *header << "extern Connection_Handle " << service_connection_handle() << ";\n";
    *header << "/* The port number of the server in a server binary */\n";
    *header << "extern Port_Num " << service_server_port_num() << ";\n";
    *header << "/* The port number of the server in a client binary */\n";
    *header << "extern Port_Num " << service_client_port_num() << ";\n";

    
    *interposeHeader << "#ifndef " << ns.toGuard() << "_INTERPOSE\n";
    *interposeHeader << "#define " << ns.toGuard() << "_INTERPOSE\n";
    *interposeHeader << "#include <nexus/idl.h>\n";
    *interposeHeader << "#include <nexus/interpose.h>\n\n";

    //outputIncludeFiles(*header, idl->includeFileList);
    *header << "//// includeDefnList\n";
    FOREACH_ASTLIST_NC(string, idl->includeDefnList, iter) {
      *header << *iter.data() << "\n";
      *interposeHeader << *iter.data() << "\n";
    }
    *header << "//// serverstr\n";
    *header << serverStr;

    *header << "\n\n";

    interfaceListStack.push(idl->interfaceList);

    return true;
  }

  virtual bool visitChannelDecl(ChannelDecl *channel_decl) {
    ns.pushName(channel_decl->name);
    interfaceListStack.push(channel_decl->interfaceList);
    return true;
  }

  virtual void postvisitChannelDecl(ChannelDecl *channel_decl) {
    StringRef name = ns.popName();
    if(name != channel_decl->name) {
      cerr << "ERROR! Removing " << name << ", expected " << channel_decl->name << endl;
      exit(-1);
    }
    // Now that all interfaces have been gathered, start building enums
    interfaceListStack.pop();
    cerr << "Enum construction for channel decl not implemented!\n";
  }

  virtual bool visitInterfaceMember(InterfaceMember *m) {
    // necessary for child processing
    curr_member = m;

    if(m->isIFMR_sourceDecls()) {
      IFMR_sourceDecls *decls = m->asIFMR_sourceDecls();
      switch(decls->type) {
      case BOTH:
	outputFlag = OUTPUT_SERVER | OUTPUT_CLIENT;
	break;
      case CALLER:
	outputFlag = OUTPUT_CLIENT;
	break;
      case CALLEE:
	outputFlag = OUTPUT_SERVER;
	break;
      }
    } else if(m->isIFMR_interposeCall() || m->isIFMR_interposeTransfer()) {
      //cerr << "interposeCall or interposeTransfer()\n";
      if(m->isIFMR_interposeCall()) {
	IFMR_interposeCall *call = 
	  m->asIFMR_interposeCall();
	Interface *i = 
	  new Interface(NULL, new LFGenerateCheckList(NULL), NULL, NULL, false, false, false);
	Interface **find_result = sub_interface_map->find(call->name);
	if(find_result == NULL) {
	  cerr << "could not find interface " << call->name << "!\n";
	  exit(-1);
	}
	Interface *template_i = *find_result;
	template_i->interposedOn = true;

	interfaceSetNS(i, template_i->ns);
	i->name = new string(interfaceName(template_i));
	i->retspec = interfaceReturnType(template_i, &i->pointerLevels);

	i->allParams = template_i->allParams;
	i->inputParams = template_i->inputParams;
	i->outputParams = template_i->outputParams;
	
	serverStr << "static " << interposeCallPrototype(template_i) << "\n";
	serverStr << curr_member->originalSource() << "\n";

	interfaceListStack.top()->list.append(i);
      } else if(m->isIFMR_interposeTransfer()) {
	/* IFMR_interposeTransfer *transfer =  */ m->asIFMR_interposeTransfer();
	cerr << "Transfer not implemented! (current design strategy is to leave it up to the user)\n";
      }
      return false;
    }
    return true;
  }

  virtual bool visitTypeSpecifier(TypeSpecifier *t) {
    if((outputFlag & OUTPUT_SERVER) && (outputFlag & OUTPUT_CLIENT)) {
      // both server and client ; don't need output since it is in the header file
      return false;
    }
    if(outputFlag & OUTPUT_SERVER) {
      serverStr << curr_member->originalSource() << "\n";
    }
    if(outputFlag & OUTPUT_CLIENT) {
      clientStr << curr_member->originalSource() << "\n";
    }
    return false;
  }

  virtual bool visitDeclaration(Declaration *d) {
    if((outputFlag & OUTPUT_SERVER) && (outputFlag & OUTPUT_CLIENT)) {
      // both server and client ; don't need output since it is in the header file
      return false;
    }
    if(outputFlag & OUTPUT_SERVER) {
      serverStr << curr_member->originalSource() << "\n";
    }
    if(outputFlag & OUTPUT_CLIENT) {
      clientStr << curr_member->originalSource() << "\n";
    }
    return false;
  }
  virtual bool visitInterface(Interface *i) {
    string name = interfaceName(i);
    interfaceSetNS(i, ns.toString());
    // *server << ns << " : " << name << ": " << curr_member->originalSource() << "\n";
    if(!idl->isSyscallDecl()) {
      // for system calls, the interfaces are exported
      serverStr << "static ";
    } else {
      serverExports << interfaceCalleePrototype(i) << ";\n";
    }
    serverStr << interfaceCalleePrototype(i) << " /* INTERFACE */ \n";
    serverStr << curr_member->originalSource() << "\n";

    interfaceListStack.top()->list.append(i);
    return false;
  }
  virtual bool visitFunction(Function *f) {
#if 0 // useful for filling in some kind of stub
    switch(currIDLKind) {
    case GenericIDL::SERVICE:
      break;
    case GenericIDL::SYSCALL:
      break;
    }
#endif
    if((outputFlag & OUTPUT_SERVER) && (outputFlag & OUTPUT_CLIENT)) {
      // both server and client ; don't need output since it is in the header file
      return false;
    }

    if(outputFlag & OUTPUT_SERVER) {
      serverStr << curr_member->originalSource() << "\n";
    }
    if(outputFlag & OUTPUT_CLIENT) {
      clientStr << curr_member->originalSource() << "\n";
    }
    return false;
  }

  virtual bool visitDecon(Decon *d) {
    ASTSWITCH(Decon, d) {
    ASTCASE(CallerConstructor, c)
      {
	// c; // suppress warnings
	callerConstructor << "	// CALLER CONSTRUCTOR BLOCK\n" <<
	  "	" << curr_member->originalSource() << "\n";
      }
    ASTNEXT(CalleeConstructor, c)
      {
	// c; // suppress warnings
	calleeConstructor << "	// CALLEE CONSTRUCTOR BLOCK\n" << 
	  "	" << curr_member->originalSource() << "\n";
      }
    ASTNEXT(CallerDestructor, c)
      {
	//c; // suppress warnings
	callerDestructor << "	// CALLER DESTRUCTOR BLOCK\n" << 
	  "	" << curr_member->originalSource() << "\n";
      }
    ASTNEXT(CalleeDestructor, c)
      {
	//c; // suppress warnings
	calleeDestructor << "	// CALLEE DESTRUCTOR BLOCK\n" << 
	  "	" << curr_member->originalSource() << "\n";
      }
    ASTDEFAULT
      {
	cerr << "Unknown type of decon block!\n";
	exit(-1);
      }
    ASTENDCASE;
    }
    return false;
  }

private:
  void generateGeneric(GenericIDL *syscall_decl, string errno_name,
		       string is_async, string ack_async) {
    // logical xor: Exactly one off isService or isSyscall
    assert( (!!syscall_decl->isServiceDecl()) ^ 
	   (!!syscall_decl->isSyscallDecl()) );
    bool is_syscall = syscall_decl->isSyscallDecl();
    string client_init_call = ns.toString() & rostring("_clientInit()");

    rostring RETURN_NONVOID_ERROR = 
      "		memset(&rbuf.rv, 0xff, sizeof(rbuf.rv));\n"
      "		return rbuf.rv;\n";

    if(!is_syscall) {
      *client << "static int " << clientInitializedVar << ";\n";
    }

    if(is_syscall) {
      *server << rostring("#define ") << service_server_port_num() << rostring(" SYSCALL_IPCPORT_") << ns.toString() << "\n";
      *server << rostring("#define ") << service_port_handle() << 
	rostring(" ( SYSCALL_IPCPORT_") << ns.toString() << " - FIRST_SYSCALL_IPCPORT + 1)\n";
      *client << rostring("#define ") << service_connection_handle() << 
	rostring(" ( SYSCALL_IPCPORT_") << ns.toString() << " - FIRST_SYSCALL_IPCPORT + 1)\n";
    } else {
      if(!generateInterpose) {
	*server << "Port_Handle " << service_port_handle() << ";\n\n";
	*server << "Port_Num " << service_server_port_num() << ";\n\n";
      }

      // Client's copy of port_num is weak
      *client << "Port_Num " << service_client_port_num() << ";\n\n";
      *client << "Connection_Handle " << service_connection_handle() << " = -1;\n\n";
    }

    *client << clientStr;
    *server << serverStr;

    InterfaceList *ilist = interfaceListStack.pop();

    stringBuilder cmd_enum_inherited(1024);
    stringBuilder cmd_enum_new(1024);
    stringBuilder arg_structs(1024);
    stringBuilder processor(1024);
    cmd_enum_inherited << "";
    cmd_enum_new << "";

#if 0
    if(is_syscall) { // begin conditional compilation for user entry stubs
      *header << "#ifndef __NEXUSKERNEL__\n";
    }
#endif

    bool is_first = true;
    string last_new = "";
    string last_inherited = "";
    string starting_ordinal;
    if(generateImplements) {
      starting_ordinal = interfaceLastOrdinal(idl->implements_ns);
    } else {
      starting_ordinal = "0";
    }
    FOREACH_ASTLIST_NC(Interface, ilist->list, iter) {
      stringBuilder curr_arg_struct(1024);
      Interface *i = iter.data();
      Interface **parent_interface = NULL;
      
      if( !generateImplements || 
	  (generateImplements && (parent_interface = sub_interface_map->find(idl->implements_ns & "_" & interfaceName(i))) == NULL) ) {
	string ord_str = interfaceCommandOrdinal(i);
	cmd_enum_new << "	" << ord_str << 
	  ( is_first ? rostring(" = ") & starting_ordinal : "")
		     << ",\n";
	is_first = false;
	last_new = ord_str;
      } else {
	string ord_str = interfaceCommandOrdinal(i);
	(*parent_interface)->implemented = true;
	cmd_enum_inherited << "	" << ord_str << " = " << interfaceCommandOrdinal_qualified(syscall_decl->implements_ns, i) <<",\n";
	last_inherited = ord_str;
      }
      curr_arg_struct << "struct " << interfacePStructName(i) << " {\n";
      curr_arg_struct << interfacePStructMembersService(i);
      curr_arg_struct << "} __attribute__((packed));\n\n";

      curr_arg_struct << "struct " << interfaceRStructName(i) << " {\n";
      curr_arg_struct << "	int resultCode;\n";
      if(!interfaceReturnTypeIsVoid(i)) {
	curr_arg_struct << "	" << interfaceReturnTypeName(i) << " rv;\n";
      }
      curr_arg_struct << "} __attribute__((packed));\n\n";

      // curr_arg_struct << "XXX RETURN VALUE STRUCT GOES HERE\n";

      *header << interfaceCallerPrototype(i) << ";\n";
      *header << interfaceCallerExtPrototype(i) << ";\n";
      *header << interfaceCallerGenericPrototype(i) << ";\n";
      *header << interfaceCallerAsyncPrototype(i) << ";\n";

      stringBuilder auto_init(128);
      auto_init << "if(!" << clientInitializedVar << ") {\n";
      auto_init << "	/* printf_failsafe(\"lazy binding of " << ns.toString() << "\\n\"); */ \n";
      auto_init << "	" << client_init_call << ";\n";
      auto_init << "}\n";

      *client << interfaceCallerPrototype(i) << "{\n";
      if(!is_syscall) {
	*client << auto_init;
      }
      stringBuilder extra_args(1024);
      extra_args << "";
      if(paramList_hasElements(interfaceParams(i))) {
	extra_args << ", " << paramList_toStringAsArgs("", interfaceParams(i));
      }
      stringBuilder ext_args(1024);
      ext_args << service_connection_handle() << extra_args;

      
      *client << "	return " << interfaceCallerExtName(i) << "(" << ext_args << ");\n";
      *client << "}\n";

      *client << interfaceCallerAsyncPrototype(i) << "{\n" 
	      << ( !is_syscall ? auto_init : "" )
	      << "	return " << interfaceCallerGenericName(i)
	      << "(1," << ext_args << ");\n"
	      << "}\n";

      *client << interfaceCallerExtPrototype(i) << "{\n"
	      << "	return " << interfaceCallerGenericName(i)
	      << "(0," << target_service_connection_handle() << extra_args <<  ");\n"
	      << "}\n";

      *client << interfaceCallerGenericPrototype(i) << "{\n";

      // First handle transfer blocks, including necessary changes to varlen
      int count = FIRST_ARG_DESCNUM;
      stringBuilder descs;
      struct {
	FakeList<ASTTypeId> *list;
	string access_flag;
      } *tab, table[2] = { { i->inputParams, "IPC_READ" },
			   { i->outputParams, "IPC_WRITE" } };
      descs << "{\n"
	"	.access = IPC_WRITE,\n"
	"	.u.direct.base = (unsigned int)&rbuf,\n"
	"	.u.direct.length = rbuf_len,\n"
	"}, \n";

      for(unsigned int j=0; j < sizeof(table) / sizeof(table[0]); j++) {
	tab = &table[j];
	FAKELIST_FOREACH_NC(ASTTypeId, tab->list, param) {
	  string arg_name = param_name(*param);
	  if(!param_isVarLen(*param)) {
	    continue;
	  }
	  if(param->direction == BUILTIN) {
	    descs << "// Skipping builtin " << arg_name << "\n";
	    continue;
	  }
	  descs << "	{ .access = " << tab->access_flag <<
	    ", .u.direct.base = (unsigned int) " << arg_name << ".data" <<
	    ", .u.direct.length = " << arg_name << ".len }, \n";

	  *client << "	" << arg_name << ".desc_num = " << count << ";\n";
	  count++;
	}
      }
      if(count > MAX_TRANSFERDESCS) {
	cerr << "Too many transfer descriptors!\n";
	exit(-1);
      }
      string descs_arg;
      if(!i->bareCall) {
	*client << "	const int num_descs = " << count <<";\n";
      }

      // Marshall code for arguments
      *client << "	char __marshall[" <<
	"sizeof(int) + sizeof(struct " << interfacePStructName(i) << ")]; // XXX SUPPORT VARIABLE LENGTH \n";
      *client << "	int __len = 0;\n";
      *client << "	struct " << interfaceRStructName(i) << " rbuf;\n";
      *client << "	int rbuf_len = sizeof(rbuf);\n";
      *client << "	if(is_async) {\n"
	"		memset(&rbuf, 0xff, sizeof(rbuf));\n"
	"		rbuf_len = 0;\n"
	"	}";

      if(!i->bareCall) {
	if(count > 0) {
	  *client << "	struct TransferDesc descs[] = {\n";
	  *client << "	" << descs;
	  *client << "	};\n";
	  descs_arg = "descs";
	} else {
	  descs_arg = "NULL";
	}
      }

      *client << "	*(int*)__marshall = " << interfaceCommandOrdinal(i) << ";\n";
      *client << paramList_marshallService(interfaceAllParams(i), "&rbuf", rostring("((struct ") & interfacePStructName(i) & rostring("*)(__marshall + sizeof(int)))"), "__len") << "\n";
      *client << "	int call_result_code;\n";

      if(!is_syscall) {
	*client << "	assert(!IS_SYSCALL_IPC_CONNECTION_HANDLE(" << target_service_connection_handle() <<"));\n";
      }
      if(!i->bareCall) {
	stringBuilder invoke_args(128);
	invoke_args << target_service_connection_handle() << ", " << "__marshall, __len + sizeof(int), " << descs_arg << ", num_descs";
	if(is_syscall) {
	  *client << "	call_result_code = IPC_InvokeSys(" << invoke_args << ");\n";
	  *client << "	if(is_async) { assert(0); }\n";
	} else {
	  *client << "	if(!is_async) {\n";
	  *client << "		call_result_code = IPC_Invoke(" << invoke_args << ");\n";
	  *client << "	} else {\n";
	  *client << "		call_result_code = IPC_AsyncSend(" << invoke_args << ");\n";
	  *client << "	}\n";
	}
      } else {
	// This code must match IPC.sc:IPC_fromIS()
	*client << "	call_result_code = nexuscall2(" << 
	  interfaceCommandOrdinal(i) << 
	  ", (int)__marshall, (int)(char *)&rbuf);\n";
      }
      *client << "	if(call_result_code < 0 || is_async) {\n";
      *client << "              /* printf(\"call_result_code=%d %s:%d\\n\", call_result_code,__FILE__,__LINE__); */ \n";
      if(i->genErrno) {
	*client << "		" << errno_name << " = call_result_code;\n";
      }
      if(!interfaceReturnTypeIsVoid(i)) {
	*client << RETURN_NONVOID_ERROR;
      } else {
	*client << "		return;\n";
      }
      *client << "	}\n";
      *client << "	\n";
      *client << "	if(rbuf_len < sizeof(int)) goto rval_len_error;\n";
      *client << "	if(rbuf.resultCode == INTERFACE_LABELREJECT) {\n";
      *client << "		printf(\"Client received label reject from %d %s:%d\\n\", " << target_service_connection_handle() << ",__FILE__,__LINE__);\n";
      if(i->genErrno) {
	*client << "		" << errno_name << " = rbuf.resultCode;\n";
      }
      if(!interfaceReturnTypeIsVoid(i)) {
	*client << RETURN_NONVOID_ERROR;
      } else {
	*client << "		return;\n";
      }
      *client << "	}\n";
      *client << "	if(rbuf.resultCode == INTERFACE_INTERPOSEDROP) {\n";
      *client << "		printf(\"Interposition dropped IPC\\n\");\n";
      if(i->genErrno) {
	*client << "		" << errno_name << " = rbuf.resultCode;\n";
      }
      if(!interfaceReturnTypeIsVoid(i)) {
	*client << RETURN_NONVOID_ERROR;
      } else {
	*client << "		return;\n";
      }
      *client << "	}\n";
      *client << "	\n";
      *client << "	if(rbuf_len != sizeof(rbuf)) {\n";
      *client << "	rval_len_error: printf(\"Incorrect return value length!\\n\");\n";
      *client << "		// XXX Better error handling;\n";
      *client << "	}\n";
      if(i->genErrno) {
	*client << "	" << errno_name << " = rbuf.resultCode;\n";
      }
      if(!interfaceReturnTypeIsVoid(i)) {
	*client << "	return rbuf.rv; // XXX Handle more complex return values\n";
      } else {
	*client << "	return;\n";
      }
      *client << "}\n\n";

      // Processor code
      outerSwitchCases << "	case " << interfaceCommandOrdinal(i) << ":\n";
      processor << "	case " << interfaceCommandOrdinal(i) << ": {\n";
      if(is_syscall) {
	processor << "	nexusthread_set_syscall_num(caller_thread, " << interfaceCommandOrdinal(i) << ");\n";
      }

      processor << "	const char *funcname;\n"
	"	funcname = \"" << interfaceCommandOrdinal(i) << "\";\n";
      processor << paramList_unmarshallService(interfaceAllParams(i), rostring("((struct ") & interfacePStructName(i) & rostring(" *) inBuf)"), "dataLen", "break");

      string rvassign;
      if(interfaceReturnTypeIsVoid(i)) {
	rvassign = "";
      } else {
	rvassign = "rbuf.rv = ";
      }
      string args;
      if(!generateInterpose) {
	args = rostring("ipd_id, call_handle, dataBuf, ") & is_async;
      } else {
	processor << "	enum InterposeHowHandled howHandled = DID_NORMALRETURN;\n";
	args = "ipd_id, call_handle, event_info, call_info, &howHandled";
      }
      processor << "	struct " << interfaceRStructName(i) << " rbuf;\n";
      processor << "		rbuf.resultCode = INTERFACE_SUCCESS;\n";
      string callee;
      if(!generateInterpose) {
	callee = interfaceCalleeName(i);
      } else {
	callee = interposeCallName(i);
      }
      processor << " 		" << rvassign << callee << "(" << args;
      if(paramList_hasElements(interfaceParams(i))) {
	processor << ", " << paramList_toStringAsArgs("", interfaceParams(i)) << ");\n";
      } else {
	processor << ");\n";
      }

      if(generateInterpose) {
	processor << "	switch(howHandled) {\n";
	processor << "	case ALREADYRETURNED:\n";
	processor << "	case DID_PASSTHROUGH:\n";
	processor << "		break;\n";
	processor << "	default: \n";
	processor << "		printf(\"Unknown howHandled type\\n\");\n";
	processor << "	case DID_NORMALRETURN: ; \n";
	processor << "		";
	processor << gen_IPC_Return(false, 
				    is_async, ack_async,
				    "call_handle",
				    "(char *)&rbuf",
				    "sizeof(rbuf)") << ";\n";
	//, (char *)&rbuf, sizeof(rbuf)
	//processor << "	IPC_CallReturn(event_port_handle, call_handle);\n";
	processor << "	}";
      } else {
	if(i->genReturn) {
	  processor << "		" << 
	    gen_IPC_Return(is_syscall, 
			   is_async, ack_async,
			   "call_handle", 
			   "(char *)&rbuf", 
			   "sizeof(rbuf)") << ";\n";
	} else {
	  processor << "		/* return not generated */\n";
	}
      }
      processor << "		break;\n";
      processor << "	}\n";

      arg_structs << curr_arg_struct;
    }

#if 0
    if(is_syscall) { // end conditional compilation for user entry stubs
      *header << "#endif // __NEXUSKERNEL__\n";
    }
#endif

    if(is_syscall) {
      *header << "#ifdef __NEXUSKERNEL__\n";
      *header << serverExports;
      *header << "#endif // __NEXUSKERNEL__\n";
    }

      

    if(!is_syscall) {
#if 0
      *header << "///// COMMANDS\n" << 
	"enum " << ns.toString() << "_Commands {\n" <<
	"// Inherited\n " <<
      		cmd_enum_inherited <<"\n" <<
	"// New\n " <<
	      "// Disabled: add manually to syscall-defs.h\n" /*	cmd_enum_new << */
	"\n}; // " << ns.toString() << "\n"
	<< "\n\n";
      string last;
      if(last_new != "") {
	last = last_new;
      } else {
	last =last_inherited;
      }

      *header << "#define " << interfaceLastOrdinal(ns.toString()) << " (" << 
	last << " + 1)\n\n";
#else
      // only generate inherited labels RamFS_.. from FS_..
      // new labels must be declared explicitly, with unique IDs, in syscall-defs.h,
      // so that they can serve as operation IDs in access control
      if (last_inherited != "") {
	      *header << "///// COMMANDS\n" << 
		"enum " << ns.toString() << "_Commands {\n" <<
		"// Inherited\n " <<
			cmd_enum_inherited <<"\n" <<
		"\n}; // " << ns.toString() << "\n"
		<< "\n\n";
      }
#endif
    }
    *header << arg_structs;

    //// PROCESSOR

    bool output_fork = false;
    if(!generateInterpose) {
      string proto;
      string extproto;
      if (is_syscall || gen_kernel()) {
	proto = rostring("int ") & serviceProcessorName() & rostring("(ServerProcessorType type, KernelServerProcessorData data)");
	*server << proto << " {\n";
      } else {
	output_fork = true;
	proto = rostring("int ") & serviceProcessorName() & rostring("(void)");
	string extname = serviceProcessorName() & "_ext";
	extproto = rostring("int ") & extname & rostring("(ServerProcessorType type, Port_Handle server_port_handle, ServerProcessorData data)");
	*server << extproto << ";\n";
	*server << proto << " {\n" <<
	  "	return " << extname << "(SERVERPROCESSOR_SYNC, DEFAULT_PROCESSOR_HANDLE, ((ServerProcessorData ) { .is_forked = NULL }));\n"<<
	"}\n";
	*server << extproto << " {\n";
      }
      
      *header << "struct ForkedInfo;\n";
      *header << proto << ";\n";

      if(extproto != string("")) {
	*header << extproto << ";\n";
      }      
    } else {
      *server << interposeProcessorPrototype() << " {\n"
	"	assert(type != SERVERPROCESSOR_SYNC_FORK && \n"
	"		type != SERVERPROCESSOR_ASYNC_AUTO_DONE);\n\n";
      *interposeHeader << interposeProcessorPrototype() << ";\n";
    }

    // XXX syscall does not need extra copy!
    int buf_len;
    if(is_syscall && !generateInterpose) {
      buf_len = 128;
    } else {
      buf_len = 1024;
    }
    *server << "	char dataBuf["<< buf_len << "]; /* XXX Make this variable length */\n";
    *server << "	int max_dataLen = "<< buf_len << ";\n";
    *server << "	int dataLen = max_dataLen;\n";
    if(!generateInterpose) {
      *server << "	IPD_ID ipd_id;\n";
      *server << "\n";
      string call_head = 
	"	Call_Handle call_handle;\n"
	"	CallDescriptor cdesc;\n",
	call_tail = 
	"	call_handle = (call_result == 0 ? cdesc.call_handle : call_result);\n"
	"	ipd_id = cdesc.ipd_id;\n";
      
      if (is_syscall || gen_kernel()) {
	*server << call_head 
		<< "	assert(type == SERVERPROCESSOR_SYNC);\n"
		<< "	int call_result;\n"
		<< "	BasicThread *caller_thread = data.caller_thread;\n"
		<<"	call_result = IPC_RecvCall((__u32)caller_thread, dataBuf, &dataLen, &cdesc);\n"
		<< call_tail;
      } else {
	*server << call_head 
		<< "	int call_result;\n" 
		<< "	Port_Handle service_port_handle = (server_port_handle != DEFAULT_PROCESSOR_HANDLE) ? server_port_handle : " << service_port_handle() << ";\n"
	        << "call_result = IPC_RecvCall(service_port_handle, dataBuf, &dataLen, &cdesc);\n"
		<< "if (call_result < 0) return call_result;\n"
	        << call_tail;
	}
    } else {
      *server << "\n";
      *server << "	dataLen = message.len;\n";
      *server << "	if(dataLen > max_dataLen) {\n";
      *server << "		printf(\"excess data len\\n\");\n";
      *server << "		return -1;\n";
      *server << "	}\n";
      *server << "	if(IPC_TransferFrom(call_handle, message.desc_num, dataBuf, 0, dataLen) != 0) {\n";
      *server << "		printf(\"message transfer error\\n\");\n";
      *server << "		return -1;\n";
      *server << "	}\n";
    }
    *server << "	if(dataLen < sizeof(int)) {\n";
    *server << "		printf(\"IPC does not contain command ordinal\\n\");\n";
    *server << "		return -1;\n";
    *server << "	}\n";
    *server << "	dataLen -= sizeof(int);\n";
    *server << "\n";
    *server << "	char *inBuf = dataBuf + sizeof(int);\n";
    *server << "	switch(*(int *)dataBuf) {\n";
    *server << processor;

    fastSyscallProcessor << interfaceSyscallProcessorPrototype() << "{\n" <<
      "	char *inBuf = dataBuf + sizeof(int);\n" <<
      "	const IPD_ID ipd_id = -1;\n" <<
      "	const Call_Handle call_handle = CALLHANDLE_SYSCALL;\n" <<
      "	BasicThread *caller_thread = nexusthread_self();\n" <<
      "	switch(*(int *)dataBuf) {\n" <<
      		processor << 
      "	}\n" <<
      "}\n\n";

    if(generateImplements) {
      std::vector<Interface*> v = sub_interface_map->toVector();
      for(unsigned int i = 0; i < v.size(); i++) {
	string code = interfaceCommandOrdinal_qualified(syscall_decl->implements_ns,  v[i]);
	if(!v[i]->implemented) {
	  *server << "case " << code << ": {\n" <<
	    "	printf(\"Unimplemented call code " << code << "\\n\");\n" <<
	    "	struct " << interfaceRStructName(v[i]) << " rbuf;\n" <<
	    "	memset(&rbuf, 0xff, sizeof(rbuf));\n" <<
	    "	rbuf.resultCode = INTERFACE_NOSUCHMETHOD;\n" <<
	    gen_IPC_Return(is_syscall, 
			   is_async, ack_async,
			   "call_handle", 
			   "(char *)&rbuf", 
			   "sizeof(rbuf)") << ";\n" <<
	    "	break;\n" <<
	    "}\n";
	} else {
	  *server << "// " << code << " is implemented\n";
	}
      }
    }
    *server << "	default:\n";
    if(!generateInterpose) {
      *server << "	{\n";
      *server << "		static int print_limit = 0;\n";
      *server << "		if(print_limit < 1) {\n";
      *server << "			print_limit++;\n";
      *server << "			printf(\"%s::%d: Unknown call code %d (%d)\\n\", __FILE__, " << service_port_handle() << ", *(int*)dataBuf, dataLen);\n";
      *server << "			int i;for(i=0; i < ((dataLen < 32) ? dataLen : 32); i++) { printf(\"%02x \", (int)(unsigned char)dataBuf[i]); }\n";
      *server << "		}\n";
      *server << "	}\n";
    } else {
      *server << "		printf(\"No interposition handler for call code %d, or unknown call code\\n\", *(int*)dataBuf);\n";
    }
    *server << "	}\n";
    if(output_fork) {
      *server << "return type == SERVERPROCESSOR_SYNC_FORK ? call_handle : 0;\n";
    } else {
      *server << "return 0;\n";
    }
    *server << "}\n";
  }
public:
  void postvisitServiceIDL(ServiceDecl *syscall_decl) {
    *server << "#include <nexus/ipc.h>\n";
    if(!gen_kernel()) {
      *server << "#include <assert.h>\n";
    }
    *server << "#include <nexus/idl.h>\n\n";
    if(generateInterface) {
      *server << "#include \"" << headerName << "\"\n";
    }
    if(generateInterpose) {
      *server << "#include <nexus/interpose.h>\n";
      FOREACH_ASTLIST_NC(string, idl->interposeIncludeDefnList, iter) {
	*server << *iter.data() << "\n";
      }
    }
    if(generateImplements) {
      FOREACH_ASTLIST_NC(string, idl->implementsIncludeDefnList, iter) {
	*header << *iter.data() << "\n";
      }
    }

    *server << "\n\n";

    if (!gen_kernel()) {
      *client << "#include <stdio.h>\n";
    }
    *server << "#include <nexus/ipc.h>\n";
    if (!gen_kernel()) {
      *server << "#include <nexus/IPC.interface.h>\n";
    }
    *client << "#include <nexus/idl.h>\n\n";
    *client << "#include <nexus/transfer.h>\n\n";
    *client << "#include<nexus/idl-client.h>\n";

    if (gen_kernel()) {
      	*client << "#include \"IPC.interface.h\"\n\n";
      	*client << "#include <nexus/thread-inline.h>\n\n";
    } else {
      	*client << "#include <nexus/IPC.interface.h>\n\n";
    }
    *client << "#include \"" << headerName << "\"\n";
    *client << "\n\n";

    generateGeneric(syscall_decl, "__ipcResultCode", "IS_ASYNC_PROCESSORTYPE(type)", "type == SERVERPROCESSOR_ASYNC_AUTO_DONE");

    /************************************************************/

    *server << "\n\n // Processors and initialization\n";

    {
      stringBuilder serverConstructorBody;
      serverConstructorBody << "	static int initialized;\n";
      serverConstructorBody << "	if(initialized) return;\n";
      serverConstructorBody << "	initialized = 1;\n";

      serverConstructorBody << "	IPC_userInit();\n";
      if(!generateInterpose) {
	serverConstructorBody << "	" << service_port_handle()     << " = IPC_CreatePort(0);\n";
	serverConstructorBody << "      " << service_server_port_num() << " = " << service_port_handle() << ";\n";
      }
      assert(!registerName);
      serverConstructorBody << calleeConstructor << "\n";
      wrapFunction(*server, *header, rostring("void"), rostring(""),
		   ns.toString() & rostring("_serverInit"), serverConstructorBody, rostring(""));
    }

    {
      stringBuilder serverDestructorBody;
      assert(!registerName);
      if(!generateInterpose) {
	serverDestructorBody << "	IPC_DestroyPort(" << service_port_handle() << ");\n";
      }
      serverDestructorBody << calleeDestructor << "\n";

      wrapFunction(*server, *header, rostring("void"), rostring(""),
		   ns.toString() & rostring("_serverDestroy"), serverDestructorBody, rostring(""));
    }
    {
      stringBuilder clientInitConstructor, clientInitSuffix;
      assert(!registerName);
      clientInitConstructor << callerConstructor << "\n";
      clientInitSuffix << "	" << clientInitializedVar << " = 1;\n";

      wrapFunction(*client, *header, rostring("int"), rostring("-INTERFACE_SUCCESS"),
		   ns.toString() & rostring("_clientInit"),
		   clientInitConstructor, clientInitSuffix);
    }

    {
      wrapFunction(*client, *header, rostring("void"), rostring(""),
		   ns.toString() & rostring("_clientDestroy"),
		   callerDestructor, rostring(""));
    }

    if(!generateInterpose) {
      string server_proto = 
	rostring("int ") & ns.toString() & "_setServerTarget(Port_Handle port_handle)";
      *header << server_proto << ";\n";
      *server << server_proto << " {\n" <<
	"	" << ns.toString() << "_port_handle = port_handle;\n" <<
	"	return 0;\n" <<
	"}\n\n";
    }
  }

  void postvisitSyscallIDL(SyscallDecl *syscall_decl) {
    *server << "#include <nexus/defs.h>\n";
    *server << "#include <nexus/machineprimitives.h>\n";
    *server << "#include <nexus/thread.h>\n";
    *server << "#include <nexus/thread-private.h>\n";
    *server << "#include <nexus/syscalls.h>\n";
    *server << "#include <nexus/ipc.h>\n";
    *server << "#include <nexus/ipc_private.h>\n";
    *server << "#include \"IPC.interface.h\"\n";
    *server << "#include \"" << headerName << "\"\n";
    *server << "\n";

    *client << "#include <nexus/syscalls.h>\n";
    *client << "#include \"" << headerName << "\"\n";
    *client << "#include<nexus/idl-client.h>\n";
    *client << "#include <nexus/ipc.h>\n";
    *client << "#include <nexus/IPC.interface.h>\n";
    *client << "\n";

    *header << "#include <nexus/idl.h>\n";

    string errno_name = ns.toString() & rostring("_errno");
    *client << "\n";
    *client << "int __thread ___tls_" << errno_name << "; // This variable depends on TLS initialization\n";
    *client << "int ___shared_" << errno_name << "; \n\n";

    *header << 
      "#ifdef __NEXUSKERNEL__\n"
      "#ifndef printf\n"
      "#define printf(X,...) printk(X, ##__VA_ARGS__)\n"
      "#endif // printf\n"
      "#endif // __NEXUSKERNEL__ \n";

    // *client << "#define printk(X,...) printf(X, ##__VA_ARGS__)\n";
    generateGeneric(syscall_decl, errno_name, "0", "0");

    /***********************************************************/

    string ipc_handler_name = ns.toString() & "_ipc_handler";
    *server << "static void " << ipc_handler_name << "(void *_t) {\n";
    *server << "	" << serviceProcessorName() << "(SERVERPROCESSOR_SYNC, ((KernelServerProcessorData) { .caller_thread = (BasicThread *)_t }));\n";
    *server << "}\n";

    *server << "	IPC_Port *" << syscall_port() << ";\n";

    {
      stringBuilder calleeSuffix;
      calleeSuffix << "	IPC_Port *port = IPCPort_find(" << service_server_port_num() << ");\n";
      calleeSuffix << "	" << syscall_port() << " = port;\n";
      calleeSuffix << "	IPCPort_setKernelHandlers(port, kernelIPD, " << ipc_handler_name <<", kernel_bind_accept_none);\n";
      calleeSuffix << "	IPCPort_makePermanent(port);\n";
      calleeSuffix << "	IPCPort_put(port);\n";
      wrapFunction(*server, *header, rostring("void"), rostring(""), 
		   ns.toString() & rostring("_kernelInit"), rostring(calleeConstructor) & rostring(calleeSuffix), "");
    }
    wrapFunction(*server, *header, rostring("void"), rostring(""), 
		 ns.toString() & rostring("_kernelDestroy"), 
		 calleeDestructor, "");

    wrapFunction(*client, *header, rostring("int"), rostring("0"),
		 ns.toString() & rostring("_userInit"), callerConstructor, "");
    wrapFunction(*client, *header, rostring("void"), rostring(""),
		 ns.toString() & rostring("_userDestroy"), callerDestructor, "");

    *header << "#ifdef __NEXUSKERNEL__\n";
    *header << "extern struct IPC_Port *" << syscall_port() << ";\n";
    *header << "#define PROCESS_" << ns.toString() << "(PORT) \\\n"
      "case SYSCALL_IPCPORT_" << ns.toString() << ": PORT = " << syscall_port() <<	"; break;\n";
    *header << "#endif // __NEXUSKERNEL__\n";

    *header << "#ifndef __NEXUSKERNEL__\n";

    *header << "extern int __errno_use_tls;\n";
    *header << "extern int __thread ___tls_" << errno_name << ";\n";
    *header << "extern int ___shared_" << errno_name << ";\n";
    *header << "#define " << errno_name << 
      " (*({ int *__rv; \\\n"
      "if(__errno_use_tls) { \\\n"
      "	__rv = &___tls_" << errno_name << "; \\\n"
      "} else { \\\n"
      "	__rv = &___shared_" << errno_name << "; \\\n"
      "} \\\n"
      "__rv; \\\n"
      "}))\n\n"
      "#endif // __NEXUSKERNEL__\n";

    // Output code for fast path

    *header << "#ifdef __NEXUSKERNEL__\n";
    *header << "/* Fast case code */\n";
    *header << "#define " << ns.toString() << "_syscallProcessorCases(__args, __arg_len, __result_dest) \\\n";
    *header << 		macroize(outerSwitchCases & "\n" &
	 "	" & interfaceSyscallProcessorName() & "(__args, __arg_len, __result_dest);\n" &
				 "	break;\n") << "\n";
    *header << interfaceSyscallProcessorPrototype() << ";\n";

    *header << "#endif // __NEXUSKERNEL__\n";
    *server << fastSyscallProcessor << "\n";
  }

  virtual void postvisitGenericIDL(GenericIDL *idl) {
    this->idl = idl;
    if(idl->isServiceDecl()) {
      ServiceDecl *sdecl = idl->asServiceDecl();
      postvisitServiceIDL(sdecl);
    } else if(idl->isSyscallDecl()) {
      SyscallDecl *sysdecl = idl->asSyscallDecl();
      postvisitSyscallIDL(sysdecl);
    } else {
      cerr << "Unknown generic idl\n";
      exit(-1);
    }

    *header << "#endif // " << ns.toGuard() << "\n";
    *interposeHeader << "#endif // " << ns.toGuard() << "\n";
    // we're totally done, do some final checks

    if(generateInterpose) {
      std::vector<Interface*> v = sub_interface_map->toVector();
      for(unsigned int i = 0; i < v.size(); i++) {
	if(!v[i]->interposedOn) {
	  cerr << "Not all interfaces interposed on\n";
	  exit(-1);
	}
      }
    }

    StringRef name = ns.popName();
    server->close();
    client->close();
    header->close();
    interposeHeader->close();
    server = NULL;
    client = NULL;
    header = NULL;
    interposeHeader = NULL;

    callerConstructor.clear();
    calleeConstructor.clear();
    callerDestructor.clear();
    calleeDestructor.clear();
    serverStr.clear();
    clientStr.clear();

    if(name != idl->name) {
      cerr << "ERROR! Removing " << name << ", expected " << idl->name << endl;
      exit(-1);
    }
  }
};


void if_malloc_stats()
{
  if (tracingSys("malloc_stats")) {
    malloc_stats();
  }
}


class SectionTimer {
  long start;
  long &elapsed;
  
public:
  SectionTimer(long &e) 
    : start(getMilliseconds()),
      elapsed(e)
  {}
  ~SectionTimer()
  {
    elapsed += getMilliseconds() - start;
  }
};

// print out type annotations for every ast node that has a type
class ToXmlASTVisitor_Types : public ToXmlASTVisitor {
//    ostream &out;                 // for the <Link/> tags
  TypeToXml &ttx;

  public:
  ToXmlASTVisitor_Types
    (TypeToXml &ttx0,
     ostream &out0,
     int &depth0,
     bool indent0 = false,
     bool ensureOneVisit0 = true)
      : ToXmlASTVisitor(out0, depth0, indent0, ensureOneVisit0)
      , ttx(ttx0)
  {}

  // Note that idempotency is handled in TypeToXml
  #define PRINT_ANNOT(A)   \
    if (A) {               \
      ttx.toXml(A); \
    }

  // this was part of the macro
//    printASTBiLink((void**)&(A), (A));

  // print the link between the ast node and the annotating node
//    void printASTBiLink(void **astField, void *annotation) {
//      out << "<__Link from=\"";
//      // this is not from an ast *node* but from the *field* of one
//      xmlPrintPointer(out, "FLD", astField);
//      out << "\" to=\"";
//      xmlPrintPointer(out, "TY", annotation);
//      out << "\"/>\n";
//    }

  // **** visit methods
  bool visitTypeSpecifier(TypeSpecifier *ts) {
    if (!ToXmlASTVisitor::visitTypeSpecifier(ts)) return false;
    if (ts->isTS_type()) {
      PRINT_ANNOT(ts->asTS_type()->type);
    } else if (ts->isTS_name()) {
      PRINT_ANNOT(ts->asTS_name()->var);
      PRINT_ANNOT(ts->asTS_name()->nondependentVar);
    } else if (ts->isTS_elaborated()) {
      PRINT_ANNOT(ts->asTS_elaborated()->atype);
    } else if (ts->isTS_classSpec()) {
      PRINT_ANNOT(ts->asTS_classSpec()->ctype);
    } else if (ts->isTS_enumSpec()) {
      PRINT_ANNOT(ts->asTS_enumSpec()->etype);
    }
    return true;
  }

  bool visitFunction(Function *f) {
    if (!ToXmlASTVisitor::visitFunction(f)) return false;
    PRINT_ANNOT(f->funcType);
    PRINT_ANNOT(f->receiver);
    return true;
  }

  bool visitMemberInit(MemberInit *memberInit) {
    if (!ToXmlASTVisitor::visitMemberInit(memberInit)) return false;
    PRINT_ANNOT(memberInit->member);
    PRINT_ANNOT(memberInit->base);
    PRINT_ANNOT(memberInit->ctorVar);
    return true;
  }

  bool visitBaseClassSpec(BaseClassSpec *bcs) {
    if (!ToXmlASTVisitor::visitBaseClassSpec(bcs)) return false;
    PRINT_ANNOT(bcs->type);
    return true;
  }

  bool visitDeclarator(Declarator *d) {
    if (!ToXmlASTVisitor::visitDeclarator(d)) return false;
    PRINT_ANNOT(d->var);
    PRINT_ANNOT(d->type);
    return true;
  }

  bool visitExpression(Expression *e) {
    if (!ToXmlASTVisitor::visitExpression(e)) return false;
    PRINT_ANNOT(e->type);
    if (e->isE_this()) {
      PRINT_ANNOT(e->asE_this()->receiver);
    } else if (e->isE_variable()) {
      PRINT_ANNOT(e->asE_variable()->var);
      PRINT_ANNOT(e->asE_variable()->nondependentVar);
    } else if (e->isE_constructor()) {
      PRINT_ANNOT(e->asE_constructor()->ctorVar);
    } else if (e->isE_fieldAcc()) {
      PRINT_ANNOT(e->asE_fieldAcc()->field);
    } else if (e->isE_new()) {
      PRINT_ANNOT(e->asE_new()->ctorVar);
    }
    return true;
  }

  #ifdef GNU_EXTENSION
  bool visitASTTypeof(ASTTypeof *a) {
    if (!ToXmlASTVisitor::visitASTTypeof(a)) return false;
    PRINT_ANNOT(a->type);
    return true;
  }
  #endif // GNU_EXTENSION

  bool visitPQName(PQName *pqn) {
    if (!ToXmlASTVisitor::visitPQName(pqn)) return false;
    if (pqn->isPQ_qualifier()) {
      PRINT_ANNOT(pqn->asPQ_qualifier()->qualifierVar);
      ttx.toXml(&(pqn->asPQ_qualifier()->sargs));
    } else if (pqn->isPQ_template()) {
      ttx.toXml(&(pqn->asPQ_template()->sargs));
    } else if (pqn->isPQ_variable()) {
      PRINT_ANNOT(pqn->asPQ_variable()->var);
    }
    return true;
  }

  bool visitEnumerator(Enumerator *e) {
    if (!ToXmlASTVisitor::visitEnumerator(e)) return false;
    PRINT_ANNOT(e->var);
    return true;
  }

  bool visitInitializer(Initializer *e) {
    if (!ToXmlASTVisitor::visitInitializer(e)) return false;
    if (e->isIN_ctor()) {
      PRINT_ANNOT(e->asIN_ctor()->ctorVar);
    }
    return true;
  }

  // FIX: TemplateParameter

  #undef PRINT_ANNOT
};


void handle_xBase(Env &env, xBase &x)
{
  // typically an assertion failure from the tchecker; catch it here
  // so we can print the errors, and something about the location
  env.errors.print(cerr);
  cerr << x << endl;
  cerr << "Failure probably related to code near " << env.locStr() << endl;

  // print all the locations on the scope stack; this is sometimes
  // useful when the env.locStr refers to some template code that
  // was instantiated from somewhere else
  //
  // (unfortunately, env.instantiationLocStack isn't an option b/c
  // it will have been cleared by the automatic invocation of
  // destructors unwinding the stack...)
  cerr << "current location stack:\n";
  cerr << env.locationStackString();

  // I changed from using exit(4) here to using abort() because
  // that way the multitest.pl script can distinguish them; the
  // former is reserved for orderly exits, whereas signals (like
  // SIGABRT) mean that something went really wrong
  abort();
}


// this is a dumb way to organize argument processing...
char *myProcessArgs(int argc, char **argv, char const *additionalInfo)
{
  // remember program name
  char const *progName = argv[0];

  // process args
  while (argc >= 2) {
    if (traceProcessArg(argc, argv)) {
      continue;
    }
    else if (0==strcmp(argv[1], "-xc")) {
      // treat this as a synonym for "-tr c_lang"
      traceAddSys("c_lang");
      argv++;
      argc--;
    }
    else if (0==strcmp(argv[1], "-w")) {
      // synonym for -tr nowarnings
      traceAddSys("nowarnings");
      argv++;
      argc--;
    }
	else if (0==strcmp(argv[1], "-k")) {
		traceAddSys("target_kernel");
		argv++;
		argc--;
	}
	else if (0==strcmp(argv[1], "-print_parents")) {
		traceAddSys("output_specified"); // disables all output
		traceAddSys("print_parents"); // print interpose_on/implements names
		argv++;
		argc--;
	}
	else if (0==strcmp(argv[1], "-print_includes")) {
		traceAddSys("output_specified"); // disables all output
		traceAddSys("print_includes"); // print idl-related includes
		argv++;
		argc--;
	}
	else if (0==strcmp(argv[1], "-make")) {
		traceAddSys("output_specified");
		char *s = strdup(argv[2]);
		char *delim = ",";
		for (s = strtok(s, delim); s != NULL; s = strtok(NULL, delim)) {
			int l = strlen(s);
			if (l >= 3 && s[l-2] == '.' && (s[l-1] == 'c' || s[l-1] == 'h')) {
				traceAddSys(s);
				//cerr << "info: making '" << s << "'\n";
			} else {
				cerr << "error: unrecognized '-make' parameter: '" << s << "'\n";
				exit(2);
			}
		}
		argv += 2;
		argc -= 2;
	}
    else {
      break;     // didn't find any more options
    }
  }

  if (argc != 2) {
    cerr << "usage: " << progName << " [options] input-file\n"
            "  options:\n"
            "    -tr <flags>:       turn on given tracing flags (comma-separated)\n"
			"    -print_parents:    just print the name of parent svc files\n"
			"    -print_includes:   just print the names of included idl headers\n"
            "    -make <outputs>:   generate only outputs (comma-separated list)...\n"
            "        for svc:   interface.h, client.c, server.c\n"
            "        for sc:    interface.h, user.c, kernel.c\n"
            "        for ia:    interpose.c, interpose.h\n"
         << (additionalInfo? additionalInfo : "");
    exit(argc==1? 0 : 2);    // error if any args supplied
  }

  return argv[1];
}

void doit(int argc, char **argv)
{
  // I think this is more noise than signal at this point
  xBase::logExceptions = false;

  traceAddSys("progress");
  //traceAddSys("parse-tree");

  if_malloc_stats();

  SourceLocManager mgr;

  // string table for storing parse tree identifiers
  StringTable strTable;

  // parsing language options
  CCLang lang;
  lang.GNU_Cplusplus();


  // ------------- process command-line arguments ---------
  char const *inputFname = myProcessArgs
    (argc, argv,
     "\n"
     "  general behavior flags:\n"
     "    c_lang             use C language rules (default is C++)\n"
     "    nohashline         ignore #line when reporting locations\n"
     "\n"
     "  options to stop after a certain stage:\n"
     "    stopAfterParse     stop after parsing\n"
     "    stopAfterTCheck    stop after typechecking\n"
     "    stopAfterElab      stop after semantic elaboration\n"
     "\n"
     "  output options:\n"
     "    parseTree          make a parse tree and print that, only\n"
     "    printAST           print AST after parsing\n"
     "    printTypedAST      print AST with type info\n"
     "    printElabAST       print AST after semantic elaboration\n"
     "    prettyPrint        echo input as pretty-printed C++\n"
     "    xmlPrintAST        print AST as XML\n"
     "\n"
     "  debugging output:\n"
     "    malloc_stats       print malloc stats every so often\n"
     "    env                print as variables are added to the environment\n"
     "    error              print as errors are accumulated\n"
     "    overload           print details of overload resolution\n"
     "\n"
     "  (grep in source for \"trace\" to find more obscure flags)\n"
     "");

  outputDir = strdup(dirname(strdup(inputFname)));
  if (!strcmp(outputDir, "."))
	  outputDirPrefix = "";
  else {
	  int n = strlen(outputDir)+1;
	  outputDirPrefix = (char *)malloc(n+1);
	  strcpy(outputDirPrefix, outputDir);
	  outputDirPrefix[n-1] = '/';
	  outputDirPrefix[n] = 0;
  }

  if (tracingSys("printAsML")) {
    Type::printAsML = true;
  }

  if (tracingSys("nohashline")) {
    sourceLocManager->useHashLines = false;
  }

  if (tracingSys("ansi")) {
    lang.ANSI_Cplusplus();
  }

  if (tracingSys("ansi_c")) {
    lang.ANSI_C89();
  }

  if (tracingSys("ansi_c99")) {
    lang.ANSI_C99();
  }

  if (tracingSys("c_lang")) {
    lang.GNU_C();
  }
  
  if (tracingSys("gnu_c89")) {
    lang.ANSI_C89();
    lang.GNU_C_extensions();
  }

  if (tracingSys("gnu_kandr_c_lang")) {
    lang.GNU_KandR_C();
    #ifndef KANDR_EXTENSION
      xfatal("gnu_kandr_c_lang option requires the K&R module (./configure -kandr=yes)");
    #endif
  }

  if (tracingSys("gnu2_kandr_c_lang")) {
    lang.GNU2_KandR_C();
    #ifndef KANDR_EXTENSION
      xfatal("gnu2_kandr_c_lang option requires the K&R module (./configure -kandr=yes)");
    #endif
  }
  
  if (tracingSys("test_xfatal")) {
    xfatal("this is a test error message");
  }

  if (tracingSys("msvcBugs")) {
    lang.MSVC_bug_compatibility();
  }

  if (!tracingSys("nowarnings")) {
    lang.enableAllWarnings();
  }

  if (tracingSys("templateDebug")) {
    // predefined set of tracing flags I've been using while debugging
    // the new templates implementation
    traceAddSys("template");
    traceAddSys("error");
    traceAddSys("scope");
    traceAddSys("templateParams");
    traceAddSys("templateXfer");
    traceAddSys("prettyPrint");
    traceAddSys("xmlPrintAST");
    traceAddSys("topform");
  }
  
  if (tracingSys("only_works_on_32bit") &&
      sizeof(long) != 4) {
    // we are running a regression test, and the testcase is known to
    // fail due to dependence on architecture parameters, so skip it
    cerr << "warning: skipping test b/c this is not a 32-bit architecture\n";
    exit(0);
  }

  // --------------- parse --------------
  TranslationUnit *unit;
  int parseWarnings = 0;
  long parseTime = 0;
  if (tracingSys("parseXml")) {
#if XML
    unit = astxmlparse(strTable, inputFname);
    if (!unit) return;
#else
    cerr << "XML features are not compiled in" << endl;
    exit(1);
#endif // XML
  }
  else {
    SectionTimer timer(parseTime);
    SemanticValue treeTop;
    ParseTreeAndTokens tree(lang, treeTop, strTable, inputFname);
    
    // grab the lexer so we can check it for errors (damn this
    // 'tree' thing is stupid..)
    Lexer *lexer = dynamic_cast<Lexer*>(tree.lexer);
    xassert(lexer);

    CCParse *parseContext = new CCParse(strTable, lang);
    tree.userAct = parseContext;

    traceProgress(2) << "building parse tables from internal data\n";
    ParseTables *tables = parseContext->makeTables();
    tree.tables = tables;

    maybeUseTrivialActions(tree);

    if (tracingSys("parseTree")) {
      // make some helpful aliases
      LexerInterface *underLexer = tree.lexer;
      UserActions *underAct = parseContext;

      // replace the lexer and parser with parse-tree-building versions
      tree.lexer = new ParseTreeLexer(underLexer, underAct);
      tree.userAct = new ParseTreeActions(underAct, tables);

      // 'underLexer' and 'tree.userAct' will be leaked.. oh well
    }

    if (!toplevelParse(tree, inputFname)) {
      exit(2); // parse error
    }

    // check for parse errors detected by the context class
    if (parseContext->errors || lexer->errors) {
      exit(2);
    }
    parseWarnings = lexer->warnings + parseContext->warnings;

    if (tracingSys("parseTree")) {
      // the 'treeTop' is actually a PTreeNode pointer; print the
      // tree and bail
      PTreeNode *ptn = (PTreeNode*)treeTop;
      ptn->printTree(cerr, PTreeNode::PF_EXPAND);
      return;
    }

    // treeTop is a TranslationUnit pointer
    unit = (TranslationUnit*)treeTop;

    //unit->debugPrint(cerr, 0);

    delete parseContext;
    delete tables;
  }

  checkHeap();

  // print abstract syntax tree
  if (tracingSys("printAST")) {
    unit->debugPrint(cerr, 0);
  }

  //if (unit) {     // when "-tr trivialActions" it's NULL...
  //  cerr << "ambiguous nodes: " << numAmbiguousNodes(unit) << endl;
  //}

  if (tracingSys("stopAfterParse")) {
    return;
  }


  // ---------------- typecheck -----------------
  BasicTypeFactory tfac;
  long tcheckTime = 0;
  if (tracingSys("no-typecheck")) {
    cerr << "warning: no-typecheck" << endl;
  } else {
    SectionTimer timer(tcheckTime);
    Env env(strTable, lang, tfac, unit);
    try {
      env.tcheckTranslationUnit(unit);
    }
    catch (XUnimp &x) {
      HANDLER();

      // relay to handler in main()
      cerr << "in code near " << env.locStr() << ":\n";
      throw;
    }
    catch (x_assert &x) {
      HANDLER();
      
      if (env.errors.hasFromNonDisambErrors()) {
        if (tracingSys("expect_confused_bail")) {
          cerr << "got the expected confused/bail\n";
          exit(0);
        }

        // The assertion failed only after we encountered and diagnosed
        // at least one real error in the input file.  Therefore, the
        // assertion might simply have been caused by a failure of the
        // error recovery code to fully restore all invariants (which is
        // often difficult).  So, we'll admit to being "confused", but
        // not to the presence of a bug in Elsa (which is what a failed
        // assertion otherwise nominally means).
        //
        // The error message is borrowed from gcc; I wouldn't be
        // surprised to discover they use a similar technique to decide
        // when to emit the same message.
        //
        // The reason I do not put the assertion failure message into
        // this one is I don't want it showing up in the output where
        // Delta might see it.  If I am intending to minimize an assertion
        // failure, it's no good if Delta introduces an error.
        env.error("confused by earlier errors, bailing out");
        env.errors.print(cerr);
        exit(4);
      }

      if (tracingSys("expect_xfailure")) {
        cerr << "got the expected xfailure\n";
        exit(0);
      }

      // if we don't have a basis for reducing severity, pass this on
      // to the normal handler
      handle_xBase(env, x);
    }
    catch (xBase &x) {
      HANDLER();
      handle_xBase(env, x);
    }

#if 0
    int numErrors = env.errors.numErrors();
    int numWarnings = env.errors.numWarnings() + parseWarnings;
#endif

#if 0 // skip a lot of analyses
    // do this now so that 'printTypedAST' will include CFG info
    #ifdef CFG_EXTENSION
    // A possible TODO is to do this right after each function is type
    // checked.  However, in the current design, that means physically
    // inserting code into Function::tcheck (ifdef'd of course).  A way
    // to do it better would be to have a general post-function-tcheck
    // interface that analyses could hook in to.  That could be augmented
    // by a parsing mode that parsed each function, analyzed it, and then
    // immediately discarded its AST.
    if (numErrors == 0) {
      numErrors += computeUnitCFG(unit);
    }
    #endif // CFG_EXTENSION

    // print abstract syntax tree annotated with types
    if (tracingSys("printTypedAST")) {
      unit->debugPrint(cerr, 0);
    }

    // structural delta thing
    if (tracingSys("structure")) {
      structurePrint(unit);
    }

    if (numErrors==0 && tracingSys("secondTcheck")) {
      // this is useful to measure the cost of disambiguation, since
      // now the tree is entirely free of ambiguities
      traceProgress() << "beginning second tcheck...\n";
      Env env2(strTable, lang, tfac, unit);
      unit->tcheck(env2);
      traceProgress() << "end of second tcheck\n";
    }

    // print errors and warnings
    env.errors.print(cerr);

    cerr << "typechecking results:\n"
         << "  errors:   " << numErrors << "\n"
         << "  warnings: " << numWarnings << "\n";

    if (numErrors != 0) {
      exit(4);
    }

    // lookup diagnostic
    if (env.collectLookupResults.length()) {
      // scan AST
      NameChecker nc;
      nc.sb << "collectLookupResults";
      unit->traverse(nc);

      // compare to given text
      if (streq(env.collectLookupResults, nc.sb)) {
        // ok
      }
      else {
        cerr << "collectLookupResults do not match:\n"
             << "  source: " << env.collectLookupResults << "\n"
             << "  tcheck: " << nc.sb << "\n"
             ;
        exit(4);
      }
    }
  }

  // ---------------- integrity checking ----------------
  long integrityTime = 0;
  {
    SectionTimer timer(integrityTime);

    // check AST integrity
    IntegrityVisitor ivis;
    unit->traverse(ivis);

    // check that the AST is a tree *and* that the lowered AST is a
    // tree; only do this *after* confirming that tcheck finished
    // without errors
    if (tracingSys("treeCheck")) {
      long start = getMilliseconds();
      LoweredIsTreeVisitor treeCheckVisitor;
      unit->traverse(treeCheckVisitor.loweredVisitor);
      traceProgress() << "done with tree check 1 ("
                      << (getMilliseconds() - start)
                      << " ms)\n";
    }

    // check an expected property of the annotated AST
    if (tracingSys("declTypeCheck") || getenv("declTypeCheck")) {
      DeclTypeChecker vis;
      unit->traverse(vis.loweredVisitor);
      cerr << "instances of type != var->type: " << vis.instances << endl;
    }

    if (tracingSys("stopAfterTCheck")) {
      return;
    }
  }

  // ----------------- elaboration ------------------
  long elaborationTime = 0;
  if (!lang.isCplusplus || tracingSys("no-elaborate")) {
    cerr << "no-elaborate" << endl;
  } 
  else {
    SectionTimer timer(elaborationTime);

    // do elaboration
    ElabVisitor vis(strTable, tfac, unit);

    // if we are going to pretty print, then we need to retain defunct children
    if (tracingSys("prettyPrint")
        // dsw: I don't know if this is right, but printing the xml
        // AST kind of resembles pretty-printing the AST; fix this if
        // it is wrong
        || tracingSys("xmlPrintAST")
        ) {
      vis.cloneDefunctChildren = true;
    }

    unit->traverse(vis.loweredVisitor);

    // print abstract syntax tree annotated with types
    if (tracingSys("printElabAST")) {
      unit->debugPrint(cerr, 0);
    }
    if (tracingSys("stopAfterElab")) {
      return;
    }
  }

  // more integrity checking
  {
    SectionTimer timer(integrityTime);

    // check that the AST is a tree *and* that the lowered AST is a
    // tree (do this *after* elaboration!)
    if (tracingSys("treeCheck")) {
      long start = getMilliseconds();
      LoweredIsTreeVisitor treeCheckVisitor;
      unit->traverse(treeCheckVisitor.loweredVisitor);
      traceProgress() << "done with tree check 2 ("
                      << (getMilliseconds() - start)
                      << " ms)\n";
    }
  }

  // dsw: pretty printing
  if (tracingSys("prettyPrint")) {
    traceProgress() << "dsw pretty print...\n";
    OStreamOutStream out0(cerr);
    CodeOutStream codeOut(out0);
    TypePrinterC typePrinter;
    PrintEnv env(typePrinter, &codeOut);
    cerr << "---- START ----" << endl;
    cerr << "// -*-c++-*-" << endl;
    unit->print(env);
    codeOut.finish();
    cerr << "---- STOP ----" << endl;
    traceProgress() << "dsw pretty print... done\n";
  }



  // dsw: xml printing of the lowered ast
//    if (tracingSys("xmlPrintLoweredAST")) {
//  #if XML
//      traceProgress() << "dsw xml print...\n";
//      bool indent = tracingSys("xmlPrintLoweredAST-indent");
//      ToXmlASTVisitor xmlVis(cerr, indent);
//      LoweredASTVisitor loweredXmlVis(&xmlVis);
//      // FIX: do type visitor
//      cerr << "---- START ----" << endl;
//      unit->traverse(loweredXmlVis);
//      cerr << endl;
//      cerr << "---- STOP ----" << endl;
//      traceProgress() << "dsw xml print... done\n";
//  #else
//      cerr << "XML features are not compiled in" << endl;
//      exit(1);
//  #endif // XML
//    }

  // test AST cloning
  if (tracingSys("testClone")) {
    TranslationUnit *u2 = unit->clone();

    if (tracingSys("cloneAST")) {
      cerr << "------- cloned AST --------\n";
      u2->debugPrint(cerr, 0);
    }

    if (tracingSys("cloneCheck")) {
      // dsw: I hope you intend that I should use the cloned TranslationUnit
      Env env3(strTable, lang, tfac, u2);
      u2->tcheck(env3);

      if (tracingSys("cloneTypedAST")) {
        cerr << "------- cloned typed AST --------\n";
        u2->debugPrint(cerr, 0);
      }

      if (tracingSys("clonePrint")) {
        OStreamOutStream out0(cerr);
        CodeOutStream codeOut(out0);
        TypePrinterC typePrinter;
        PrintEnv penv(typePrinter, &codeOut);
        cerr << "---- cloned pretty print ----" << endl;
        u2->print(penv);
        codeOut.finish();
      }
    }
#endif // skip a lot of analyses
  }

  // test debugPrint but send the output to /dev/null (basically just
  // make sure it doesn't segfault or abort)
  if (tracingSys("testDebugPrint")) {
    ofstream devnull("/dev/null");
    unit->debugPrint(devnull, 0);
  }

  // Dump out the bodies
  IDLTranslatorPassOne pass1;
  unit->traverse(pass1);
  IDLTranslatorPassTwo translate(&pass1);
  unit->traverse(translate);

  /*
  cerr << "parse=" << parseTime << "ms"
       << " tcheck=" << tcheckTime << "ms"
    // << " integ=" << integrityTime << "ms"
    // << " elab=" << elaborationTime << "ms"
       << "\n"
       ;
	   */

  // dsw: xml printing of the raw ast
  if (tracingSys("xmlPrintAST")) {
#if XML
    traceProgress() << "dsw xml print...\n";
    bool indent = tracingSys("xmlPrintAST-indent");
    int depth = 0;              // shared depth counter between printers
    cerr << "---- START ----" << endl;
    if (tracingSys("xmlPrintAST-types")) {
      TypeToXml xmlTypeVis(cerr, depth, indent);
      ToXmlASTVisitor_Types xmlVis_Types(xmlTypeVis, cerr, depth, indent);
      xmlTypeVis.astVisitor = &xmlVis_Types;
      ASTVisitor *vis = &xmlVis_Types;
      LoweredASTVisitor loweredXmlVis(&xmlVis_Types); // might not be used
      if (tracingSys("xmlPrintAST-lowered")) {
        vis = &loweredXmlVis;
      }
      unit->traverse(*vis);
    } else {
      ToXmlASTVisitor xmlVis(cerr, depth, indent);
      ASTVisitor *vis = &xmlVis;
      LoweredASTVisitor loweredXmlVis(&xmlVis); // might not be used
      if (tracingSys("xmlPrintAST-lowered")) {
        vis = &loweredXmlVis;
      }
      unit->traverse(*vis);
    }
    cerr << endl;
    cerr << "---- STOP ----" << endl;
    traceProgress() << "dsw xml print... done\n";
#else
    cerr << "XML features are not compiled in" << endl;
    exit(1);
#endif // XML
  }
  //traceProgress() << "cleaning up...\n";

  //malloc_stats();

  // delete the tree
  // (currently this doesn't do very much because FakeLists are
  // non-owning, so I won't pretend it does)
  //delete unit;

  strTable.clear();

  //checkHeap();
  //malloc_stats();
}

int main(int argc, char **argv)
{
  try {
    doit(argc, argv);
  }
  catch (XUnimp &x) {
    HANDLER();
    cerr << x << endl;

    // don't consider this the same as dying on an assertion failure;
    // I want to have tests in regrtest that are "expected" to fail
    // for the reason that they use unimplemented language features
    return 10;
  }
  catch (XFatal &x) {
    HANDLER();
    
    // similar to XUnimp
    cerr << x << endl;
    return 10;
  }
  catch (xBase &x) {
    HANDLER();
    cerr << x << endl;
    abort();
  }

  //malloc_stats();

  return 0;
}
