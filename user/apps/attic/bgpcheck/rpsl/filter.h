#ifndef FILTER_H
#define FILTER_H

#include <arpa/inet.h>
#include <string>
#include <vector>

#define INF 10000
#define NO_EXPORT 0xFFFFFF01
#define NO_ADVERTISE 0xFFFFFF02

enum NodeType { NODE_OPERATOR, NODE_PREFIX_SET, NODE_PREFIX, NODE_REGEX, NODE_REGEX_ENT,
	NODE_REGEX_AS_SET, NODE_AS, NODE_AS_RANGE, NODE_AS_SET, NODE_ATTR_MATCH, NODE_ATTR_ACTION,
	NODE_ACTION, NODE_INT, NODE_IP, NODE_GENERIC_LIST, NODE_PEERING };

class Node {
public:
  virtual NodeType type(void) const = 0;
  virtual ~Node(void) {};
};


/* OperatorNode: catch-all for simple tokens, often single characters.
 * AND, OR, and NOT all go here. */
#define opr(which, args...) new OperatorNode(which, args)
class OperatorNode : public Node {
public:
	OperatorNode(int which, int argc, ...);
	~OperatorNode(void);
	inline NodeType type(void) const { return NODE_OPERATOR; }
	inline unsigned int nops(void) const { return operands.size(); }
	int op;
	std::vector<Node*> operands;
};

/* ListNodeBase: base class for all list types
 * Instantiate the descendants, below.
 * Used for sets and lists without operators or grouping,
 * like prefix sets and regular expressions */
#define list(T, V) ({T *_l = new T; _l->add(V); _l; })
class ListNodeBase : public Node {
public:
  ~ListNodeBase(void);
  virtual NodeType type(void) const = 0;
  inline void add(Node *node) { data.push_back(node); }
  inline unsigned int size(void) const { return data.size(); }
  inline const Node *operator[] (int n) const { return data[n]; }
private:
  std::vector<Node*> data;
};

template<NodeType T> class ListNodeT : public ListNodeBase {
	inline NodeType type(void) const { return T; }
};

typedef ListNodeT<NODE_GENERIC_LIST> ListNode;
typedef ListNodeT<NODE_PREFIX_SET> PrefixSetNode;
typedef ListNodeT<NODE_REGEX> RegexNode;

/* RegexASSetNode: represents bracketed token sets in a regex,
 * like [AS1 AS2 AS5-AS8]
 * Specialization of ListNode, because we need to know if the set is
 * complemented */
class RegexASSetNode : public ListNodeT<NODE_REGEX_AS_SET> {
public:
	RegexASSetNode(void) : complement(false) {}
	bool complement;
};

/* PrefixNode: stores a prefix and its modifiers, like 1.0.0.0/8^24-28 */
class PrefixNode : public Node {
public:
	PrefixNode(const struct in_addr _base, int _len, int _sub_start, int _sub_end);
  inline NodeType type(void) const { return NODE_PREFIX; }
	struct in_addr base;
	int len, sub_start, sub_end;
};

/* PeeringNode: stores a peering specification: as-expr [rtr] [at rtr] */
class PeeringNode : public Node {
public:
	PeeringNode(Node *_as, struct in_addr _rtr1, struct in_addr _rtr2)
		: as(_as), rtr1(_rtr1), rtr2(_rtr2) {}
	~PeeringNode(void) { delete as; }
  inline NodeType type(void) const { return NODE_PEERING; }
	Node *as;
	struct in_addr rtr1, rtr2;
};

template<class V, NodeType T>
class SimpleNode : public Node {
public:
	SimpleNode(V _data) : data(_data) {}
  inline NodeType type(void) const { return T; }
	V data;
};

/* ASNode: stores an int, representing an AS number */
typedef SimpleNode<int, NODE_AS> ASNode;

/* ASRangeNode: stores a pair of ints, representing a range of AS numbers */
typedef SimpleNode<std::pair<int,int>, NODE_AS_RANGE> ASRangeNode;

/* ASSetNode: stores a string, representing an AS Set name */
typedef SimpleNode<std::string, NODE_AS_SET> ASSetNode;

typedef SimpleNode<int, NODE_INT> IntNode;
typedef SimpleNode<struct in_addr, NODE_IP> IPNode;

/* AttributeMatchNode: represents a boolean function on an attribute
 * e.g., community.contains(7)
 * or    community(NO_EXPORT)
 * or    community == { 1, 2, 3 } */
class AttributeMatchNode : public Node {
public:
	AttributeMatchNode(int _attr_key, int _attr_method, ListNodeBase *_args)
		: attr_key(_attr_key), attr_method(_attr_method), args(_args) {}
	~AttributeMatchNode(void) { delete args; }
  inline NodeType type(void) const { return NODE_ATTR_MATCH; }
	int attr_key, attr_method;
	ListNodeBase *args;
};

/* AttributeActionNode: represents a mutator method for an attribute
 * community = { 1, 2, 3 }
 * pref = 70
 * med = 10
 * aspath.prepend(AS3)
 * community.append(5) */
class AttributeActionNode : public Node {
public:
	AttributeActionNode(int _attr_key, int _attr_method, ListNodeBase *_args)
		: attr_key(_attr_key), attr_method(_attr_method), args(_args) {}
	~AttributeActionNode(void) { delete args; }
  inline NodeType type(void) const { return NODE_ATTR_ACTION; }
	int attr_key, attr_method;
	ListNodeBase *args;
};

/* RegexEntNode: stores one atom of a regex: an AS number, an AS set, a
 * bracketed AS set, or even another AS in parentheses.  Regex atoms are
 * repeatable with '+', '*', or '{N,M}'.  A '~' character sets the uniform
 * flag, meaning that all matched tokens must be the same.  That is,
 * AS-FOO~+ matches one or more identical tokens found in AS-FOO. */
class RegexEntNode : public Node {
public:
	RegexEntNode(Node *_atom, int _min, int _max, bool _uniform=false)
		: atom(_atom), min(_min), max(_max), uniform(_uniform) {}
	~RegexEntNode(void) { delete atom; }
  inline NodeType type(void) const { return NODE_REGEX_ENT; }
	Node *atom;
	int min, max;
	bool uniform;
};

/* Kevin's structure for keeping parser state, particularly error
 * locations. */
struct filter_parse_data {
	Node *f;
	char *errmsg;
	char *errtok;
	int errline;
	int errcol;
	int errcolend;
}; 
extern struct filter_parse_data fpd;

/* Parse a string into a parse tree, the root of which is returned as type
 * Node.  Returns NULL (and prints an error to stdout) on failure.  String
 * passed in may not be preserved?  Deleting the tree is the
 * responsibility of the caller, but it should be as easy as
 *     Node *foo = filter_parse("...");
 *     delete foo;
 * NB: it's perfectly legal to pass filter_parse() a string with newlines
 * and continuation characters (' ', '\t', or '+') in it, straight from an
 * RPSL file.  But don't pass it the actual "Filter: " specifier.
 */
Node *filter_parse(char *c);

/* Print a long, debuggy version of the parse tree */
void filter_print(const Node *node, int indent=1);

/* Print a compact version of the parse tree that should be (almost) legal
 * RPSL.  Parentheses are inserted all over the place to show precedence.
 * Regexes are printed with extra '<' and '>' that make it not legal RPSL.
 * Too bad. */
void filter_print_pretty(const Node *node);

#endif // FILTER_H
