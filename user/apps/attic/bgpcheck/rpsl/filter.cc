#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "filter.h"
#include "rpsl.tab.hh"

OperatorNode::OperatorNode(int which, int argc, ...) {
  op = which;
  va_list args;
  va_start(args, argc);
  for (int i=0; i<argc; i++)
    operands.push_back(va_arg(args, Node*));
  va_end(args);
}

OperatorNode::~OperatorNode(void) {
  for (unsigned int i=0; i<operands.size(); i++)
    if (operands[i]) delete operands[i];
}

ListNodeBase::~ListNodeBase(void) {
  for (unsigned int i=0; i<data.size(); i++)
    delete data[i];
}

PrefixNode::PrefixNode(struct in_addr _base, int _len, int _sub_start, int _sub_end)
		: base(_base), len(_len), sub_start(_sub_start), sub_end(_sub_end) { }

void filter_print_pretty(const Node *node) {
	unsigned int i;
	const OperatorNode *on;
	const ListNodeBase *ln;
	const PrefixNode *pn;
	const RegexEntNode *rn;
	const AttributeMatchNode *amn;
	const AttributeActionNode *aan;
	const IntNode *in;
	const PeeringNode *peer;
	char args_delim = '(';
	switch (node->type()) {
		case NODE_OPERATOR:
			on = dynamic_cast<const OperatorNode*>(node);
			switch (on->op) {
				case OR:
					putchar('(');
					filter_print_pretty(on->operands[0]);
					printf(" OR ");
					filter_print_pretty(on->operands[1]);
					putchar(')');
					break;
				case AND:
					putchar('(');
					filter_print_pretty(on->operands[0]);
					printf(" AND ");
					filter_print_pretty(on->operands[1]);
					putchar(')');
					break;
				case NOT:
					printf("NOT ");
					filter_print_pretty(on->operands[0]);
					break;
				case '|':
					putchar('(');
					filter_print_pretty(on->operands[0]);
					printf(" | ");
					filter_print_pretty(on->operands[1]);
					putchar(')');
					break;
				case ANY:
					printf("ANY");
					break;
				case FILTER:
					printf("filter: ");
					filter_print_pretty(on->operands[0]);
					break;
				case IMPORT:
					printf("import: ");
					filter_print_pretty(on->operands[0]);
					printf(" ACCEPT ");
					filter_print_pretty(on->operands[1]);
					break;
				case EXPORT:
					printf("export: ");
					filter_print_pretty(on->operands[0]);
					printf(" ANNOUNCE ");
					filter_print_pretty(on->operands[1]);
					break;
				case TO:
				case FROM:
					printf(on->op == TO ? "TO " : "FROM ");
					filter_print_pretty(on->operands[0]);
					if (on->operands[1]) {
						printf(" ACTION");
						ln = dynamic_cast<const ListNodeBase*>(on->operands[1]);
						for (i=0; i<ln->size(); i++) {
							putchar(' ');
							filter_print_pretty((*ln)[i]);
							putchar(';');
						}
					}
					break;
				default:
					assert(isprint(on->op));
					assert(on->nops() == 0);
					putchar(on->op);
			}
			break;
		case NODE_PREFIX_SET:
			putchar('{');
			ln = dynamic_cast<const ListNodeBase*>(node);
			for (i=0; i<ln->size(); i++) {
				if (i > 0) putchar(',');
				putchar(' ');
				filter_print_pretty((*ln)[i]);
			}
			printf(" }");
			break;
		case NODE_REGEX:
			putchar('<');
			ln = dynamic_cast<const ListNodeBase*>(node);
			for (i=0; i<ln->size(); i++) {
				putchar(' ');
				filter_print_pretty((*ln)[i]);
			}
			printf(" >");
			break;
		case NODE_REGEX_AS_SET:
			putchar('[');
			if (dynamic_cast<const RegexASSetNode*>(node)->complement) printf(" ^");
			ln = dynamic_cast<const ListNodeBase*>(node);
			for (i=0; i<ln->size(); i++) {
				putchar(' ');
				filter_print_pretty((*ln)[i]);
			}
			printf(" ]");
			break;
		case NODE_PREFIX:
			pn = dynamic_cast<const PrefixNode*>(node);
			printf("%s/%d", inet_ntoa(pn->base), pn->len);
			if (pn->sub_start == pn->len && pn->sub_end == 32) printf("^+");
			else if (pn->sub_start == pn->len + 1 && pn->sub_end == 32) printf("^-");
			else if (pn->sub_start == pn->len && pn->sub_end == pn->len) {}
			else if (pn->sub_start == pn->sub_end) printf("^%d", pn->sub_start);
			else printf("^%d-%d", pn->sub_start, pn->sub_end);
			break;
		case NODE_REGEX_ENT:
			rn = dynamic_cast<const RegexEntNode*>(node);
			filter_print_pretty(rn->atom);
			if (rn->uniform) putchar('~');
			if (rn->min == 1 && rn->max == 1) {}
			else if (rn->min == 0 && rn->max == INF) printf("*");
			else if (rn->min == 1 && rn->max == INF) printf("+");
			else if (rn->max == INF) printf("{%d,}", rn->min);
			else printf("{%d,%d}", rn->min, rn->max);
			break;
		case NODE_INT:
			in = dynamic_cast<const IntNode*>(node);
			switch (in->data) {
				case NO_EXPORT:      printf("NO_EXPORT");     break;
				case NO_ADVERTISE:   printf("NO_ADVERTISE");  break;
				default:
					if (in->data >= 1<<16)
						printf("%d:%d", in->data>>16, in->data&0xFFFF);
					else
						printf("%d", in->data);
			}
			break;
		case NODE_AS:
			printf("AS%d", dynamic_cast<const ASNode*>(node)->data);
			break;
		case NODE_AS_RANGE:
			printf("AS%d-AS%d", dynamic_cast<const ASRangeNode*>(node)->data.first, dynamic_cast<const ASRangeNode*>(node)->data.second);
			break;
		case NODE_AS_SET:
			printf("%s", dynamic_cast<const ASSetNode*>(node)->data.c_str());
			break;
		case NODE_ATTR_MATCH:
			amn = dynamic_cast<const AttributeMatchNode*>(node);
			switch (amn->attr_key) {
				case COMMUNITY: printf("community"); break;
				default:        printf("<<unknown attr %d>>", amn->attr_key);
			}
			putchar('.');
			switch (amn->attr_method) {
				case CONTAINS:  printf("contains");  break;
				default:        printf("<<unknown method %d>>", amn->attr_method);
			}
			putchar('(');
			for (i=0; i<amn->args->size(); i++) {
				if (i > 0) printf(", ");
				filter_print_pretty((*amn->args)[i]);
			}
			putchar(')');
			break;
		case NODE_ATTR_ACTION:
			aan = dynamic_cast<const AttributeActionNode*>(node);
			switch (aan->attr_key) {
				case PREF:      printf("pref");      break;
				case MED:       printf("med");       break;
				case DPA:       printf("dpa");       break;
				case ASPATH:    printf("aspath");    break;
				case COMMUNITY: printf("community"); break;
				case NEXT_HOP:  printf("next-hop");  break;
				case COST:      printf("cost");      break;
				default:        printf("<<unknown attr %d>>", aan->attr_key);
			}
			switch (aan->attr_method) {
				case '=':
					printf(" = ");
					args_delim = aan->attr_key == COMMUNITY ? '{': '\0';
					break;
				case PREPEND:   printf(".prepend");  break;
				case APPEND:    printf(".append");   break;
				case DELETE:    printf(".delete");   break;
				default:        printf("<<unknown method %d>>", aan->attr_method);
			}
			if (args_delim) putchar(args_delim);
			if (aan->args)
				for (i=0; i<aan->args->size(); i++) {
					if (i > 0) printf(", ");
					filter_print_pretty((*aan->args)[i]);
				}
			if (args_delim == '(') putchar(')');
			else if (args_delim == '{') putchar('}');
			break;
		case NODE_GENERIC_LIST:
			ln = dynamic_cast<const ListNodeBase*>(node);
			for (i=0; i<ln->size(); i++) {
				if (i > 0) putchar(' ');
				filter_print_pretty((*ln)[i]);
			}
			break;
		case NODE_PEERING:
			peer = dynamic_cast<const PeeringNode*>(node);
			filter_print_pretty(peer->as);
			if (peer->rtr1.s_addr != INADDR_NONE)
				printf(" %s", inet_ntoa(peer->rtr1));
			if (peer->rtr2.s_addr != INADDR_NONE)
				printf(" at %s", inet_ntoa(peer->rtr2));
			break;
		default:
			printf("<<UNKNOWN NODE TYPE: %d>>", node->type());
	}
}

void filter_print(const Node *node, int indent) {
	unsigned int i;
	const OperatorNode *on;
	const ListNodeBase *ln;
	const RegexEntNode *rn;
	const PeeringNode *peer;
	printf("%*s", 2*indent, " ");
	switch (node->type()) {
		case NODE_OPERATOR:
			on = dynamic_cast<const OperatorNode*>(node);
			switch (on->op) {
				case OR:       printf("OR:\n");       break;
				case AND:      printf("AND:\n");      break;
				case NOT:      printf("NOT:\n");      break;
				case ANY:      printf("ANY\n");       break;
				case FILTER:   printf("FILTER:\n");   break;
				case IMPORT:   printf("IMPORT:\n");   break;
				case EXPORT:   printf("EXPORT:\n");   break;
				case TO:       printf("TO:\n");       break;
				case FROM:     printf("FROM:\n");     break;
				default:
					printf(isprint(on->op) ? "'%c'\n" : "operator %d:\n", on->op);
			}
			for (i=0; i<on->nops(); i++)
				filter_print(on->operands[i], indent+1);
			break;
		case NODE_PREFIX_SET:
			printf("prefix set:\n");
			ln = dynamic_cast<const ListNodeBase*>(node);
			for (i=0; i<ln->size(); i++)
				filter_print((*ln)[i], indent+1);
			break;
		case NODE_GENERIC_LIST:
			printf("list:\n");
			ln = dynamic_cast<const ListNodeBase*>(node);
			for (i=0; i<ln->size(); i++)
				filter_print((*ln)[i], indent+1);
			break;
		case NODE_REGEX:
			printf("regex:\n");
			ln = dynamic_cast<const ListNodeBase*>(node);
			for (i=0; i<ln->size(); i++)
				filter_print((*ln)[i], indent+1);
			break;
		case NODE_REGEX_AS_SET:
			printf("regex as_set[complement=%s]:\n",
				dynamic_cast<const RegexASSetNode*>(node)->complement ? "true" : "false");
			ln = dynamic_cast<const ListNodeBase*>(node);
			for (i=0; i<ln->size(); i++)
				filter_print((*ln)[i], indent+1);
			break;
		case NODE_PREFIX:
			filter_print_pretty(node);
			putchar('\n');
			break;
		case NODE_REGEX_ENT:
			rn = dynamic_cast<const RegexEntNode*>(node);
			printf("regex_ent[%d,%d,%s]:\n", rn->min, rn->max, rn->uniform ? "true" : "false");
			filter_print(rn->atom, indent+1);
			break;
		case NODE_AS:
			printf("as: %d\n", dynamic_cast<const ASNode*>(node)->data);
			break;
		case NODE_AS_RANGE:
			printf("as_range: %d-%d\n", dynamic_cast<const ASRangeNode*>(node)->data.first, dynamic_cast<const ASRangeNode*>(node)->data.second);
			break;
		case NODE_AS_SET:
			printf("as_set: %s\n", dynamic_cast<const ASSetNode*>(node)->data.c_str());
			break;
		case NODE_ATTR_MATCH:
		case NODE_ATTR_ACTION:
			filter_print_pretty(node);
			putchar('\n');
			break;
		case NODE_PEERING:
			printf("Peering:\n");
			peer = dynamic_cast<const PeeringNode*>(node);
			filter_print(peer->as, indent+1);
			printf("%*s%s\n", indent*2, "", inet_ntoa(peer->rtr1));
			printf("%*s%s\n", indent*2, "", inet_ntoa(peer->rtr2));
			break;
		default:
			printf("<<UNKNOWN NODE TYPE: %d>>\n", node->type());
	}
}
