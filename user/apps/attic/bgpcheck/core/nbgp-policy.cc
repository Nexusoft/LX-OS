#include <iostream>
#include <assert.h>

#include "../include/nbgp/nbgp.h"
#include "../include/nbgp/bgpcheck.h"
#include "../include/nbgp/policy_specification.h"

//timeout is in ms
#define NBGP_POLICY_TIMEOUT 15000

////////////////////////////////////////// Prefix_Spec

void Prefix_Spec::init_base(){
  prefix = 0;
  delta = 0;
  operand = -1;
  range_general = -1;
  range_specific = 33;
}

//Base
Prefix_Spec::Prefix_Spec(unsigned int _prefix, unsigned short _prefix_length){
  init_base();
  operand = PREFIX_SINGLE;
  prefix = _prefix;
  range_specific = range_general = _prefix_length;
}
//Set (no-modifier)
Prefix_Spec::Prefix_Spec(){
  init_base();
  operand = PREFIX_NOOP;
}
//Operand
Prefix_Spec::Prefix_Spec(Prefix_Spec *spec, int _operand){
  init_base();
  operand = _operand;
  if(operand == PREFIX_EXCLUSIVE_SPECIFICS) { delta = 1; }
  add(spec);
}
//Range
Prefix_Spec::Prefix_Spec(Prefix_Spec *spec, short _start){
  init_base();
  operand = PREFIX_RANGE_ONE;
  range_specific = range_general = _start;
}
Prefix_Spec::Prefix_Spec(Prefix_Spec *spec, short _start, short _stop){
  init_base();
  operand = PREFIX_RANGE_MANY;
  range_general = _start;
  range_specific = _stop;
}

Prefix_Spec::~Prefix_Spec(){
  std::vector<Prefix_Spec *>::iterator iter;
  
  for(iter = set.begin(); iter != set.end(); ++iter){
    delete *iter;
  }
}

void Prefix_Spec::add(Prefix_Spec *spec){
  set.push_back(spec);
}

short Prefix_Spec::contains(unsigned int _prefix, unsigned short _prefix_length){
  return contains(_prefix, _prefix_length, 0, 1);
}

short Prefix_Spec::contains(unsigned int _prefix, 
                            unsigned short prefix_length,
                            unsigned short _delta,
                            unsigned short restrict){
  if(operand != PREFIX_NOOP){
    if(restrict){
      if(range_specific < prefix_length){
        //if this is the topmost operand, the prefix shouldn't be
        //more specific than the most specific prefix in the set.
        return 0;
      }
      restrict = 1;
    }
    if(range_general + _delta > prefix_length){
      //The prefix shouldn't be more general than the most general
      //prefix this set allows.  Operators can only make prefixes MORE
      //specific.  They can't make them more general.  Hence, it must be
      //at least as specific as ALL of the restricting factors.
      return 0;
    }
    if((operand == PREFIX_EXCLUSIVE_SPECIFICS) ||
       (operand == PREFIX_INCLUSIVE_SPECIFICS)){
      //range operators reset the high end offset.
      delta = 0;
    }
  }
  
  if(operand == PREFIX_SINGLE){
    //we know prefix_length is the length of this node's prefix
    //since range_specific == range_general and it is neither greater than
    //or less than either.  On the other hand, if there was an operator
    //above us, it already did the low end check and the check for its own
    //range (if any)
    int i;
    i = 1 << prefix_length; 
    i -= 1;
    i = i << (32 - prefix_length);
    return (prefix & i) == (_prefix & i);
  } else {
    return set_contains(_prefix, prefix_length, _delta + delta, restrict);
  }  
}


short Prefix_Spec::set_contains(unsigned int _prefix, 
                                unsigned short _prefix_length,
                                unsigned short delta,
                                unsigned short restrict){
  std::vector<Prefix_Spec *>::iterator iter;

  assert(operand != PREFIX_SINGLE);

  for(iter = set.begin(); iter != set.end(); ++iter){
    if((*iter)->contains(_prefix, _prefix_length, delta, restrict)){
      return 1;
    }
  }
  return 0;
}

////////////////////////////////////////// Policy_Action

short Policy_Action::packet_satisfies(bgp_packet *p){
  int i;
  switch(field){
    case PACTION_COMMUNITY:
      switch(op){
        case PACTION_OP_SET:
        case PACTION_OP_APPEND:
          for(i = 0; i < p->contents.UPDATE.num_communities; i++){
            if(p->contents.UPDATE.communities[i] == value){
              return 1;
            }
          }
          return 0;
          break;
        case PACTION_OP_REMOVE:
          for(i = 0; i < p->contents.UPDATE.num_communities; i++){
            if(p->contents.UPDATE.communities[i] == value){
              return 0;
            }
          }
          break;
      }
      break;
    case PACTION_LOCALPREF:
      //if((unsigned int)p->contents.UPDATE.preference != value) return 0;
      break;
    case PACTION_MED:
      //if((unsigned int)p->contents.UPDATE.med != value) return 0;
      break;
    case PACTION_DROP:
      return 0;
      break;
  }
  return 1;
}
short Policy_Action::match_community(unsigned int community){
  if(field == PACTION_COMMUNITY){
    switch(op){
      case PACTION_OP_CMP_EQ:
        if(value == community){
          return 1;
        } else {
          return 0;
        }
        break;
      case PACTION_OP_CMP_NEQ:
        if(value == community){
          return 0;
        } else {
          return 1;
        }
        break;
    }
  }
  return 0;
}
short Policy_Action::match_localpref(unsigned int localpref){
  if(field == PACTION_LOCALPREF){
    switch(op){
      case PACTION_OP_CMP_LT:
        return (localpref <  value);
        break;
      case PACTION_OP_CMP_GT:
        return (localpref >  value);
        break;
      case PACTION_OP_CMP_EQ:
        return (localpref == value);
        break;
      case PACTION_OP_CMP_NEQ:
        return (localpref != value);
        break;
    }
  }
  return 0;
}
short Policy_Action::match_med(unsigned int med){
  if(field == PACTION_MED){
    switch(op){
      case PACTION_OP_CMP_LT:
        return (med <  value);
        break;
      case PACTION_OP_CMP_GT:
        return (med >  value);
        break;
      case PACTION_OP_CMP_EQ:
        return (med == value);
        break;
      case PACTION_OP_CMP_NEQ:
        return (med != value);
        break;
    }
  }
  return 0;
}
short Policy_Action::match_question(Policy_Question *q, Policy_Intermediate_State *s){
  std::vector<unsigned int>::iterator iter;
  switch(field){
    case PACTION_COMMUNITY:
      for(iter = (*q->incoming)->communities.begin(); iter != (*q->incoming)->communities.end(); ++iter){
        if(*iter == value){
          return op == PACTION_OP_CMP_EQ;
        }
      }
      if(s && s->match_community(value)){
        return op == PACTION_OP_CMP_EQ;
      }
      return op != PACTION_OP_CMP_EQ;
      break;
    case PACTION_LOCALPREF:
      if(s){
        return s->match_localpref(value);
      } else {
        //return op == (((unsigned int)(*q->incoming)->localpref == value)?PACTION_OP_CMP_EQ:PACTION_OP_CMP_NEQ);
        return op == PACTION_OP_CMP_EQ;
      }
      break;
    case PACTION_MED:
      if(s){
        return s->match_localpref(value);
      } else {
        //return op == (((unsigned int)(*q->incoming)->localpref == value)?PACTION_OP_CMP_EQ:PACTION_OP_CMP_NEQ);
        return op == PACTION_OP_CMP_EQ;
      }
      break;      
  }
  return 0;
}

////////////////////////////////////////// Policy_Regex

void Policy_Regex::init_base(){
  type = 0;
  as = 0;
  range_max = (0 - 1);
  range_min = 0;
  next = NULL;
}
Policy_Regex::Policy_Regex(unsigned short _as){
  type = REGEX_AS;
  as = _as;
}
Policy_Regex::Policy_Regex(int _type, Policy_Regex *child){
  type = _type;
  if(child){
    add_child(child);
  }
}
Policy_Regex::~Policy_Regex(){
  std::vector<Policy_Regex *>::iterator iter;
  for(iter = children.begin(); iter != children.end(); ++iter){
    delete *iter;
  }
  if(next)
    delete next;
}

void Policy_Regex::add_child(Policy_Regex *child){
  children.push_back(child);
}
void Policy_Regex::add_peer(Policy_Regex *peer){
  if(next){
    next->add_peer(peer);
  } else {
    next = peer;
  }
}

short Policy_Regex::next_cont(std::vector<unsigned short>::iterator path,  std::vector<unsigned short>::iterator begin, std::vector<unsigned short>::iterator end, std::vector<Policy_Regex *> *cont, Policy_Regex *step){
  Policy_Regex *tmp;
  short ret;

  if(step){
    return step->match(path, begin, end, cont);
  } else {
    if(cont->size() <= 0){
      return 1;
    }
    
    tmp = cont->back();
    cont->pop_back();
    ret = tmp->match(path, begin, end, cont);
    cont->push_back(tmp); //reset in case we need to repeat this.
    return ret;
  }
}

short Policy_Regex::match(std::vector<unsigned short> path){
  std::vector<Policy_Regex *> cont_stack;
  return match(path.begin(), path.begin(), path.end(), &cont_stack);
}

short Policy_Regex::match(std::vector<unsigned short>::iterator path,  std::vector<unsigned short>::iterator begin, std::vector<unsigned short>::iterator end, std::vector<Policy_Regex *> *cont){
  std::vector<Policy_Regex *>::iterator iter;
  int ret;

  switch(type){
    case REGEX_AS:
      if((path == end) || (*path != as)){
        return 0;
      }
      ++path;
      return next_cont(path, begin, end, cont, next);
    case REGEX_OR:
    case REGEX_SET:
      if(next){
        cont->push_back(next);
      }
      for(iter = children.begin(); iter != children.end(); ++iter){
        if(next_cont(path, begin, end, cont, *iter)){
          if(next){
            cont->pop_back();
          }
          return 1;
        }
      }
      if(next){
        cont->pop_back();
      }
      return 0;
      break;
    case REGEX_SPECIAL:
      switch(as){
        case REGEX_SPECIAL_ANY:
          if(path == end){
            return 0;
          }
          ++path;
          break;
        case REGEX_SPECIAL_START:
          if(path != begin){
            return 0;
          }
          break;
        case REGEX_SPECIAL_END:
          if(path != end){
            return 0;
          }
          break;
      }
      return next_cont(path, begin, end, cont, next);
      break;
    default:
      return 0; //punt on the rest of these for now.
  }
}

////////////////////////////////////////// Policy_Intermediate_State

void Policy_Intermediate_State::add(Policy_Action act){
  acts.push_back(act);
}
short Policy_Intermediate_State::match_community(unsigned int community){
  std::vector<Policy_Action>::iterator iter;
  
  for(iter = acts.begin(); iter != acts.end(); ++iter){
    if(iter->match_community(community)){
      return 1;
    }
  }
  return 0;
}
short Policy_Intermediate_State::match_med(int med){
  std::vector<Policy_Action>::iterator iter;
  
  for(iter = acts.begin(); iter != acts.end(); ++iter){
    if(iter->match_med(med)){
      return 1;
    }
  }
  return 0;
}
short Policy_Intermediate_State::match_localpref(int localpref){
  std::vector<Policy_Action>::iterator iter;
  
  for(iter = acts.begin(); iter != acts.end(); ++iter){
    if(iter->match_localpref(localpref)){
      return 1;
    }
  }
  return 0;
}
short Policy_Intermediate_State::packet_satisfies(bgp_packet *p){
  std::vector<Policy_Action>::iterator iter;
  for(iter = acts.begin(); iter != acts.end(); ++iter){
    if(!iter->packet_satisfies(p)){
      return 0;
    }
  }
  return 1;
}

////////////////////////////////////////// Policy_Filter

short Policy_Filter::match(Policy_Question *q, Policy_Intermediate_State *s){
  switch(type){
    case FILTER_AND:
      if(d.boolean_op.op1 || !d.boolean_op.op1->match(q, s)){
        return 0;
      }
      if(d.boolean_op.op2 || !d.boolean_op.op2->match(q, s)){
        return 0;
      }
      return 1;
      break;
    case FILTER_OR:
      if(d.boolean_op.op1 && d.boolean_op.op1->match(q, s)){
        return 1;
      }
      if(d.boolean_op.op2 && d.boolean_op.op2->match(q, s)){
        return 1;
      }
      return 0;
      break;
    case FILTER_NOT:
      if(!d.boolean_op.op1){
        return 1;
      }
      return !d.boolean_op.op1->match(q, s);
      break;
    case FILTER_PSET:
      if(d.p_set){
        return (d.p_set->contains(q->prefix, q->p_len));
      } else {
        return 0;
      }
      break;
    case FILTER_ACTION:
      if(d.action){
        return d.action->match_question(q, s);
      } else {
        return 0;
      }
      break;
    case FILTER_ASPATH:
      if(d.regex){
        return d.regex->match((*q->incoming)->as_path);
      } else {
        return 0;
      }
      break;
    case FILTER_ANY:
      return 1;
      break;
  }
  return 1;
}

////////////////////////////////////////// NBGP_AS_Policy_Set

NBGP_AS_Policy_Set::NBGP_AS_Policy_Set(){
  flags = 0;
}

void NBGP_AS_Policy_Set::add_as(unsigned short _as){
  as.push_back(_as);
}
void NBGP_AS_Policy_Set::add_action(Policy_Action _action){
  action.push_back(_action);
}

short NBGP_AS_Policy_Set::match_as(unsigned short _as){
  std::vector<unsigned short>::iterator curr;
  
  if(flags & NBGP_AS_ANY){ return 1; }
  
  for(curr = as.begin(); curr != as.end(); ++curr){
    if(*curr == _as){
      return 1;
    }
  }
  return 0;
}
short NBGP_AS_Policy_Set::apply_actions(Policy_Intermediate_State *s){
  std::vector<Policy_Action>::iterator act;
  for(act = action.begin(); act != action.end(); ++act){
    if(act->field == PACTION_DROP){
      return 0;
    }
    s->add(*act);
  }
  return 1;
}
short NBGP_AS_Policy_Set::check_actions(bgp_packet *p){
  std::vector<Policy_Action>::iterator act;
  assert(p->type == 2);
  for(act = action.begin(); act != action.end(); ++act){
    if(!act->packet_satisfies(p)){
      return 0;
    }
  }
  return 1;
}

////////////////////////////////////////// Policy_Line

NBGP_Policy_Line::NBGP_Policy_Line(){
  filter = NULL;
}
NBGP_Policy_Line::~NBGP_Policy_Line(){
  if(filter){
    delete filter;
  }
}
void NBGP_Policy_Line::set_filter(Policy_Filter *_filter){
  if(filter){
    delete filter;
  }
  filter = _filter;
}
void NBGP_Policy_Line::add_as(NBGP_AS_Policy_Set *_as_action){
  as_actions.push_back(_as_action);
}

//match import and match export return one of three values.
// -1: The question does match this line of the policy file BUT this incoming ad IS NOT eligible to back the outgoing ad.
//  0: The question does NOT match this line of the policy file OR the incoming ad IS eligible to back the outgoing ad.

short NBGP_Policy_Line::match_import(Policy_Question *q, Policy_Intermediate_State *state){
  if(filter->match(q, NULL)){
    //only apply this rule to questions which match the filter.
    std::vector<NBGP_AS_Policy_Set *>::iterator as;
    unsigned short source = (*q->incoming)->as_id;
    
    
    for(as = as_actions.begin(); as != as_actions.end(); ++as){
      if((*as)->match_as(source)){
        if((*as)->apply_actions(state)){
          return 0;
        }
        return -1;
      }
    }
  }
  return 0;
}
short NBGP_Policy_Line::match_export(Policy_Question *q, Policy_Intermediate_State *state){
  if(filter->match(q, NULL)){
    //only apply this rule to questions which match the filter.
    std::vector<NBGP_AS_Policy_Set *>::iterator as;
    unsigned short dest = q->dest_as;
    assert(q != NULL);
    
    
    for(as = as_actions.begin(); as != as_actions.end(); ++as){
      if((*as)->match_as(dest)){
        if((*as)->check_actions(q->outgoing)){
          return 0;
        }
        return -1;
      }
    }
  }
  return 0;
}

////////////////////////////////////////// NBGP_Policy

NBGP_Policy::NBGP_Policy(){
  swap_in = NULL;
  //nothing yet
}
NBGP_Policy::~NBGP_Policy(){
  if(swap_in) delete swap_in;
  //nothing yet
}

void NBGP_Policy::add_export(NBGP_Policy_Line *line){
  exports.push_back(line);
}
void NBGP_Policy::add_import(NBGP_Policy_Line *line){
  imports.push_back(line);
}
void NBGP_Policy::add_policy(NBGP_Policy *p){
  policies.push_back(p);
}

short NBGP_Policy::check_imports(Policy_Question *q, Policy_Intermediate_State *s){
  std::vector<NBGP_Policy_Line *>::iterator line;
  
  for(line = imports.begin(); line != imports.end(); ++line){
    if((*line)->match_import(q, s) < 0){
      return 1;
    }
  }
  
  return 0;
}

short NBGP_Policy::check_exports(Policy_Question *q, Policy_Intermediate_State *s){
  std::vector<NBGP_Policy_Line *>::iterator line;
  
  for(line = exports.begin(); line != exports.end(); ++line){
    if((*line)->match_export(q, s) < 0){
      return 1;
    }
  }
  
  return 0;
}
short NBGP_Policy::ask(Policy_Question *q){
  return ask_real(q);
}
short NBGP_Policy::ask_real(Policy_Question *q){
  Policy_Intermediate_State s;
  std::vector<NBGP_Policy *>::iterator p;
  
  if(check_imports(q, &s)){
    return 1;
  }
  for(p = policies.begin(); p != policies.end(); ++p){
    if((*p)->check_imports(q, &s)){
      return 1;
    }
  }
  if(check_exports(q, &s)){
    return 1;
  }
  for(p = policies.begin(); p != policies.end(); ++p){
    if((*p)->check_exports(q, &s)){
      return 1;
    }
  }
  return !s.packet_satisfies(q->outgoing);
}

void NBGP_Policy::install(BC_Checker *checker, Runtime *r){
  if(swap_in) delete swap_in;
  swap_in = new Swapper(checker->set_policy(this), checker, NBGP_POLICY_TIMEOUT);
  r->register_handler(swap_in);
}

NBGP_Policy::Swapper::Swapper(Policy_Grouping *_policy, BC_Checker *_checker, int timeout) : 
  Runtime_Handler(timeout, NULL, "NBGP_Policy::Swapper"), policy(_policy), checker(_checker) {}

int NBGP_Policy::Swapper::handle_periodic(Runtime *runtime){
  checker->force_policy_swap(policy);
  return 0;
}

