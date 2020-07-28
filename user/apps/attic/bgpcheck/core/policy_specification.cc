#include <iostream>
#include "../include/nbgp/policy_specification.h"

/////////////////////////////// Policy_Specification

Policy_Specification::Policy_Specification(){
  //nothing
}
Policy_Specification::~Policy_Specification(){
  //nothing
}

short Policy_Specification::ask(Policy_Question *q){
  return 0;
}

/////////////////////////////// Policy_Grouping

Policy_Grouping::Policy_Grouping() : 
  specs()
{
}

Policy_Grouping::~Policy_Grouping(){
  std::vector<Policy_Specification *>::iterator iter;
  for(iter = specs.begin(); iter != specs.end(); ++iter){
    delete *iter;
  }
}

void Policy_Grouping::add(Policy_Specification *spec){
  specs.push_back(spec);
}
short Policy_Grouping::ask(Policy_Question *q){
  std::vector<Policy_Specification *>::iterator iter;
  short ret;
  for(iter = specs.begin(); iter != specs.end(); ++iter){
    if((ret = (*iter)->ask(q))){
      return ret;
    }
  }
  return 0;
}
