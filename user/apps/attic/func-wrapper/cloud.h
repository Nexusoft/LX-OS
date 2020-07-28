#ifndef _CLOUD_H_
#define _CLOUD_H_

struct CloudStartHeader {
  int exec_len;
  char exec_name[64];

  int arg_len;
  char arg[64];
};
#endif // _CLOUD_H_
