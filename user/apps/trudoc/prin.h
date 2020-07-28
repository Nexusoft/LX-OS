#ifndef PRIN_H
#define PRIN_H

extern char *aas_key;
extern int aas_key_len;

Form *make_name(char *name);
Form *make_sub(Form *parent, char *name);

char *mem_dup(char *buf, int len);

#endif // PRIN_H
