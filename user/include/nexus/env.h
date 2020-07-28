#ifndef _NEXUS_ENV_H_
#define _NEXUS_ENV_H_

/** Returns the requested value, allocated on the heap */
char *Env_get_value(const char *name, int *len_p);

#endif // _NEXUS_ENV_H_

