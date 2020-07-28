#include <nexus/ipc.h>

const char *canonical_string(const char *str);
void IPD_PropagateTaints(int source, int dest);

extern int non_composable;
extern int do_sanity_checks;
extern int g_wrap_pattern;
