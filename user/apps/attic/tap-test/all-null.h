#include <nexus/ipc.h>

const char *canonical_string(const char *str);
void IPD_PropagateTaints(int source, int dest);

extern int non_composable;
extern int do_sanity_checks;
extern int g_wrap_pattern;

typedef enum VetoCheckMode {
  NO_CHECK,
  NO_VETOES,
  HAS_VETO,
} VetoCheckMode;

extern VetoCheckMode veto_check_mode;
extern int saw_veto;
extern int num_vetoes;

#define ALL_NULL_VETO_FNAME "/nfs/ALL_NULL_VETO.000"
