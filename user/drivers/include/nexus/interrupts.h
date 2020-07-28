#ifndef __UDRIVER_INTERRUPTS_H__
#define __UDRIVER_INTERRUPTS_H__

#include <linux/types.h>

int disable_intr(void);
void restore_intr(int lvl);

void nexus_cli(void);
void nexus_sti(void);

#endif
