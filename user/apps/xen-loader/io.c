#include <assert.h>
#include "io.h"
#include <nexus/Xen.interface.h>

void send_virq(int irq_num) {
  Xen_DeliverVIRQ(irq_num);
}
