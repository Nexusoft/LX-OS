#include <nexus/defs.h>
#define MTRR_NEED_STRINGS
#include <nexus/machineprimitives.h>
#include <nexus/mtrr.h>
#include <asm/msr.h>
#include <asm/errno.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>

static void mtrr_read(int index, struct MTRR_Base *b, struct MTRR_Mask *m, int *size_p) {
  __u32 low, high;
  rdmsr(IA32_MTRR_PHYSBASE(index), low, high);
  *b = MTRR_Base_from_u32(low, high);
  rdmsr(IA32_MTRR_PHYSMASK(index), low, high);
  *m = MTRR_Mask_from_u32(low, high);

  __u32 mask = m->mask << PAGE_SHIFT;

  // Infer size. Assumes contiguous mask
  int size;
  for(size = 12; size < 32; size++) {
    __u32 size_mask = ((1 << size) - 1);
    if(~mask == size_mask) {
      break;
    }
  }
  if(size == 32) {
    size = -1;
  } else {
    size = 1 << size;
  }

  *size_p = size;
}

void mtrr_dump(void) {
  __u32 low, high;
  int type;

  rdmsr(IA32_MTRR_DEF_TYPE, low, high);
  type = low & 0xff;
  if(type >= 7) {
    type = 2; // unknown type
  }
  printk("MTRR[default]: type='%s' Fixed enabled=%d MTRR enabled=%d\n",
	 mtrr_strings[type], low & (1 << 10), low & (1 << 11) );

  int i;
  for(i=0; i < NUM_MTRR; i++) {
    struct MTRR_Base b;
    struct MTRR_Mask m;
    int size;
    mtrr_read(i, &b, &m, &size);

    type = b.type;
    if(type >= 7) {
      type = 2;
    }
    void *base = (void *) (b.physaddr << PAGE_SHIFT);
    unsigned long mask = m.mask << PAGE_SHIFT;
    
    printk("MTRR[%d]: type = '%s' base = %p mask = %p (size = %d) valid = %d \n",
	   i, mtrr_strings[type], base, (void *)mask, size, m.valid);
  }
}

int mtrr_add (unsigned long base, unsigned long size,
	      unsigned int type, char increment) {
  if(((size - 1) & size) != 0) {
    printk("mtrr_add: size is not a power of 2!\n");
    return -EINVAL;
  }
  if(size < PAGE_SIZE) {
    printk("mtrr_add: size is smaller than a page!\n");
    return -EINVAL;
  }

  // prevent other processes from disrupting updating
  int i;
  int intlevel = disable_intr();
  // Find a free MTRR
  int success = 0;

  for(i=0; i < NUM_MTRR; i++) {
    struct MTRR_Base b;
    struct MTRR_Mask m;
    int _size;
    mtrr_read(i, &b, &m, &_size);
    if(m.valid) {
      continue;
    }
    printk_red("added mtrr %d\n", i);

    memset(&b, 0, sizeof(b));
    memset(&m, 0, sizeof(m));
    b.type = type;
    b.physaddr = base >> PAGE_SHIFT;
    m.valid = 1;
    m.mask = ~(size - 1) >> PAGE_SHIFT;

    wrmsr(IA32_MTRR_PHYSBASE(i), ((__u32*)&b)[0], ((__u32*)&b)[1]);
    wrmsr(IA32_MTRR_PHYSMASK(i), ((__u32*)&m)[0], ((__u32*)&m)[1]);

    success = 1;
    break;
  }
  restore_intr(intlevel);
  if(success) {
    printk_red("wrote to mtrr %d", i);
    return 0;
  } else {
    printk_red("out of mtrrs\n");
    return -EINVAL;
  }
}
