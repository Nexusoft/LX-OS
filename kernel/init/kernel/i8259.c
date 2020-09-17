#include <linux/config.h>
#include <asm/errno.h>
#include <linux/ioport.h>
#include <asm/hw_irq.h>
#include <asm/timex.h>
#include <asm/param.h>
#include <linux/smp_lock.h>
#include <linux/spinlock.h>

#include <asm/atomic.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/pgtable.h>
#include <asm/delay.h>
#include <asm/desc.h>
#include <asm/apic.h>

#include <nexus/machine-structs.h>
#include <nexus/machineprimitives.h>
#include <nexus/defs.h>
#include <nexus/idtgdt.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>

#define __init
#define __initdata
#define __devinit

/*
 * Common place to define all x86 IRQ vectors
 *
 * This builds up the IRQ handler stubs using some ugly macros in irq.h
 *
 * These macros create the low-level assembly IRQ routines that save
 * register context and call do_IRQ(). do_IRQ() then does all the
 * operations that are needed to keep the AT (or SMP IOAPIC)
 * interrupt-controller happy.
 */

#if 0
BUILD_COMMON_IRQ()
#endif

#define NEXUSIRQ_NAME2(nr) nr##_interrupt(void)
#define NEXUSIRQ_NAME(nr) NEXUSIRQ_NAME2(NEXUSIRQ##nr)

#define BUILD_NEXUSIRQ(nr) \
asmlinkage void NEXUSIRQ_NAME(nr); \
__asm__( \
"\n"__ALIGN_STR"\n" \
SYMBOL_NAME_STR(NEXUSIRQ) #nr "_interrupt:\n\t" \
	"pushl $"#nr"-256\n\t" \
        "jmp nexus_asm_irq");

#define NEXUSBI(x,y) \
	BUILD_NEXUSIRQ(x##y)

#define BUILD_16_NEXUSIRQS(x) \
	NEXUSBI(x,0) NEXUSBI(x,1) NEXUSBI(x,2) NEXUSBI(x,3) \
	NEXUSBI(x,4) NEXUSBI(x,5) NEXUSBI(x,6) NEXUSBI(x,7) \
	NEXUSBI(x,8) NEXUSBI(x,9) NEXUSBI(x,a) NEXUSBI(x,b) \
	NEXUSBI(x,c) NEXUSBI(x,d) NEXUSBI(x,e) NEXUSBI(x,f)

void gcc_ggdb_workaround(void) { } // force switch into .text section

/*
 * ISA PIC or low IO-APIC triggered (INTA-cycle or APIC) interrupts:
 * (these are usually mapped to vectors 0x20-0x2f)
 */
BUILD_16_NEXUSIRQS(0x0)

#undef BUILD_16_NEXUSIRQS
#undef NEXUSBI

#define NEXUSIRQ(x,y) \
	NEXUSIRQ##x##y##_interrupt

#define NEXUSIRQLIST_16(x) \
	NEXUSIRQ(x,0), NEXUSIRQ(x,1), NEXUSIRQ(x,2), NEXUSIRQ(x,3), \
	NEXUSIRQ(x,4), NEXUSIRQ(x,5), NEXUSIRQ(x,6), NEXUSIRQ(x,7), \
	NEXUSIRQ(x,8), NEXUSIRQ(x,9), NEXUSIRQ(x,a), NEXUSIRQ(x,b), \
	NEXUSIRQ(x,c), NEXUSIRQ(x,d), NEXUSIRQ(x,e), NEXUSIRQ(x,f)

void (*interrupt[NR_IRQS])(void) = {
        NEXUSIRQLIST_16(0x0),
};

#undef NEXUSIRQ
#undef NEXUSIRQLIST_16

/*
 * This is the 'legacy' 8259A Programmable Interrupt Controller,
 * present in the majority of PC/AT boxes.
 * plus some generic x86 specific things if generic specifics makes
 * any sense at all.
 * this file should become arch/i386/kernel/irq.c when the old irq.c
 * moves to arch independent land
 */

spinlock_t i8259A_lock = SPIN_LOCK_UNLOCKED;

/*
 * 8259A PIC functions to handle ISA devices:
 */

/*
 * This contains the irq mask for both 8259A irq controllers,
 */
static unsigned int cached_irq_mask = 0xffff;

#define __byte(x,y) 	(((unsigned char *)&(y))[x])
#define cached_21	(__byte(0,cached_irq_mask))
#define cached_A1	(__byte(1,cached_irq_mask))

unsigned int getirqmask(void){
  return cached_irq_mask;
}

int check_8259A_irq(unsigned int irq) {
	return !(cached_irq_mask & (1 << irq));
}

void disable_8259A_irq(unsigned int irq)
{
	unsigned int mask = 1 << irq;
	unsigned long flags;

	spin_lock_irqsave(&i8259A_lock, flags);
	cached_irq_mask |= mask;
	if (irq & 8)
		outb(cached_A1,0xA1);
	else
		outb(cached_21,0x21);
	spin_unlock_irqrestore(&i8259A_lock, flags);
}

void enable_8259A_irq(unsigned int irq)
{
	unsigned int mask = ~(1 << irq);
	unsigned long flags;

	spin_lock_irqsave(&i8259A_lock, flags);
	cached_irq_mask &= mask;
	if (irq & 8)
		outb(cached_A1,0xA1);
	else
		outb(cached_21,0x21);
	spin_unlock_irqrestore(&i8259A_lock, flags);
}

int i8259A_irq_pending(unsigned int irq)
{
	unsigned int mask = 1<<irq;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&i8259A_lock, flags);
	if (irq < 8)
		ret = inb(0x20) & mask;
	else
		ret = inb(0xA0) & (mask >> 8);
	spin_unlock_irqrestore(&i8259A_lock, flags);

	return ret;
}

/*
 * This function assumes to be called rarely. Switching between
 * 8259A registers is slow.
 * This has to be protected by the irq controller spinlock
 * before being called.
 */
static inline int i8259A_irq_real(unsigned int irq)
{
	int value;
	int irqmask = 1<<irq;

	if (irq < 8) {
		outb(0x0B,0x20);		/* ISR register */
		value = inb(0x20) & irqmask;
		outb(0x0A,0x20);		/* back to the IRR register */
		return value;
	}
	outb(0x0B,0xA0);		/* ISR register */
	value = inb(0xA0) & (irqmask >> 8);
	outb(0x0A,0xA0);		/* back to the IRR register */
	return value;
}

/*
 * Careful! The 8259A is a fragile beast, it pretty
 * much _has_ to be done exactly like this (mask it
 * first, _then_ send the EOI, and the order of EOI
 * to the two 8259s is important!
 */
int mask_and_ack_8259A(unsigned int irq)
{
	unsigned int irqmask = 1 << irq;
	unsigned long flags;
	int spurious = 0;

	spin_lock_irqsave(&i8259A_lock, flags);
	/*
	 * Lightweight spurious IRQ detection. We do not want
	 * to overdo spurious IRQ handling - it's usually a sign
	 * of hardware problems, so we only do the checks we can
	 * do without slowing down good hardware unnecesserily.
	 *
	 * Note that IRQ7 and IRQ15 (the two spurious IRQs
	 * usually resulting from the 8259A-1|2 PICs) occur
	 * even if the IRQ is masked in the 8259A. Thus we
	 * can check spurious 8259A IRQs without doing the
	 * quite slow i8259A_irq_real() call for every IRQ.
	 * This does not cover 100% of spurious interrupts,
	 * but should be enough to warn the user that there
	 * is something bad going on ...
	 */
	if (cached_irq_mask & irqmask)
		goto spurious_8259A_irq;
	cached_irq_mask |= irqmask;

handle_real_irq:
	if (irq & 8) {
		inb(0xA1);		/* DUMMY - (do we need this?) */
		outb(cached_A1,0xA1);
		outb(0x60+(irq&7),0xA0);/* 'Specific EOI' to slave */
		outb(0x62,0x20);	/* 'Specific EOI' to master-IRQ2 */
	} else {
		inb(0x21);		/* DUMMY - (do we need this?) */
		outb(cached_21,0x21);
		outb(0x60+irq,0x20);	/* 'Specific EOI' to master */
	}
	spin_unlock_irqrestore(&i8259A_lock, flags);
	return spurious;

spurious_8259A_irq:
	/*
	 * this is the slow path - should happen rarely.
	 */
	if (i8259A_irq_real(irq))
		/*
		 * oops, the IRQ _is_ in service according to the
		 * 8259A - not spurious, go handle it.
		 */
		goto handle_real_irq;

	{
		static int spurious_irq_mask;
		/*
		 * At this point we can be sure the IRQ is spurious,
		 * lets ACK and report it. [once per IRQ]
		 */
		if (!(spurious_irq_mask & irqmask)) {
			printk("spurious 8259A interrupt: IRQ%d.\n", irq);
			spurious_irq_mask |= irqmask;
		}
		/*
		 * Theoretically we do not have to handle this IRQ,
		 * but in Linux this does not cause problems and is
		 * simpler for us.
		 */
		//XXX DAN: it causes problems for nexus.
		spurious = 1;
		goto handle_real_irq; // kwalsh: why? does it need the ack?
	}
}

void __init init_8259A(void)
{
	unsigned long flags;

	spin_lock_irqsave(&i8259A_lock, flags);

	outb(0xff, 0x21);	/* mask all of 8259A-1 */
	outb(0xff, 0xA1);	/* mask all of 8259A-2 */

	/*
	 * outb_p - this has to work on a wide range of PC hardware.
	 */
	outb_p(0x11, 0x20);	/* ICW1: select 8259A-1 init */
	outb_p(0x20 + 0, 0x21);	/* ICW2: 8259A-1 IR0-7 mapped to 0x20-0x27 */
	outb_p(0x04, 0x21);	/* 8259A-1 (the master) has a slave on IR2 */
#if 0
	if (auto_eoi)
		outb_p(0x03, 0x21);	/* master does Auto EOI */
	else
#endif
		outb_p(0x01, 0x21);	/* master expects normal EOI */

	outb_p(0x11, 0xA0);	/* ICW1: select 8259A-2 init */
	outb_p(0x20 + 8, 0xA1);	/* ICW2: 8259A-2 IR0-7 mapped to 0x28-0x2f */
	outb_p(0x02, 0xA1);	/* 8259A-2 is a slave on master's IR2 */
	outb_p(0x01, 0xA1);	/* (slave's support for AEOI in flat mode
				    is to be investigated) */

	udelay(100);		/* wait for 8259A to initialize */

	outb(cached_21, 0x21);	/* restore master IRQ mask */
	outb(cached_A1, 0xA1);	/* restore slave IRQ mask */

	spin_unlock_irqrestore(&i8259A_lock, flags);
}

void __init init_ISA_irqs(void)
{
	init_8259A();
}

void __init init_IRQ(void)
{
	int i;


	init_ISA_irqs();

	/*
	 * Cover the whole vector space, no vector can escape
	 * us. (some of these will be overridden and become
	 * 'special' SMP interrupts)
	 */

	for (i = 0; i < NR_IRQS; i++) {
		int vector = FIRST_EXTERNAL_VECTOR + i;
		if (vector != SYSCALL_VECTOR)
		    set_idt(vector, 14, 0, interrupt[i]);
		//XXX 14, 0 means interrupt into kernel
		//set_intr_gate(vector, interrupt[i]);
	}

/* LATCH is used in the interval timer and ftape setup. */
#define LATCH  ((CLOCK_TICK_RATE + HZ/2) / HZ)	/* For divider */

	/*
	 * Set the clock to HZ Hz, we already have a valid
	 * vector now:
	 */
	outb_p(0x34,0x43);		/* binary, mode 2, LSB/MSB, ch 0 */
	outb_p(LATCH & 0xff , 0x40);	/* LSB */
	outb(LATCH >> 8 , 0x40);	/* MSB */

	enable_8259A_irq(2); // cascade

	/*
	 * External FPU? Set up irq13 if so, for
	 * original braindamaged IBM FERR coupling.
	 */
	//if (boot_cpu_data.hard_math && !cpu_has_fpu)
		//enable_8259A_irq(13);
}
