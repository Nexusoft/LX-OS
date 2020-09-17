/*
 *	Intel i810 and friends ICH driver for Linux
 *	Alan Cox <alan@redhat.com>
 *
 *  Built from:
 *	Low level code:  Zach Brown (original nonworking i810 OSS driver)
 *			 Jaroslav Kysela <perex@suse.cz> (working ALSA driver)
 *
 *	Framework: Thomas Sailer <sailer@ife.ee.ethz.ch>
 *	Extended by: Zach Brown <zab@redhat.com>  
 *			and others..
 *
 *  Hardware Provided By:
 *	Analog Devices (A major AC97 codec maker)
 *	Intel Corp  (you've probably heard of them already)
 *
 *  AC97 clues and assistance provided by
 *	Analog Devices
 *	Zach 'Fufu' Brown
 *	Jeff Garzik
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *
 *	Intel 810 theory of operation
 *
 *	The chipset provides three DMA channels that talk to an AC97
 *	CODEC (AC97 is a digital/analog mixer standard). At its simplest
 *	you get 48Khz audio with basic volume and mixer controls. At the
 *	best you get rate adaption in the codec. We set the card up so
 *	that we never take completion interrupts but instead keep the card
 *	chasing its tail around a ring buffer. This is needed for mmap
 *	mode audio and happens to work rather well for non-mmap modes too.
 *
 *	The board has one output channel for PCM audio (supported) and
 *	a stereo line in and mono microphone input. Again these are normally
 *	locked to 48Khz only. Right now recording is not finished.
 *
 *	There is no midi support, no synth support. Use timidity. To get
 *	esd working you need to use esd -r 48000 as it won't probe 48KHz
 *	by default. mpg123 can't handle 48Khz only audio so use xmms.
 *
 *	Fix The Sound On Dell
 *
 *	Not everyone uses 48KHz. We know of no way to detect this reliably
 *	and certainly not to get the right data. If your i810 audio sounds
 *	stupid you may need to investigate other speeds. According to Analog
 *	they tend to use a 14.318MHz clock which gives you a base rate of
 *	41194Hz.
 *
 *	This is available via the 'ftsodell=1' option. 
 *
 *	If you need to force a specific rate set the clocking= option
 *
 *	This driver is cursed. (Ben LaHaise)
 *
 *  ICH 3 caveats
 *	Intel errata #7 for ICH3 IO. We need to disable SMI stuff
 *	when codec probing. [Not Yet Done]
 *
 *  ICH 4 caveats
 *
 *      The ICH4 has the feature, that the codec ID doesn't have to be 
 *      congruent with the IO connection.
 * 
 *      Therefore, from driver version 0.23 on, there is a "codec ID" <->
 *      "IO register base offset" mapping (card->ac97_id_map) field.
 *   
 *      Juergen "George" Sawinski (jsaw) 
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/ioport.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/soundcard.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/fs.h>

#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/hardirq.h>

#include <nexus/device.h>
#include <nexus/udevice.h>
#include <nexus/ioport.h>
#include <nexus/sema.h>
#include <nexus/ipc.h>

#include "../sound_core.h"
#include "ac97_codec.h"

extern struct file_operations *nexus_audio_fops;
static struct file_operations i810_audio_fops;

/*djwill this is included because this is the ported nexus kernel
  driver, rather than the linux driver */
typedef struct AudioBuf {
  int hz;
  Sema *block;
  int waiting;
	// we need to buffer writes in the background, instead of just blocking
	// char *backbuf;
	// int backpos;
} AudioBuf;
/*djwill: these definitions are also only needed because this is the
  ported Nexus driver */
extern int  IPC_TransferTo(Call_Handle call_handle, int desc_num, unsigned int remote, void * local, int len);
extern int  IPC_TransferFrom(Call_Handle call_handle, int desc_num, void * local, unsigned int remote, int len);

#ifndef PCI_DEVICE_ID_INTEL_82801
#define PCI_DEVICE_ID_INTEL_82801	0x2415
#endif
#ifndef PCI_DEVICE_ID_INTEL_82901
#define PCI_DEVICE_ID_INTEL_82901	0x2425
#endif
#ifndef PCI_DEVICE_ID_INTEL_ICH2
#define PCI_DEVICE_ID_INTEL_ICH2	0x2445
#endif
#ifndef PCI_DEVICE_ID_INTEL_ICH3
#define PCI_DEVICE_ID_INTEL_ICH3	0x2485
#endif
#ifndef PCI_DEVICE_ID_INTEL_ICH4
#define PCI_DEVICE_ID_INTEL_ICH4	0x24c5
#endif
#ifndef PCI_DEVICE_ID_INTEL_ICH5
#define PCI_DEVICE_ID_INTEL_ICH5	0x24d5
#endif
#ifndef PCI_DEVICE_ID_INTEL_ICH8
#define PCI_DEVICE_ID_INTEL_ICH8	0x284b
#endif
#ifndef PCI_DEVICE_ID_INTEL_440MX
#define PCI_DEVICE_ID_INTEL_440MX	0x7195
#endif
#ifndef PCI_DEVICE_ID_SI_7012
#define PCI_DEVICE_ID_SI_7012		0x7012
#endif
#ifndef PCI_DEVICE_ID_NVIDIA_MCP1_AUDIO
#define PCI_DEVICE_ID_NVIDIA_MCP1_AUDIO	0x01b1
#endif
#ifndef PCI_DEVICE_ID_NVIDIA_MCP2_AUDIO
#define PCI_DEVICE_ID_NVIDIA_MCP2_AUDIO	0x006a
#endif
#ifndef PCI_DEVICE_ID_NVIDIA_MCP3_AUDIO
#define PCI_DEVICE_ID_NVIDIA_MCP3_AUDIO	0x00da
#endif
#ifndef PCI_DEVICE_ID_AMD_768_AUDIO
#define PCI_DEVICE_ID_AMD_768_AUDIO	0x7445
#endif
#ifndef PCI_DEVICE_ID_AMD_8111_AC97
#define PCI_DEVICE_ID_AMD_8111_AC97	0x746d
#endif

static int ftsodell=0;
static int strict_clocking=0;
static unsigned int clocking=0;
static int spdif_locked=0;

//#define DEBUG
//#define DEBUG2
//#define DEBUG_INTERRUPTS
//#define DEBUG_LOCKING
//#define DEBUG_MMAP
//#define DEBUG_MMIO

#define ADC_RUNNING	1
#define DAC_RUNNING	2

#define I810_FMT_16BIT	1
#define I810_FMT_STEREO	2
#define I810_FMT_MASK	3

#define SPDIF_ON	0x0004
#define SURR_ON		0x0010
#define CENTER_LFE_ON	0x0020
#define VOL_MUTED	0x8000

/* the 810's array of pointers to data buffers */

struct sg_item {
#define BUSADDR_MASK	0xFFFFFFFE
	u32 busaddr;	
#define CON_IOC 	0x80000000 /* interrupt on completion */
#define CON_BUFPAD	0x40000000 /* pad underrun with last sample, else 0 */
#define CON_BUFLEN_MASK	0x0000ffff /* buffer length in samples */
	u32 control;
};

/* an instance of the i810 channel */
#define SG_LEN 32
struct i810_channel 
{
	/* these sg guys should probably be allocated
	   seperately as nocache. Must be 8 byte aligned */
	struct sg_item sg[SG_LEN];	/* 32*8 */
	u32 offset;			/* 4 */
	u32 port;			/* 4 */
	u32 used;
	u32 num;
};

/*
 * we have 3 seperate dma engines.  pcm in, pcm out, and mic.
 * each dma engine has controlling registers.  These goofy
 * names are from the datasheet, but make it easy to write
 * code while leafing through it.
 *
 * ICH4 has 6 dma engines, pcm in, pcm out, mic, pcm in 2, 
 * mic in 2, s/pdif.   Of special interest is the fact that
 * the upper 3 DMA engines on the ICH4 *must* be accessed
 * via mmio access instead of pio access.
 */

#define ENUM_ENGINE(PRE,DIG) 									\
enum {												\
	PRE##_BDBAR =	0x##DIG##0,		/* Buffer Descriptor list Base Address */	\
	PRE##_CIV =	0x##DIG##4,		/* Current Index Value */			\
	PRE##_LVI =	0x##DIG##5,		/* Last Valid Index */				\
	PRE##_SR =	0x##DIG##6,		/* Status Register */				\
	PRE##_PICB =	0x##DIG##8,		/* Position In Current Buffer */		\
	PRE##_PIV =	0x##DIG##a,		/* Prefetched Index Value */			\
	PRE##_CR =	0x##DIG##b		/* Control Register */				\
}

ENUM_ENGINE(OFF,0);	/* Offsets */
ENUM_ENGINE(PI,0);	/* PCM In */
ENUM_ENGINE(PO,1);	/* PCM Out */
ENUM_ENGINE(MC,2);	/* Mic In */

enum {
	GLOB_CNT =	0x2c,			/* Global Control */
	GLOB_STA = 	0x30,			/* Global Status */
	CAS	 = 	0x34			/* Codec Write Semaphore Register */
};

ENUM_ENGINE(MC2,4);     /* Mic In 2 */
ENUM_ENGINE(PI2,5);     /* PCM In 2 */
ENUM_ENGINE(SP,6);      /* S/PDIF */

enum {
	SDM =           0x80                    /* SDATA_IN Map Register */
};

/* interrupts for a dma engine */
#define DMA_INT_FIFO		(1<<4)  /* fifo under/over flow */
#define DMA_INT_COMPLETE	(1<<3)  /* buffer read/write complete and ioc set */
#define DMA_INT_LVI		(1<<2)  /* last valid done */
#define DMA_INT_CELV		(1<<1)  /* last valid is current */
#define DMA_INT_DCH		(1)	/* DMA Controller Halted (happens on LVI interrupts) */
#define DMA_INT_MASK (DMA_INT_FIFO|DMA_INT_COMPLETE|DMA_INT_LVI)

/* interrupts for the whole chip */
#define INT_SEC		(1<<11)
#define INT_PRI		(1<<10)
#define INT_MC		(1<<7)
#define INT_PO		(1<<6)
#define INT_PI		(1<<5)
#define INT_MO		(1<<2)
#define INT_NI		(1<<1)
#define INT_GPI		(1<<0)
#define INT_MASK (INT_SEC|INT_PRI|INT_MC|INT_PO|INT_PI|INT_MO|INT_NI|INT_GPI)

#define DRIVER_VERSION "0.24"

/* magic numbers to protect our data structures */
#define I810_CARD_MAGIC		0x5072696E /* "Prin" */
#define I810_STATE_MAGIC	0x63657373 /* "cess" */
#define I810_DMA_MASK		0xffffffff /* DMA buffer mask for pci_alloc_consist */
#define NR_HW_CH		3

/* maxinum number of AC97 codecs connected, AC97 2.0 defined 4 */
#define NR_AC97                 4

/* Please note that an 8bit mono stream is not valid on this card, you must have a 16bit */
/* stream at a minimum for this card to be happy */
static const unsigned sample_size[] = { 1, 2, 2, 4 };
/* Samples are 16bit values, so we are shifting to a word, not to a byte, hence shift */
/* values are one less than might be expected */
static const unsigned sample_shift[] = { -1, 0, 0, 1 };

enum {
	ICH82801AA = 0,
	ICH82901AB,
	INTEL440MX,
	INTELICH2,
	INTELICH3,
	INTELICH4,
	INTELICH5,
	INTELICH8,
	SI7012,
	NVIDIA_NFORCE,
	AMD768,
	AMD8111
};

static char * card_names[] = {
	"Intel ICH 82801AA",
	"Intel ICH 82901AB",
	"Intel 440MX",
	"Intel ICH2",
	"Intel ICH3",
	"Intel ICH4",
	"Intel ICH5",
	"Intel ICH8",
	"SiS 7012",
	"NVIDIA nForce Audio",
	"AMD 768",
	"AMD-8111 IOHub"
};

/* These are capabilities (and bugs) the chipsets _can_ have */
static struct {
	int16_t      nr_ac97;
#define CAP_MMIO                 0x0001
#define CAP_20BIT_AUDIO_SUPPORT  0x0002
	u_int16_t flags;
} card_cap[] = {
	{  1, 0x0000 }, /* ICH82801AA */
	{  1, 0x0000 }, /* ICH82901AB */
	{  1, 0x0000 }, /* INTEL440MX */
	{  1, 0x0000 }, /* INTELICH2 */
	{  2, 0x0000 }, /* INTELICH3 */
 	{  3, 0x0003 }, /* INTELICH4 */
	{  3, 0x0003 }, /* INTELICH5 */
	{  3, 0x0003 }, /* INTELICH8 */
	/*@FIXME to be verified*/	{  2, 0x0000 }, /* SI7012 */
	/*@FIXME to be verified*/	{  2, 0x0000 }, /* NVIDIA_NFORCE */
	/*@FIXME to be verified*/	{  2, 0x0000 }, /* AMD768 */
	/*@FIXME to be verified*/	{  3, 0x0001 }, /* AMD8111 */
};

static struct pci_device_id i810_pci_tbl [] __initdata = {
	{PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82801,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, ICH82801AA},
	{PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82901,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, ICH82901AB},
	{PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_440MX,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, INTEL440MX},
	{PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_ICH2,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, INTELICH2},
	{PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_ICH3,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, INTELICH3},
	{PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_ICH4,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, INTELICH4},
	{PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_ICH5,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, INTELICH5},
	{PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_ICH8,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, INTELICH8},
	{PCI_VENDOR_ID_SI, PCI_DEVICE_ID_SI_7012,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, SI7012},
	{PCI_VENDOR_ID_NVIDIA, PCI_DEVICE_ID_NVIDIA_MCP1_AUDIO,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, NVIDIA_NFORCE},
	{PCI_VENDOR_ID_NVIDIA, PCI_DEVICE_ID_NVIDIA_MCP2_AUDIO,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, NVIDIA_NFORCE},
	{PCI_VENDOR_ID_NVIDIA, PCI_DEVICE_ID_NVIDIA_MCP3_AUDIO,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, NVIDIA_NFORCE},
	{PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_768_AUDIO,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, AMD768},
	{PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_8111_AC97,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, AMD8111},

	{PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_ICH6_18,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, INTELICH4},

	{0,}
};

MODULE_DEVICE_TABLE (pci, i810_pci_tbl);

#ifdef CONFIG_PM
#define PM_SUSPENDED(card) (card->pm_suspended)
#else
#define PM_SUSPENDED(card) (0)
#endif

/* "software" or virtual channel, an instance of opened /dev/dsp */
struct i810_state {
	unsigned int magic;
	struct i810_card *card;	/* Card info */

	/* single open lock mechanism, only used for recording */
	struct semaphore open_sem;
	wait_queue_head_t open_wait;

	/* file mode */
	mode_t open_mode;

	/* virtual channel number */
	int virt;

#ifdef CONFIG_PM
	unsigned int pm_saved_dac_rate,pm_saved_adc_rate;
#endif
	struct dmabuf {
		/* wave sample stuff */
		unsigned int rate;
		unsigned char fmt, enable, trigger;

		/* hardware channel */
		struct i810_channel *read_channel;
		struct i810_channel *write_channel;

		/* OSS buffer management stuff */
		void *rawbuf;
		dma_addr_t dma_handle;
		unsigned buforder;
		unsigned numfrag;
		unsigned fragshift;

		/* our buffer acts like a circular ring */
		unsigned hwptr;		/* where dma last started, updated by update_ptr */
		unsigned swptr;		/* where driver last clear/filled, updated by read/write */
		int count;		/* bytes to be consumed or been generated by dma machine */
		unsigned total_bytes;	/* total bytes dmaed by hardware */

		unsigned error;		/* number of over/underruns */
		wait_queue_head_t wait;	/* put process on wait queue when no more space in buffer */

		/* redundant, but makes calculations easier */
		/* what the hardware uses */
		unsigned dmasize;
		unsigned fragsize;
		unsigned fragsamples;

		/* what we tell the user to expect */
		unsigned userfrags;
		unsigned userfragsize;

		/* OSS stuff */
		unsigned mapped:1;
		unsigned ready:1;
		unsigned update_flag;
		unsigned ossfragsize;
		unsigned ossmaxfrags;
		unsigned subdivision;
	} dmabuf;
};


struct i810_card {
	unsigned int magic;

	/* We keep i810 cards in a linked list */
	struct i810_card *next;

	/* The i810 has a certain amount of cross channel interaction
	   so we use a single per card lock */
	spinlock_t lock;
	
	/* Control AC97 access serialization */
	spinlock_t ac97_lock;

	/* PCI device stuff */
	struct pci_dev * pci_dev;
	u16 pci_id;
	u16 pci_id_internal; /* used to access card_cap[] */
#ifdef CONFIG_PM	
	u16 pm_suspended;
	u32 pm_save_state[64/sizeof(u32)];
	int pm_saved_mixer_settings[SOUND_MIXER_NRDEVICES][NR_AC97];
#endif
	/* soundcore stuff */
	int dev_audio;

	/* structures for abstraction of hardware facilities, codecs, banks and channels*/
	u16    ac97_id_map[NR_AC97];
	struct ac97_codec *ac97_codec[NR_AC97];
	struct i810_state *states[NR_HW_CH];
	struct i810_channel *channel;	/* 1:1 to states[] but diff. lifetime */
	dma_addr_t chandma;

	u16 ac97_features;
	u16 ac97_status;
	u16 channels;
	
	/* hardware resources */
	unsigned long ac97base;
	unsigned long iobase;
	u32 irq;

	unsigned long ac97base_mmio_phys;
	unsigned long iobase_mmio_phys;
	u_int8_t *ac97base_mmio;
	u_int8_t *iobase_mmio;

	int           use_mmio;
	
	/* Function support */
	struct i810_channel *(*alloc_pcm_channel)(struct i810_card *);
	struct i810_channel *(*alloc_rec_pcm_channel)(struct i810_card *);
	struct i810_channel *(*alloc_rec_mic_channel)(struct i810_card *);
	void (*free_pcm_channel)(struct i810_card *, int chan);

	/* We have a *very* long init time possibly, so use this to block */
	/* attempts to open our devices before we are ready (stops oops'es) */
	int initializing;
};

struct i810_card *mycard;

/* extract register offset from codec struct */
#define IO_REG_OFF(codec) (((struct i810_card *) codec->private_data)->ac97_id_map[codec->id])

/* set LVI from CIV */
#define CIV_TO_LVI(port, off) outb((inb(port+OFF_CIV)+off) & 31, port+OFF_LVI)

static struct i810_card *devs = NULL;

static int i810_open_mixdev(struct inode *inode, struct file *file);
static int i810_ioctl_mixdev(struct inode *inode, struct file *file,
			     unsigned int cmd, unsigned long arg);
static u16 i810_ac97_get(struct ac97_codec *dev, u8 reg);
static void i810_ac97_set(struct ac97_codec *dev, u8 reg, u16 data);
static u16 i810_ac97_get_mmio(struct ac97_codec *dev, u8 reg);
static void i810_ac97_set_mmio(struct ac97_codec *dev, u8 reg, u16 data);
static u16 i810_ac97_get_io(struct ac97_codec *dev, u8 reg);
static void i810_ac97_set_io(struct ac97_codec *dev, u8 reg, u16 data);

#if 1 // djwill: this is an interface to Nexus which we don't have in userspace
AudioBuf default_audio_buf;	
AudioBuf *curr_audio_buf = &default_audio_buf;

void i810_set_current_audio_buf(void *a){curr_audio_buf = (AudioBuf *)a;}
void i810_unset_current_audio_buf(void){curr_audio_buf = &default_audio_buf;}
#endif

static struct i810_channel *i810_alloc_pcm_channel(struct i810_card *card)
{
	if(card->channel[1].used==1)
		return NULL;
	card->channel[1].used=1;
	return &card->channel[1];
}

static struct i810_channel *i810_alloc_rec_pcm_channel(struct i810_card *card)
{
	if(card->channel[0].used==1)
		return NULL;
	card->channel[0].used=1;
	return &card->channel[0];
}

static struct i810_channel *i810_alloc_rec_mic_channel(struct i810_card *card)
{
	if(card->channel[2].used==1)
		return NULL;
	card->channel[2].used=1;
	return &card->channel[2];
}

static void i810_free_pcm_channel(struct i810_card *card, int channel)
{
	card->channel[channel].used=0;
}

static int i810_valid_spdif_rate ( struct ac97_codec *codec, int rate )
{
	unsigned long id = 0L;

	id = (i810_ac97_get(codec, AC97_VENDOR_ID1) << 16);
	id |= i810_ac97_get(codec, AC97_VENDOR_ID2) & 0xffff;
#ifdef DEBUG
	printk ( "i810_audio: codec = %s, codec_id = 0x%08lx\n", codec->name, id);
#endif
	switch ( id ) {
		case 0x41445361: /* AD1886 */
			if (rate == 48000) {
				return 1;
			}
			break;
		default: /* all other codecs, until we know otherwiae */
			if (rate == 48000 || rate == 44100 || rate == 32000) {
				return 1;
			}
			break;
	}
	return (0);
}

/* i810_set_spdif_output
 * 
 *  Configure the S/PDIF output transmitter. When we turn on
 *  S/PDIF, we turn off the analog output. This may not be
 *  the right thing to do.
 *
 *  Assumptions:
 *     The DSP sample rate must already be set to a supported
 *     S/PDIF rate (32kHz, 44.1kHz, or 48kHz) or we abort.
 */
static int i810_set_spdif_output(struct i810_state *state, int slots, int rate)
{
	int	vol;
	int	aud_reg;
	int	r = 0;
	struct ac97_codec *codec = state->card->ac97_codec[0];

	if(!codec->codec_ops->digital) {
		state->card->ac97_status &= ~SPDIF_ON;
	} else {
		if ( slots == -1 ) { /* Turn off S/PDIF */
			codec->codec_ops->digital(codec, 0, 0, 0);
			/* If the volume wasn't muted before we turned on S/PDIF, unmute it */
			if ( !(state->card->ac97_status & VOL_MUTED) ) {
				aud_reg = i810_ac97_get(codec, AC97_MASTER_VOL_STEREO);
				i810_ac97_set(codec, AC97_MASTER_VOL_STEREO, (aud_reg & ~VOL_MUTED));
			}
			state->card->ac97_status &= ~(VOL_MUTED | SPDIF_ON);
			return 0;
		}

		vol = i810_ac97_get(codec, AC97_MASTER_VOL_STEREO);
		state->card->ac97_status = vol & VOL_MUTED;
		
		r = codec->codec_ops->digital(codec, slots, rate, 0);

		if(r)
			state->card->ac97_status |= SPDIF_ON;
		else
			state->card->ac97_status &= ~SPDIF_ON;

		/* Mute the analog output */
		/* Should this only mute the PCM volume??? */
		i810_ac97_set(codec, AC97_MASTER_VOL_STEREO, (vol | VOL_MUTED));
	}
	return r;
}

/* i810_set_dac_channels
 *
 *  Configure the codec's multi-channel DACs
 *
 *  The logic is backwards. Setting the bit to 1 turns off the DAC. 
 *
 *  What about the ICH? We currently configure it using the
 *  SNDCTL_DSP_CHANNELS ioctl.  If we're turnning on the DAC, 
 *  does that imply that we want the ICH set to support
 *  these channels?
 *  
 *  TODO:
 *    vailidate that the codec really supports these DACs
 *    before turning them on. 
 */
static void i810_set_dac_channels(struct i810_state *state, int channel)
{
	int	aud_reg;
	struct ac97_codec *codec = state->card->ac97_codec[0];
	
	/* No codec, no setup */
	
	if(codec == NULL)
		return;

	aud_reg = i810_ac97_get(codec, AC97_EXTENDED_STATUS);
	aud_reg |= AC97_EA_PRI | AC97_EA_PRJ | AC97_EA_PRK;
	state->card->ac97_status &= ~(SURR_ON | CENTER_LFE_ON);

	switch ( channel ) {
		case 2: /* always enabled */
			break;
		case 4:
			aud_reg &= ~AC97_EA_PRJ;
			state->card->ac97_status |= SURR_ON;
			break;
		case 6:
			aud_reg &= ~(AC97_EA_PRJ | AC97_EA_PRI | AC97_EA_PRK);
			state->card->ac97_status |= SURR_ON | CENTER_LFE_ON;
			break;
		default:
			break;
	}
	i810_ac97_set(codec, AC97_EXTENDED_STATUS, aud_reg);

}


/* set playback sample rate */
static unsigned int i810_set_dac_rate(struct i810_state * state, unsigned int rate)
{	
	struct dmabuf *dmabuf = &state->dmabuf;
	u32 new_rate;
	struct ac97_codec *codec=state->card->ac97_codec[0];
	
	printk("Setting audio output rate to %d Hz\n", rate);

	if(!(state->card->ac97_features&0x0001))
	{
		dmabuf->rate = clocking;
#ifdef DEBUG
		if (rate != dmabuf->rate)
			printk("  Asked for %d Hz, but ac97_features says we only do %d Hz.  Sorry!\n",
		       rate, clocking);
#endif		       
		return clocking;
	}
			
	int rate0 = rate;
	if (rate0 > 48000)
		rate = 48000;
	if (rate0 < 8000)
		rate = 8000;
	dmabuf->rate = rate;
		
	/*
	 *	Adjust for misclocked crap
	 */
	/* XXX DAN: this doesn't look equivalent */
	//rate = ( rate0 * clocking)/48000;
	rate = ( rate * clocking)/48000;
	if(strict_clocking && rate < 8000) {
		rate = 8000;
		dmabuf->rate = (rate * 48000)/clocking;
	}

        new_rate=ac97_set_dac_rate(codec, rate);
	if(new_rate != rate) {
		dmabuf->rate = (new_rate * 48000)/clocking;
	}
#ifdef DEBUG
	if (rate0 != dmabuf->rate)
		printk("  Asked for %d Hz, bug got %d Hz instead. Just because.\n",
				rate0, dmabuf->rate);
#endif
	return dmabuf->rate;
}
extern int i810_set_my_dac_rate(unsigned int rate){
	return i810_set_dac_rate(mycard->states[0], rate);
}


/* get current playback/recording dma buffer pointer (byte offset from LBA),
   called with spinlock held! */
static inline unsigned i810_get_dma_addr(struct i810_state *state, int rec)
{
	struct dmabuf *dmabuf = &state->dmabuf;
	unsigned int civ, offset, port, port_picb, bytes = 2;
	
	if (!dmabuf->enable)
		return 0;

	if (rec)
		port = state->card->iobase + dmabuf->read_channel->port;
	else
		port = state->card->iobase + dmabuf->write_channel->port;

	if(state->card->pci_id == PCI_DEVICE_ID_SI_7012) {
		port_picb = port + OFF_SR;
		bytes = 1;
	} else
		port_picb = port + OFF_PICB;

	do {
		civ = inb(port+OFF_CIV) & 31;
		offset = inw(port_picb);

		/* Must have a delay here! */ 
		if(offset == 0)
			udelay(1);
		/* Reread both registers and make sure that that total
		 * offset from the first reading to the second is 0.
		 * There is an issue with SiS hardware where it will count
		 * picb down to 0, then update civ to the next value,
		 * then set the new picb to fragsize bytes.  We can catch
		 * it between the civ update and the picb update, making
		 * it look as though we are 1 fragsize ahead of where we
		 * are.  The next to we get the address though, it will
		 * be back in the right place, and we will suddenly think
		 * we just went forward dmasize - fragsize bytes, causing
		 * totally stupid *huge* dma overrun messages.  We are
		 * assuming that the 1us delay is more than long enough
		 * that we won't have to worry about the chip still being
		 * out of sync with reality ;-)
		 */
	} while (civ != (inb(port+OFF_CIV) & 31) || offset != inw(port_picb));
		 
	return (((civ + 1) * dmabuf->fragsize - (bytes * offset))
		% dmabuf->dmasize);
}

/* Stop recording (lock held) */
static inline void __stop_adc(struct i810_state *state)
{
	struct dmabuf *dmabuf = &state->dmabuf;
	struct i810_card *card = state->card;

	dmabuf->enable &= ~ADC_RUNNING;
	outb(0, card->iobase + PI_CR);
	// wait for the card to acknowledge shutdown
	while( inb(card->iobase + PI_CR) != 0 ) ;
	// now clear any latent interrupt bits (like the halt bit)
	if(card->pci_id == PCI_DEVICE_ID_SI_7012)
		outb( inb(card->iobase + PI_PICB), card->iobase + PI_PICB );
	else
		outb( inb(card->iobase + PI_SR), card->iobase + PI_SR );
	outl( inl(card->iobase + GLOB_STA) & INT_PI, card->iobase + GLOB_STA);
}

static void stop_adc(struct i810_state *state)
{
	struct i810_card *card = state->card;
	unsigned long flags;

	spin_lock_irqsave(&card->lock, flags);
	__stop_adc(state);
	spin_unlock_irqrestore(&card->lock, flags);
}

static inline void __start_adc(struct i810_state *state)
{
	struct dmabuf *dmabuf = &state->dmabuf;

	if (dmabuf->count < dmabuf->dmasize && dmabuf->ready && !dmabuf->enable &&
	    (dmabuf->trigger & PCM_ENABLE_INPUT)) {
		dmabuf->enable |= ADC_RUNNING;
		// Interrupt enable, LVI enable, DMA enable
		outb(0x10 | 0x04 | 0x01, state->card->iobase + PI_CR);
	}
}

#if 0
static void start_adc(struct i810_state *state)
{
	struct i810_card *card = state->card;
	unsigned long flags;

	spin_lock_irqsave(&card->lock, flags);
	__start_adc(state);
	spin_unlock_irqrestore(&card->lock, flags);
}
#endif

/* stop playback (lock held) */
static inline void __stop_dac(struct i810_state *state)
{
	struct dmabuf *dmabuf = &state->dmabuf;
	struct i810_card *card = state->card;

	dmabuf->enable &= ~DAC_RUNNING;
	outb(0, card->iobase + PO_CR);
	// wait for the card to acknowledge shutdown
	while( inb(card->iobase + PO_CR) != 0 ) ;
	// now clear any latent interrupt bits (like the halt bit)
	if(card->pci_id == PCI_DEVICE_ID_SI_7012)
		outb( inb(card->iobase + PO_PICB), card->iobase + PO_PICB );
	else
		outb( inb(card->iobase + PO_SR), card->iobase + PO_SR );
	outl( inl(card->iobase + GLOB_STA) & INT_PO, card->iobase + GLOB_STA);
}

static void stop_dac(struct i810_state *state)
{
	struct i810_card *card = state->card;
	unsigned long flags;

	spin_lock_irqsave(&card->lock, flags);
	__stop_dac(state);
	spin_unlock_irqrestore(&card->lock, flags);
}	

static inline void __start_dac(struct i810_state *state)
{
	struct dmabuf *dmabuf = &state->dmabuf;

	if (dmabuf->count > 0 && dmabuf->ready && !dmabuf->enable &&
	    (dmabuf->trigger & PCM_ENABLE_OUTPUT)) {
		dmabuf->enable |= DAC_RUNNING;
		// Interrupt enable, LVI enable, DMA enable
		outb(0x10 | 0x04 | 0x01, state->card->iobase + PO_CR);
	}
}
static void start_dac(struct i810_state *state)
{
	struct i810_card *card = state->card;
	unsigned long flags;

	spin_lock_irqsave(&card->lock, flags);
	__start_dac(state);
	spin_unlock_irqrestore(&card->lock, flags);
}

#define DMABUF_DEFAULTORDER (16-PAGE_SHIFT)
#define DMABUF_MINORDER 1

/* allocate DMA buffer, playback and recording buffer should be allocated seperately */
static int alloc_dmabuf(struct i810_state *state)
{
	struct dmabuf *dmabuf = &state->dmabuf;
	void *rawbuf= NULL;
	int order, size;
	//DAN: struct page *page, *pend;

	/* If we don't have any oss frag params, then use our default ones */
	if(dmabuf->ossmaxfrags == 0)
		dmabuf->ossmaxfrags = 4;
	if(dmabuf->ossfragsize == 0)
		dmabuf->ossfragsize = (PAGE_SIZE<<DMABUF_DEFAULTORDER)/dmabuf->ossmaxfrags;
	size = dmabuf->ossfragsize * dmabuf->ossmaxfrags;

	if(dmabuf->rawbuf && (PAGE_SIZE << dmabuf->buforder) == size)
		return 0;
	/* alloc enough to satisfy the oss params */
	for (order = DMABUF_DEFAULTORDER; order >= DMABUF_MINORDER; order--) {
		if ( (PAGE_SIZE<<order) > size )
			continue;
		if ((rawbuf = pci_alloc_consistent(state->card->pci_dev,
						   PAGE_SIZE << order,
						   &dmabuf->dma_handle)))
			break;
	}
	if (!rawbuf)
		return -ENOMEM;


#ifdef DEBUG
	printk("i810_audio: allocated %ld (order = %d) bytes at %p\n",
	       PAGE_SIZE << order, order, rawbuf);
#endif

	dmabuf->ready  = dmabuf->mapped = 0;
	dmabuf->rawbuf = rawbuf;
	dmabuf->buforder = order;
	
#if 0
	/* now mark the pages as reserved; otherwise remap_page_range doesn't do what we want */
	pend = virt_to_page(rawbuf + (PAGE_SIZE << order) - 1);
	for (page = virt_to_page(rawbuf); page <= pend; page++)
		mem_map_reserve(page);
#endif

	return 0;
}

/* free DMA buffer */
static void dealloc_dmabuf(struct i810_state *state)
{
	struct dmabuf *dmabuf = &state->dmabuf;
	//DAN: struct page *page, *pend;

	if (dmabuf->rawbuf) {
		/* undo marking the pages as reserved */
#if 0
		pend = virt_to_page(dmabuf->rawbuf + (PAGE_SIZE << dmabuf->buforder) - 1);
		for (page = virt_to_page(dmabuf->rawbuf); page <= pend; page++)
			mem_map_unreserve(page);
#endif	
		pci_free_consistent(state->card->pci_dev, PAGE_SIZE << dmabuf->buforder,
				    dmabuf->rawbuf, dmabuf->dma_handle);
	}
	dmabuf->rawbuf = NULL;
	dmabuf->mapped = dmabuf->ready = 0;
}

static int prog_dmabuf(struct i810_state *state, unsigned rec)
{
	struct dmabuf *dmabuf = &state->dmabuf;
	struct i810_channel *c;
	struct sg_item *sg;
	unsigned long flags;
	int ret;
	unsigned fragint;
	int i;

	spin_lock_irqsave(&state->card->lock, flags);
	if(dmabuf->enable & DAC_RUNNING)
		__stop_dac(state);
	if(dmabuf->enable & ADC_RUNNING)
		__stop_adc(state);
	dmabuf->total_bytes = 0;
	dmabuf->count = dmabuf->error = 0;
	dmabuf->swptr = dmabuf->hwptr = 0;
	spin_unlock_irqrestore(&state->card->lock, flags);

	/* allocate DMA buffer, let alloc_dmabuf determine if we are already
	 * allocated well enough or if we should replace the current buffer
	 * (assuming one is already allocated, if it isn't, then allocate it).
	 */
	if ((ret = alloc_dmabuf(state)))
		return ret;

	/* FIXME: figure out all this OSS fragment stuff */
	/* I did, it now does what it should according to the OSS API.  DL */
	/* We may not have realloced our dmabuf, but the fragment size to
	 * fragment number ratio may have changed, so go ahead and reprogram
	 * things
	 */
	dmabuf->dmasize = PAGE_SIZE << dmabuf->buforder;
	dmabuf->numfrag = SG_LEN;
	dmabuf->fragsize = dmabuf->dmasize/dmabuf->numfrag;
	dmabuf->fragsamples = dmabuf->fragsize >> 1;
	dmabuf->userfragsize = dmabuf->ossfragsize;
	dmabuf->userfrags = dmabuf->dmasize/dmabuf->ossfragsize;

	memset(dmabuf->rawbuf, 0, dmabuf->dmasize);

	if(dmabuf->ossmaxfrags == 4) {
		fragint = 8;
		dmabuf->fragshift = 2;
	} else if (dmabuf->ossmaxfrags == 8) {
		fragint = 4;
		dmabuf->fragshift = 3;
	} else if (dmabuf->ossmaxfrags == 16) {
		fragint = 2;
		dmabuf->fragshift = 4;
	} else {
		fragint = 1;
		dmabuf->fragshift = 5;
	}
	/*
	 *	Now set up the ring 
	 */
	if(dmabuf->read_channel)
		c = dmabuf->read_channel;
	else
		c = dmabuf->write_channel;
	while(c != NULL) {
		sg=&c->sg[0];
		/*
		 *	Load up 32 sg entries and take an interrupt at half
		 *	way (we might want more interrupts later..) 
		 */
	  
		for(i=0;i<dmabuf->numfrag;i++)
		{
			sg->busaddr=(u32)dmabuf->dma_handle+dmabuf->fragsize*i;
			// the card will always be doing 16bit stereo
			sg->control=dmabuf->fragsamples;
			if(state->card->pci_id == PCI_DEVICE_ID_SI_7012)
				sg->control <<= 1;
			sg->control|=CON_BUFPAD;
			// set us up to get IOC interrupts as often as needed to
			// satisfy numfrag requirements, no more
			if( ((i+1) % fragint) == 0) {
				sg->control|=CON_IOC;
			}
			sg++;
		}
		spin_lock_irqsave(&state->card->lock, flags);
		outb(2, state->card->iobase+c->port+OFF_CR);   /* reset DMA machine */
		while( inb(state->card->iobase+c->port+OFF_CR) & 0x02 ) ;
		outl((u32)state->card->chandma +
		    c->num*sizeof(struct i810_channel),
		    state->card->iobase+c->port+OFF_BDBAR);
		CIV_TO_LVI(state->card->iobase+c->port, 0);

		spin_unlock_irqrestore(&state->card->lock, flags);

		if(c != dmabuf->write_channel)
			c = dmabuf->write_channel;
		else
			c = NULL;
	}
	
	/* set the ready flag for the dma buffer */
	dmabuf->ready = 1;

#ifdef DEBUG
	printk("i810_audio: prog_dmabuf, sample rate = %d, format = %d,\n\tnumfrag = %d, "
	       "fragsize = %d dmasize = %d\n",
	       dmabuf->rate, dmabuf->fmt, dmabuf->numfrag,
	       dmabuf->fragsize, dmabuf->dmasize);
#endif

	return 0;
}

static void __i810_update_lvi(struct i810_state *state, int rec)
{
	struct dmabuf *dmabuf = &state->dmabuf;
	int x, port;
	
	port = state->card->iobase;
	if(rec)
		port += dmabuf->read_channel->port;
	else
		port += dmabuf->write_channel->port;

	/* if we are currently stopped, then our CIV is actually set to our
	 * *last* sg segment and we are ready to wrap to the next.  However,
	 * if we set our LVI to the last sg segment, then it won't wrap to
	 * the next sg segment, it won't even get a start.  So, instead, when
	 * we are stopped, we set both the LVI value and also we increment
	 * the CIV value to the next sg segment to be played so that when
	 * we call start_{dac,adc}, things will operate properly
	 */
	if (!dmabuf->enable && dmabuf->ready) {
		if(rec && dmabuf->count < dmabuf->dmasize &&
		   (dmabuf->trigger & PCM_ENABLE_INPUT))
		{
			CIV_TO_LVI(port, 1);
			__start_adc(state);
			while( !(inb(port + OFF_CR) & ((1<<4) | (1<<2))) ) ;
		} else if (!rec && dmabuf->count &&
			   (dmabuf->trigger & PCM_ENABLE_OUTPUT))
		{
			CIV_TO_LVI(port, 1);
			__start_dac(state);
			while( !(inb(port + OFF_CR) & ((1<<4) | (1<<2))) ) ;
		}
	}

	/* swptr - 1 is the tail of our transfer */
	x = (dmabuf->dmasize + dmabuf->swptr - 1) % dmabuf->dmasize;
	x /= dmabuf->fragsize;
	outb(x, port+OFF_LVI);
}

static void i810_update_lvi(struct i810_state *state, int rec)
{
	struct dmabuf *dmabuf = &state->dmabuf;
	//unsigned long flags;

	if(!dmabuf->ready)
		return;
	//spin_lock_irqsave(&state->card->lock, flags);
	__i810_update_lvi(state, rec);
	//spin_unlock_irqrestore(&state->card->lock, flags);
}

/* update buffer manangement pointers, especially, dmabuf->count and dmabuf->hwptr */
static void i810_update_ptr(struct i810_state *state)
{
	struct dmabuf *dmabuf = &state->dmabuf;
	unsigned hwptr;
	int diff;
	int intlevel;
	/* error handling and process wake up for DAC */
	if (dmabuf->enable == ADC_RUNNING) {
		/* update hardware pointer */
		hwptr = i810_get_dma_addr(state, 1);
		diff = (dmabuf->dmasize + hwptr - dmabuf->hwptr) % dmabuf->dmasize;
#if defined(DEBUG_INTERRUPTS) || defined(DEBUG_MMAP)
		printk("ADC HWP %d,%d,%d\n", hwptr, dmabuf->hwptr, diff);
#endif
		dmabuf->hwptr = hwptr;
		dmabuf->total_bytes += diff;
		dmabuf->count += diff;
		if (dmabuf->count > dmabuf->dmasize) {
			/* buffer underrun or buffer overrun */
			/* this is normal for the end of a read */
			/* only give an error if we went past the */
			/* last valid sg entry */
			if((inb(state->card->iobase + PI_CIV) & 31) !=
			   (inb(state->card->iobase + PI_LVI) & 31)) {
				printk(KERN_WARNING "i810_audio: DMA overrun on read\n");
				dmabuf->error++;
			}
		}
		//DAN:
		if (dmabuf->count > dmabuf->userfragsize)
			printk("DAN: what gets woken up?\n");
		//wake_up(&dmabuf->wait);
	}
	/* error handling and process wake up for DAC */
	if (dmabuf->enable == DAC_RUNNING) {
		/* update hardware pointer */
		hwptr = i810_get_dma_addr(state, 0);
		diff = (dmabuf->dmasize + hwptr - dmabuf->hwptr) % dmabuf->dmasize;
#if defined(DEBUG_INTERRUPTS) || defined(DEBUG_MMAP)
		printk("DAC HWP %d,%d,%d\n", hwptr, dmabuf->hwptr, diff);
#endif
		dmabuf->hwptr = hwptr;
		dmabuf->total_bytes += diff;
		dmabuf->count -= diff;
		if (dmabuf->count < 0) {
			/* buffer underrun or buffer overrun */
			/* this is normal for the end of a write */
			/* only give an error if we went past the */
			/* last valid sg entry */
			if((inb(state->card->iobase + PO_CIV) & 31) !=
			   (inb(state->card->iobase + PO_LVI) & 31)) {
				printk(KERN_WARNING "i810_audio: DMA overrun on write\n");
				printk("i810_audio: CIV %d, LVI %d, hwptr %x, "
					"count %d\n",
					inb(state->card->iobase + PO_CIV) & 31,
					inb(state->card->iobase + PO_LVI) & 31,
					dmabuf->hwptr, dmabuf->count);
				dmabuf->error++;
			}
		}
		//DAN:
		intlevel = disable_intr();	
		if ((dmabuf->count < (int)(dmabuf->dmasize-dmabuf->userfragsize)) 
		    && (curr_audio_buf->waiting > 0)){

			printk("need synch!! %s %d\n", __FILE__, __LINE__);
#ifdef DEBUG_LOCKING
			printk("waking\n");
#endif
			if(curr_audio_buf->block != NULL)
				curr_audio_buf->waiting--;

			restore_intr(intlevel);			
			if(curr_audio_buf->block != NULL)
				V_nexus(curr_audio_buf->block);
	 	}else {
#ifdef DEBUG_LOCKING
			printk("no need for waking\n");
#endif
			restore_intr(intlevel);
		}
	}
}

static inline int i810_get_free_write_space(struct i810_state *state)
{
	struct dmabuf *dmabuf = &state->dmabuf;
	int free;

	i810_update_ptr(state);
	// catch underruns during playback
	if (dmabuf->count < 0) {
		dmabuf->count = 0;
		dmabuf->swptr = dmabuf->hwptr;
	}
	free = dmabuf->dmasize - dmabuf->count;
	free -= (dmabuf->hwptr % dmabuf->fragsize);
	if(free < 0)
		return(0);
	return(free);
}

static inline int i810_get_available_read_data(struct i810_state *state)
{
	struct dmabuf *dmabuf = &state->dmabuf;
	int avail;

	i810_update_ptr(state);
	// catch overruns during record
	if (dmabuf->count > dmabuf->dmasize) {
		dmabuf->count = dmabuf->dmasize;
		dmabuf->swptr = dmabuf->hwptr;
	}
	avail = dmabuf->count;
	avail -= (dmabuf->hwptr % dmabuf->fragsize);
	if(avail < 0)
		return(0);
	return(avail);
}

static int drain_dac(struct i810_state *state, int signals_allowed)
{
	//DAN: DECLARE_WAITQUEUE(wait, current);
	struct dmabuf *dmabuf = &state->dmabuf;
	unsigned long flags;
	//unsigned long tmo;
	int count;

	if (!dmabuf->ready)
		return 0;
	if(dmabuf->mapped) {
		stop_dac(state);
		return 0;
	}
	printk("DAN: drain_dac, adding to wait queue\n");
	
	//XXX nexus wait_queues needed
	//add_wait_queue(&dmabuf->wait, &wait);
	for (;;) {

		spin_lock_irqsave(&state->card->lock, flags);
		i810_update_ptr(state);
		count = dmabuf->count;
		spin_unlock_irqrestore(&state->card->lock, flags);

		if (count <= 0)
			break;

		/* 
		 * This will make sure that our LVI is correct, that our
		 * pointer is updated, and that the DAC is running.  We
		 * have to force the setting of dmabuf->trigger to avoid
		 * any possible deadlocks.
		 */
		if(!dmabuf->enable) {
			dmabuf->trigger = PCM_ENABLE_OUTPUT;
			i810_update_lvi(state,0);
		}
                if (signal_pending(current) && signals_allowed) {
                        break;
                }

		/* It seems that we have to set the current state to
		 * TASK_INTERRUPTIBLE every time to make the process
		 * really go to sleep.  This also has to be *after* the
		 * update_ptr() call because update_ptr is likely to
		 * do a wake_up() which will unset this before we ever
		 * try to sleep, resuling in a tight loop in this code
		 * instead of actually sleeping and waiting for an
		 * interrupt to wake us up!
		 */
		//set_current_state(TASK_INTERRUPTIBLE);
		/*
		 * set the timeout to significantly longer than it *should*
		 * take for the DAC to drain the DMA buffer
		 */
		//tmo = (count * HZ) / (dmabuf->rate);
		//if (!schedule_timeout(tmo >= 2 ? tmo : 2)){
		//	printk(KERN_ERR "i810_audio: drain_dac, dma timeout?\n");
		//	count = 0;
		//	break;
		//}
		//nexus_udelay(tmo * 600000);
	}
	//set_current_state(TASK_RUNNING);
	//remove_wait_queue(&dmabuf->wait, &wait);
	if(count > 0 && signal_pending(current) && signals_allowed)
		return -ERESTARTSYS;
	stop_dac(state);
	return 0;
}

static void i810_channel_interrupt(struct i810_card *card)
{
	int i, count;

#ifdef DEBUG_INTERRUPTS
	printk("CHANNEL ");
#endif
	for(i=0;i<NR_HW_CH;i++)
	{
		struct i810_state *state = card->states[i];
		struct i810_channel *c;
		struct dmabuf *dmabuf;
		unsigned long port = card->iobase;
		u16 status;
		int intlevel;

		if(!state)
			continue;
		if(!state->dmabuf.ready)
			continue;
		dmabuf = &state->dmabuf;
		if(dmabuf->enable & DAC_RUNNING) {
			c=dmabuf->write_channel;
		} else if(dmabuf->enable & ADC_RUNNING) {
			c=dmabuf->read_channel;
		} else	/* This can occur going from R/W to close */
			continue;
		
		port+=c->port;

		if(card->pci_id == PCI_DEVICE_ID_SI_7012)
			status = inw(port + OFF_PICB);
		else
			status = inw(port + OFF_SR);

#ifdef DEBUG_INTERRUPTS
		printk("NUM %d PORT %X IRQ ( ST%d ", c->num, c->port, status);
#endif
		if(status & DMA_INT_COMPLETE)
		{
			/* only wake_up() waiters if this interrupt signals
			 * us being beyond a userfragsize of data open or
			 * available, and i810_update_ptr() does that for
			 * us
			 */
			i810_update_ptr(state);
#ifdef DEBUG_INTERRUPTS
			printk("COMP %d ", dmabuf->hwptr /
					dmabuf->fragsize);
#endif
		}
		if(status & (DMA_INT_LVI | DMA_INT_DCH))
		{
			/* wake_up() unconditionally on LVI and DCH */
			i810_update_ptr(state);
			//wake_up(&dmabuf->wait);

			intlevel = disable_intr();
			if (curr_audio_buf->waiting > 0){
#ifdef DEBUG_LOCKING
				printk("unconditional waking: %d waiters\n", curr_audio_buf->waiting);
#endif
				if(curr_audio_buf->block != NULL)
					curr_audio_buf->waiting--;
				restore_intr(intlevel);
				if(curr_audio_buf->block != NULL)
					V_nexus(curr_audio_buf->block);			     
			}else {
#ifdef DEBUG_LOCKING
				printk("no need for unconditional waking\n");
#endif
				restore_intr(intlevel);
			}


#ifdef DEBUG_INTERRUPTS
			if(status & DMA_INT_LVI)
				printk("LVI ");
			if(status & DMA_INT_DCH)
				printk("DCH -");
#endif
			if(dmabuf->enable & DAC_RUNNING)
				count = dmabuf->count;
			else
				count = dmabuf->dmasize - dmabuf->count;
			if(count > 0) {
				outb(inb(port+OFF_CR) | 1, port+OFF_CR);
#ifdef DEBUG_INTERRUPTS
				printk(" CONTINUE ");
#endif
			} else {
				if (dmabuf->enable & DAC_RUNNING)
					__stop_dac(state);
				if (dmabuf->enable & ADC_RUNNING)
					__stop_adc(state);
				dmabuf->enable = 0;
#ifdef DEBUG_INTERRUPTS
				printk(" STOP ");
#endif
			}
		}
		if(card->pci_id == PCI_DEVICE_ID_SI_7012)
			outw(status & DMA_INT_MASK, port + OFF_PICB);
		else
			outw(status & DMA_INT_MASK, port + OFF_SR);
	}
#ifdef DEBUG_INTERRUPTS
	printk(")\n");
#endif
}

void i810_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	struct i810_card *card = (struct i810_card *)dev_id;
	u32 status;
	//printk("AUDIO INTERRUPT!!!!\n");

	spin_lock(&card->lock);

	status = inl(card->iobase + GLOB_STA);

	if(!(status & INT_MASK)) 
	{
		spin_unlock(&card->lock);
		return;  /* not for us */
	}
	//printk("I");

	if(status & (INT_PO|INT_PI|INT_MC))
		i810_channel_interrupt(card);

 	/* clear 'em */
	//printk("clearing status\n");
	outl(status & INT_MASK, card->iobase + GLOB_STA);
	spin_unlock(&card->lock);
}
PCI_InterruptHandlerFunc pci_intr_handler = i810_interrupt;


/* in this loop, dmabuf.count signifies the amount of data that is
   waiting to be copied to the user's buffer.  It is filled by the dma
   machine and drained by this loop. */

static ssize_t i810_read(struct file *file, char *buffer, size_t count, loff_t *ppos)
{
	printk("DAN: %s %d", __FILE__, __LINE__);
	return 0;
}
static ssize_t i810_read_nexus(char *buffer, size_t count, loff_t *ppos) {
	return i810_read(NULL, buffer, count, ppos);
}

#define SANITYCHECK() if((cnt < 0)||(cnt == -659930784)) { printk("I AM FUCKED in %s:%d, cnt = %d!!!\n", __FILE__, __LINE__, cnt); for(;;);}

/* in this loop, dmabuf.count signifies the amount of data that is
   waiting to be dma to the soundcard.  it is drained by the dma
   machine and filled by this loop. */
ssize_t i810_write(struct file *file, const char *buffer, size_t count, loff_t *ppos)
{
	struct i810_state *state = mycard->states[0];
	struct i810_card *card=state ? state->card : 0;
	struct dmabuf *dmabuf = &state->dmabuf;
	ssize_t ret;
	//unsigned long flags;
	unsigned int swptr = 0;
	int cnt, x;
	int intlevel;
        //DECLARE_WAITQUEUE(waita, current);
	int dbg = 0;

	count &= ~0x3; // kwalsh: bug... can't play last 3 bytes

#ifdef DEBUG2
	printk("i810_audio: i810_write called, count = %d\n", count);
#endif

	//if (ppos != &file->f_pos)
	// return -ESPIPE;
	if (dmabuf->mapped)
		return -ENXIO;
	if (dmabuf->enable & ADC_RUNNING)
		return -ENODEV;
	if (!dmabuf->write_channel) {
		dmabuf->ready = 0;
		dmabuf->write_channel = card->alloc_pcm_channel(card);
		if(!dmabuf->write_channel)
			return -EBUSY;
	}
	if (!dmabuf->ready && (ret = prog_dmabuf(state, 0)))
		return ret;
	// if (!access_ok(VERIFY_READ, buffer, count))
	// return -EFAULT;
	ret = 0;

        // add_wait_queue(&dmabuf->wait, &waita);
	
	intlevel = disable_intr();	
	if ((dmabuf->count >= (int)(dmabuf->dmasize - dmabuf->userfragsize))
	    ||(curr_audio_buf->waiting > 0)){
#ifdef DEBUG_LOCKING
		printk("sleeping: %d %d %d %d\n",
				dmabuf->count, dmabuf->dmasize, dmabuf->userfragsize,
				curr_audio_buf->waiting);
#endif
		if(curr_audio_buf->block != NULL)
			curr_audio_buf->waiting++;

		restore_intr(intlevel);

		if(curr_audio_buf->block == NULL)
			return 0;
		P(curr_audio_buf->block);
	}else {
#ifdef DEBUG_LOCKING
		printk("no need for sleeping\n");
#endif
		restore_intr(intlevel);
	}


	while (count > 0) {
#if 0
		set_current_state(TASK_INTERRUPTIBLE);
		spin_lock_irqsave(&state->card->lock, flags);
                if (PM_SUSPENDED(card)) {
                        spin_unlock_irqrestore(&card->lock, flags);
                        schedule();
                        if (signal_pending(current)) {
                                if (!ret) ret = -EAGAIN;
                                break;
                        }
                        continue;
                }
#endif
		swptr = dmabuf->swptr;

		cnt = i810_get_free_write_space(state);
		/* Bound the maximum size to how much we can copy to the
		 * dma buffer before we hit the end.  If we have more to
		 * copy then it will get done in a second pass of this
		 * loop starting from the beginning of the buffer.
		 */
		if(cnt > (dmabuf->dmasize - swptr))
			cnt = dmabuf->dmasize - swptr;
		//spin_unlock_irqrestore(&state->card->lock, flags);

#ifdef DEBUG2
		printk(KERN_INFO "i810_audio: i810_write: %d bytes available space\n", cnt);
#endif
			
		if (cnt > count)
			cnt = count;
		/* Lop off the last two bits to force the code to always
		 * write in full samples.  This keeps software that sets
		 * O_NONBLOCK but doesn't check the return value of the
		 * write call from getting things out of state where they
		 * think a full 4 byte sample was written when really only
		 * a portion was, resulting in odd sound and stereo
		 * hysteresis.
		 */

		//DAN: this will force it to loop because count makes cnt small, then lop off to 0
		cnt &= ~0x3;
		
		if (cnt <= 0) {
			unsigned long tmo;
			// There is data waiting to be played
			/*
			 * Force the trigger setting since we would
			 * deadlock with it set any other way
			 */
			dmabuf->trigger = PCM_ENABLE_OUTPUT;
			i810_update_lvi(state,0);
			//if (file->f_flags & O_NONBLOCK) {
			//if (!ret) ret = -EAGAIN;
			//goto ret;
			//}
			/* Not strictly correct but works */
			tmo = (dmabuf->dmasize * HZ * 2) / (dmabuf->rate * 4);
			/* There are two situations when sleep_on_timeout returns, one is when
			   the interrupt is serviced correctly and the process is waked up by
			   ISR ON TIME. Another is when timeout is expired, which means that
			   either interrupt is NOT serviced correctly (pending interrupt) or it
			   is TOO LATE for the process to be scheduled to run (scheduler latency)
			   which results in a (potential) buffer underrun. And worse, there is
			   NOTHING we can do to prevent it. */
#if 0
			if (!schedule_timeout(tmo >= 2 ? tmo : 2)) {
#ifdef DEBUG
				printk(KERN_ERR "i810_audio: playback schedule timeout, "
				       "dmasz %u fragsz %u count %i hwptr %u swptr %u\n",
				       dmabuf->dmasize, dmabuf->fragsize, dmabuf->count,
				       dmabuf->hwptr, dmabuf->swptr);
#endif
				/* a buffer underrun, we delay the recovery until next time the
				   while loop begin and we REALLY have data to play */
				//return ret;
			}
			if (signal_pending(current)) {
				if (!ret) ret = -ERESTARTSYS;
				goto ret;
			}
#endif
			continue;
		}

		memcpy(dmabuf->rawbuf+swptr,buffer,cnt);

		swptr = (swptr + cnt) % dmabuf->dmasize;

		dmabuf->swptr = swptr;
		dmabuf->count += cnt;

		count -= cnt;
		buffer += cnt;
		ret += cnt;
		//spin_unlock_irqrestore(&state->card->lock, flags);
	}
	if (swptr % dmabuf->fragsize) {
		x = dmabuf->fragsize - (swptr % dmabuf->fragsize);
		memset(dmabuf->rawbuf + swptr, '\0', x);
	}
	//ret:
	i810_update_lvi(state,0);
        //set_current_state(TASK_RUNNING);
        //remove_wait_queue(&dmabuf->wait, &waita);

	return ret;
}

/* No kernel lock - we have our own spinlock */
static unsigned int __attribute__((unused)) i810_poll(struct file *file, struct poll_table_struct *wait)
{
	printk("[i810] warning: unsupported %s called", __FUNCTION__);
	return 0;
}

static int __attribute__((unused)) i810_mmap(struct file *file, struct vm_area_struct *vma)
{
	printk("[i810] warning: unsupported %s called", __FUNCTION__);
	return 0;
}


int reset_speed_nexus(int val){
	struct i810_state *state = mycard->states[0]; //(struct i810_state *)file;
	struct dmabuf *dmabuf = &state->dmabuf;
	unsigned long flags;
	struct ac97_codec *codec = state->card->ac97_codec[0];

	//SNDCTL_DSP_SPEED
	if (val >= 0) {
		if ( (state->card->ac97_status & SPDIF_ON) ) {  /* S/PDIF Enabled */
			printk("spidf\n");
		/* AD1886 only supports 48000, need to check that */
			if ( i810_valid_spdif_rate ( codec, val ) ) {
				/* Set DAC rate */
				i810_set_spdif_output ( state, -1, 0 );
				stop_dac(state);
				dmabuf->ready = 0;
				spin_lock_irqsave(&state->card->lock, flags);
				i810_set_dac_rate(state, val);
				spin_unlock_irqrestore(&state->card->lock, flags);
				/* Set S/PDIF transmitter rate. */
				i810_set_spdif_output ( state, AC97_EA_SPSA_3_4, val );
				if ( ! (state->card->ac97_status & SPDIF_ON) ) {
					val = dmabuf->rate;
				}
			} else { /* Not a valid rate for S/PDIF, ignore it */
				val = dmabuf->rate;
			}
		} else {
			printk("no spidf\n");
			stop_dac(state);
			dmabuf->ready = 0;
			spin_lock_irqsave(&state->card->lock, flags);
			i810_set_dac_rate(state, val);
			spin_unlock_irqrestore(&state->card->lock, flags);
		}
	}
	return 0;
}


static int i810_ioctl(struct inode *inode, struct file *file, 
		      unsigned int cmd, unsigned long arg)
{
	printk("[i810] unsupported function %s called\n", __FUNCTION__);
}

int i810_ioctl_nexus(unsigned int cmd, Call_Handle call_handle, 
		     struct VarLen *destin, struct VarLen *destout){
	int dbg_ioctl = 0;
	struct i810_state *state = mycard->states[0]; //(struct i810_state *)file;
	struct i810_channel *c = NULL;
	struct dmabuf *dmabuf = &state->dmabuf;
	unsigned long flags;
	audio_buf_info abinfo;
	count_info cinfo;
	unsigned int i_glob_cnt;
	int val = 0, ret;
	struct ac97_codec *codec = state->card->ac97_codec[0];
	int soundversion = SOUND_VERSION, one=1, two=2, afmt_s16_le=AFMT_S16_LE;

	if (nexus_audio_fops != &i810_audio_fops) {
		printk("[i810] hacked ioctl called for incorrect device\n");
		return -1;
	}

	switch (cmd){
	case OSS_GETVERSION:
		printk("%s.%d check correctness\n", __FUNCTION__, __LINE__);
		abort();
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      &soundversion, 0, sizeof(int));
	case SNDCTL_DSP_RESET:
		if(dbg_ioctl){
			printk("SNDCTL_DSP_RESET\n");
		}
		spin_lock_irqsave(&state->card->lock, flags);
		if (dmabuf->enable == DAC_RUNNING) {
			c = dmabuf->write_channel;
			__stop_dac(state);
		}
		if (dmabuf->enable == ADC_RUNNING) {
			c = dmabuf->read_channel;
			__stop_adc(state);
		}
		if (c != NULL) {
			outb(2, state->card->iobase+c->port+OFF_CR);   /* reset DMA machine */
			while ( inb(state->card->iobase+c->port+OFF_CR) & 2 );
			outl((u32)state->card->chandma +
			     c->num*sizeof(struct i810_channel),
			     state->card->iobase+c->port+OFF_BDBAR);
			CIV_TO_LVI(state->card->iobase+c->port, 0);
		}

		spin_unlock_irqrestore(&state->card->lock, flags);
		//synchronize_irq();
		dmabuf->ready = 0;
		dmabuf->swptr = dmabuf->hwptr = 0;
		dmabuf->count = dmabuf->total_bytes = 0;
		return 0;

	case SNDCTL_DSP_SYNC:
		if(dbg_ioctl){
			printk("SNDCTL_DSP_SYNC\n");
		}
		if (dmabuf->enable != DAC_RUNNING)// || file->f_flags & O_NONBLOCK)
			return 0;
		if((val = drain_dac(state, 1)))
			return val;
		dmabuf->total_bytes = 0;
		return 0;

	case SNDCTL_DSP_SPEED: /* set smaple rate */
		if(dbg_ioctl){
			printk("SNDCTL_DSP_SPEED\n");
		}
		//val = arg;
		if(IPC_TransferFrom(call_handle, destin->desc_num, 
				    (void *)&val, 0, sizeof(int)))
		   return -EFAULT;
		curr_audio_buf->hz = val;
		if (val >= 0) {
			//if (file->f_mode & FMODE_WRITE) {
			if ( (state->card->ac97_status & SPDIF_ON) ) {  /* S/PDIF Enabled */
				/* AD1886 only supports 48000, need to check that */
				if ( i810_valid_spdif_rate ( codec, val ) ) {
					/* Set DAC rate */
					i810_set_spdif_output ( state, -1, 0 );
					stop_dac(state);
					dmabuf->ready = 0;
					spin_lock_irqsave(&state->card->lock, flags);
					i810_set_dac_rate(state, val);
					spin_unlock_irqrestore(&state->card->lock, flags);
					/* Set S/PDIF transmitter rate. */
					i810_set_spdif_output ( state, AC97_EA_SPSA_3_4, val );
					if ( ! (state->card->ac97_status & SPDIF_ON) ) {
						val = dmabuf->rate;
					}
				} else { /* Not a valid rate for S/PDIF, ignore it */
					val = dmabuf->rate;
				}
			} else {
				stop_dac(state);
				dmabuf->ready = 0;
				spin_lock_irqsave(&state->card->lock, flags);
				i810_set_dac_rate(state, val);
				spin_unlock_irqrestore(&state->card->lock, flags);
			}
			//}
#if 0
			if (file->f_mode & FMODE_READ) {
				stop_adc(state);
				dmabuf->ready = 0;
				spin_lock_irqsave(&state->card->lock, flags);
				i810_set_adc_rate(state, val);
				spin_unlock_irqrestore(&state->card->lock, flags);
			}
#endif
		}
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&dmabuf->rate, 0, sizeof(int));
				 

		//return 0;

	case SNDCTL_DSP_STEREO: /* set stereo or mono channel */
		if(dbg_ioctl){
			printk("SNDCTL_DSP_STEREO\n");
		}
		if (dmabuf->enable & DAC_RUNNING) {
			stop_dac(state);
		}
		if (dmabuf->enable & ADC_RUNNING) {
			stop_adc(state);
		}
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&one, 0, sizeof(int));

				 


	case SNDCTL_DSP_GETBLKSIZE:
		//if (file->f_mode & FMODE_WRITE) {
		if (!dmabuf->ready && (val = prog_dmabuf(state, 0)))
			return val;
		//}
#if 0
		if (file->f_mode & FMODE_READ) {
			if (!dmabuf->ready && (val = prog_dmabuf(state, 1)))
				return val;
		}
#endif
		if(dbg_ioctl){
			printk("SNDCTL_DSP_GETBLKSIZE %d\n", dmabuf->userfragsize);
		}
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&dmabuf->userfragsize, 0, sizeof(int));


				 

	case SNDCTL_DSP_GETFMTS: /* Returns a mask of supported sample format*/
		if(dbg_ioctl){
			printk("SNDCTL_DSP_GETFMTS\n");
		}
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&afmt_s16_le, 0, sizeof(int));



	case SNDCTL_DSP_SETFMT: /* Select sample format */
		if(dbg_ioctl){
			printk("SNDCTL_DSP_SETFMT\n");
		}
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&afmt_s16_le, 0, sizeof(int));




	case SNDCTL_DSP_CHANNELS:
		if(dbg_ioctl){
			printk("SNDCTL_DSP_CHANNELS\n");
		}
		if(IPC_TransferFrom(call_handle, destin->desc_num, 
					(void *)&val, 0, sizeof(int)))
		   return -EFAULT;

		if (val > 0) {
			if (dmabuf->enable & DAC_RUNNING) {
				stop_dac(state);
			}
			if (dmabuf->enable & ADC_RUNNING) {
				stop_adc(state);
			}
		} else {
			return IPC_TransferTo(call_handle, destout->desc_num, 
					      (void *)&state->card->channels, 0, sizeof(int));

		}

		/* ICH and ICH0 only support 2 channels */
		if ( state->card->pci_id == PCI_DEVICE_ID_INTEL_82801 
		     || state->card->pci_id == PCI_DEVICE_ID_INTEL_82901) 
			return IPC_TransferTo(call_handle, destout->desc_num, 
					      (void *)&two, 0, sizeof(int));
				


		/* Multi-channel support was added with ICH2. Bits in */
		/* Global Status and Global Control register are now  */
		/* used to indicate this.                             */

                i_glob_cnt = inl(state->card->iobase + GLOB_CNT);

		/* Current # of channels enabled */
		if ( i_glob_cnt & 0x0100000 )
			ret = 4;
		else if ( i_glob_cnt & 0x0200000 )
			ret = 6;
		else
			ret = 2;

		switch ( val ) {
		case 2: /* 2 channels is always supported */
			outl(i_glob_cnt & 0xffcfffff,
			     state->card->iobase + GLOB_CNT);
			/* Do we need to change mixer settings????  */
			break;
		case 4: /* Supported on some chipsets, better check first */
			if ( state->card->channels >= 4 ) {
				outl((i_glob_cnt & 0xffcfffff) | 0x100000,
				     state->card->iobase + GLOB_CNT);
				/* Do we need to change mixer settings??? */
			} else {
				val = ret;
			}
			break;
		case 6: /* Supported on some chipsets, better check first */
			if ( state->card->channels >= 6 ) {
				outl((i_glob_cnt & 0xffcfffff) | 0x200000,
				     state->card->iobase + GLOB_CNT);
				/* Do we need to change mixer settings??? */
			} else {
				val = ret;
			}
			break;
		default: /* nothing else is ever supported by the chipset */
			val = ret;
			break;
		}

		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&val, 0, sizeof(int));


	case SNDCTL_DSP_POST: /* the user has sent all data and is notifying us */
		/* we update the swptr to the end of the last sg segment then return */
		if(dbg_ioctl){
			printk("SNDCTL_DSP_POST\n");
		}
		if(!dmabuf->ready || (dmabuf->enable != DAC_RUNNING))
			return 0;
		if((dmabuf->swptr % dmabuf->fragsize) != 0) {
			val = dmabuf->fragsize - (dmabuf->swptr % dmabuf->fragsize);
			dmabuf->swptr += val;
			dmabuf->count += val;
		}
		return 0;

	case SNDCTL_DSP_SUBDIVIDE:
		if (dmabuf->subdivision)
			return -EINVAL;
		if(IPC_TransferFrom(call_handle, destin->desc_num, 
					(void *)&val, 0, sizeof(int)))
			return -EFAULT;
		if (val != 1 && val != 2 && val != 4)
			return -EINVAL;
		if(dbg_ioctl){
			printk("SNDCTL_DSP_SUBDIVIDE %d\n", val);
		}
		dmabuf->subdivision = val;
		dmabuf->ready = 0;
		return 0;

	case SNDCTL_DSP_SETFRAGMENT:
		if(IPC_TransferFrom(call_handle, destin->desc_num, 
					(void *)&val, 0, sizeof(int)))
			return -EFAULT;

		dmabuf->ossfragsize = 1<<(val & 0xffff);
		dmabuf->ossmaxfrags = (val >> 16) & 0xffff;
		if (!dmabuf->ossfragsize || !dmabuf->ossmaxfrags)
			return -EINVAL;
		/*
		 * Bound the frag size into our allowed range of 256 - 4096
		 */
		if (dmabuf->ossfragsize < 256)
			dmabuf->ossfragsize = 256;
		else if (dmabuf->ossfragsize > 4096)
			dmabuf->ossfragsize = 4096;
		/*
		 * The numfrags could be something reasonable, or it could
		 * be 0xffff meaning "Give me as much as possible".  So,
		 * we check the numfrags * fragsize doesn't exceed our
		 * 64k buffer limit, nor is it less than our 8k minimum.
		 * If it fails either one of these checks, then adjust the
		 * number of fragments, not the size of them.  It's OK if
		 * our number of fragments doesn't equal 32 or anything
		 * like our hardware based number now since we are using
		 * a different frag count for the hardware.  Before we get
		 * into this though, bound the maxfrags to avoid overflow
		 * issues.  A reasonable bound would be 64k / 256 since our
		 * maximum buffer size is 64k and our minimum frag size is
		 * 256.  On the other end, our minimum buffer size is 8k and
		 * our maximum frag size is 4k, so the lower bound should
		 * be 2.
		 */

		if(dmabuf->ossmaxfrags > 256)
			dmabuf->ossmaxfrags = 256;
		else if (dmabuf->ossmaxfrags < 2)
			dmabuf->ossmaxfrags = 2;

		val = dmabuf->ossfragsize * dmabuf->ossmaxfrags;
		while (val < 8192) {
			val <<= 1;
			dmabuf->ossmaxfrags <<= 1;
		}
		while (val > 65536) {
			val >>= 1;
			dmabuf->ossmaxfrags >>= 1;
		}
		dmabuf->ready = 0;
		if(dbg_ioctl){
			printk("SNDCTL_DSP_SETFRAGMENT 0x%x, %d, %d\n", val,
			       dmabuf->ossfragsize, dmabuf->ossmaxfrags);
		}

		return 0;
	case SNDCTL_DSP_GETOSPACE:
		//if (!(file->f_mode & FMODE_WRITE))
		//return -EINVAL;
		if (!dmabuf->ready && (val = prog_dmabuf(state, 0)) != 0)
			return val;
		spin_lock_irqsave(&state->card->lock, flags);
		i810_update_ptr(state);
		abinfo.fragsize = dmabuf->userfragsize;
		abinfo.fragstotal = dmabuf->userfrags;
		if (dmabuf->mapped)
 			abinfo.bytes = dmabuf->dmasize;
  		else
 			abinfo.bytes = i810_get_free_write_space(state);
		abinfo.fragments = abinfo.bytes / dmabuf->userfragsize;
		spin_unlock_irqrestore(&state->card->lock, flags);
#if defined(DEBUG) || defined(DEBUG_MMAP)
		printk("SNDCTL_DSP_GETOSPACE %d, %d, %d, %d\n", abinfo.bytes,
		       abinfo.fragsize, abinfo.fragments, abinfo.fragstotal);
#endif
		//return copy_to_user((void *)arg, &abinfo, sizeof(abinfo)) ? -EFAULT : 0;
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&abinfo, 0, sizeof(abinfo));
		return 0;
	case SNDCTL_DSP_GETOPTR:
		if (!dmabuf->ready && (val = prog_dmabuf(state, 0)) != 0)
			return val;
		spin_lock_irqsave(&state->card->lock, flags);
		val = i810_get_free_write_space(state);
		cinfo.bytes = dmabuf->total_bytes;
		cinfo.ptr = dmabuf->hwptr;
		cinfo.blocks = val/dmabuf->userfragsize;
		if (dmabuf->mapped && (dmabuf->trigger & PCM_ENABLE_OUTPUT)) {
			dmabuf->count += val;
			dmabuf->swptr = (dmabuf->swptr + val) % dmabuf->dmasize;
			__i810_update_lvi(state, 0);
		}
		spin_unlock_irqrestore(&state->card->lock, flags);
#if defined(DEBUG) || defined(DEBUG_MMAP)
		printk("SNDCTL_DSP_GETOPTR %d, %d, %d, %d\n", cinfo.bytes,
		       cinfo.blocks, cinfo.ptr, dmabuf->count);
#endif
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&cinfo, 0, sizeof(cinfo)) ? -EFAULT : 0;

	case SNDCTL_DSP_GETISPACE:
		//if (!(file->f_mode & FMODE_READ))
		if (1)	//DAN: We say we're always in write mode
			return -EINVAL;
		if (!dmabuf->ready && (val = prog_dmabuf(state, 1)) != 0)
			return val;
		spin_lock_irqsave(&state->card->lock, flags);
		abinfo.bytes = i810_get_available_read_data(state);
		abinfo.fragsize = dmabuf->userfragsize;
		abinfo.fragstotal = dmabuf->userfrags;
		abinfo.fragments = abinfo.bytes / dmabuf->userfragsize;
		spin_unlock_irqrestore(&state->card->lock, flags);
#if defined(DEBUG) || defined(DEBUG_MMAP)
		printk("SNDCTL_DSP_GETISPACE %d, %d, %d, %d\n", abinfo.bytes,
		       abinfo.fragsize, abinfo.fragments, abinfo.fragstotal);
#endif
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&abinfo, 0, sizeof(abinfo))? -EFAULT : 0;

	case SNDCTL_DSP_GETIPTR:
		//if (!(file->f_mode & FMODE_READ))
		if(1)	
			return -EINVAL;
		if (!dmabuf->ready && (val = prog_dmabuf(state, 0)) != 0)
			return val;
		spin_lock_irqsave(&state->card->lock, flags);
		val = i810_get_available_read_data(state);
		cinfo.bytes = dmabuf->total_bytes;
		cinfo.blocks = val/dmabuf->userfragsize;
		cinfo.ptr = dmabuf->hwptr;
		if (dmabuf->mapped && (dmabuf->trigger & PCM_ENABLE_INPUT)) {
			dmabuf->count -= val;
			dmabuf->swptr = (dmabuf->swptr + val) % dmabuf->dmasize;
			__i810_update_lvi(state, 1);
		}
		spin_unlock_irqrestore(&state->card->lock, flags);
#if defined(DEBUG) || defined(DEBUG_MMAP)
		printk("SNDCTL_DSP_GETIPTR %d, %d, %d, %d\n", cinfo.bytes,
		       cinfo.blocks, cinfo.ptr, dmabuf->count);
#endif
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&cinfo, 0, sizeof(cinfo)) ? -EFAULT : 0;

	case SNDCTL_DSP_NONBLOCK:
		if(dbg_ioctl){
			printk("SNDCTL_DSP_NONBLOCK\n");
		}
		//file->f_flags |= O_NONBLOCK;
		return 0;

	case SNDCTL_DSP_GETCAPS:
		if(dbg_ioctl){
			printk("SNDCTL_DSP_GETCAPS\n");
		}
		val = DSP_CAP_REALTIME|DSP_CAP_TRIGGER|DSP_CAP_MMAP|DSP_CAP_BIND;
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&val, 0, sizeof(int));

	case SNDCTL_DSP_GETTRIGGER:
		val = 0;
		if(dbg_ioctl){
			printk("SNDCTL_DSP_GETTRIGGER 0x%x\n", dmabuf->trigger);
		}
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&dmabuf->trigger, 0, sizeof(int));

	case SNDCTL_DSP_SETTRIGGER:
		if(IPC_TransferFrom(call_handle, destin->desc_num, 
					(void *)&val, 0, sizeof(int)))
			return -EFAULT;
#if defined(DEBUG) || defined(DEBUG_MMAP)
		printk("SNDCTL_DSP_SETTRIGGER 0x%x\n", val);
#endif
#if 0
		if((file->f_mode & FMODE_READ) && !(val & PCM_ENABLE_INPUT) && dmabuf->enable == ADC_RUNNING) {
			stop_adc(state);
		}
#endif		
		if(/*(file->f_mode & FMODE_WRITE) &&*/ !(val & PCM_ENABLE_OUTPUT) && dmabuf->enable == DAC_RUNNING) {
			stop_dac(state);
		}
		dmabuf->trigger = val;
		if(/*(file->f_mode & FMODE_WRITE) &&*/ (val & PCM_ENABLE_OUTPUT) && !(dmabuf->enable & DAC_RUNNING)) {
			if (!dmabuf->write_channel) {
				dmabuf->ready = 0;
				dmabuf->write_channel = state->card->alloc_pcm_channel(state->card);
				if (!dmabuf->write_channel)
					return -EBUSY;
			}
			if (!dmabuf->ready && (ret = prog_dmabuf(state, 0)))
				return ret;
			if (dmabuf->mapped) {
				spin_lock_irqsave(&state->card->lock, flags);
				i810_update_ptr(state);
				dmabuf->count = 0;
				dmabuf->swptr = dmabuf->hwptr;
				dmabuf->count = i810_get_free_write_space(state);
				dmabuf->swptr = (dmabuf->swptr + dmabuf->count) % dmabuf->dmasize;
				__i810_update_lvi(state, 0);
				spin_unlock_irqrestore(&state->card->lock, flags);
			} else
				start_dac(state);
		}
#if 0
		if((file->f_mode & FMODE_READ) && (val & PCM_ENABLE_INPUT) && !(dmabuf->enable & ADC_RUNNING)) {
			if (!dmabuf->read_channel) {
				dmabuf->ready = 0;
				dmabuf->read_channel = state->card->alloc_rec_pcm_channel(state->card);
				if (!dmabuf->read_channel)
					return -EBUSY;
			}
			if (!dmabuf->ready && (ret = prog_dmabuf(state, 1)))
				return ret;
			if (dmabuf->mapped) {
				spin_lock_irqsave(&state->card->lock, flags);
				i810_update_ptr(state);
				dmabuf->swptr = dmabuf->hwptr;
				dmabuf->count = 0;
				spin_unlock_irqrestore(&state->card->lock, flags);
			}
			i810_update_lvi(state, 1);
			start_adc(state);
		}
#endif
		return 0;

	case SNDCTL_DSP_SETDUPLEX:
		if(dbg_ioctl){
			printk("SNDCTL_DSP_SETDUPLEX\n");
		}
		return -EINVAL;

	case SNDCTL_DSP_GETODELAY:
#if 0
		if (!(file->f_mode & FMODE_WRITE))
			return -EINVAL;
#endif	
		spin_lock_irqsave(&state->card->lock, flags);
		i810_update_ptr(state);
		val = dmabuf->count;
		spin_unlock_irqrestore(&state->card->lock, flags);
		if(dbg_ioctl){
			printk("SNDCTL_DSP_GETODELAY %d\n", dmabuf->count);
		}
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&val, 0, sizeof(int));

	case SOUND_PCM_READ_RATE:
		if(dbg_ioctl){
			printk("SOUND_PCM_READ_RATE %d\n", dmabuf->rate);
		}
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&dmabuf->rate, 0, sizeof(int));

	case SOUND_PCM_READ_CHANNELS:
		if(dbg_ioctl){
			printk("SOUND_PCM_READ_CHANNELS\n");
		}
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&two, 0, sizeof(int));

	case SOUND_PCM_READ_BITS:
		if(dbg_ioctl){
			printk("SOUND_PCM_READ_BITS\n");
		}
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&afmt_s16_le, 0, sizeof(int));

	case SNDCTL_DSP_SETSPDIF: /* Set S/PDIF Control register */
		if(dbg_ioctl){
			printk("SNDCTL_DSP_SETSPDIF\n");
		}
		if(IPC_TransferFrom(call_handle, destin->desc_num, 
					(void *)&val, 0, sizeof(int)))
			return -EFAULT;

		/* Check to make sure the codec supports S/PDIF transmitter */

		if((state->card->ac97_features & 4)) {
			/* mask out the transmitter speed bits so the user can't set them */
			val &= ~0x3000;

			/* Add the current transmitter speed bits to the passed value */
			ret = i810_ac97_get(codec, AC97_SPDIF_CONTROL);
			val |= (ret & 0x3000);

			i810_ac97_set(codec, AC97_SPDIF_CONTROL, val);
			if(i810_ac97_get(codec, AC97_SPDIF_CONTROL) != val ) {
				printk(KERN_ERR "i810_audio: Unable to set S/PDIF configuration to 0x%04x.\n", val);
				return -EFAULT;
			}
		}
#ifdef DEBUG
		else 
			printk(KERN_WARNING "i810_audio: S/PDIF transmitter not avalible.\n");
#endif
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&val, 0, sizeof(int));

	case SNDCTL_DSP_GETSPDIF: /* Get S/PDIF Control register */
		if(dbg_ioctl){
			printk("SNDCTL_DSP_GETSPDIF\n");
		}
		if(IPC_TransferFrom(call_handle, destin->desc_num, 
					(void *)&val, 0, sizeof(int)))
			return -EFAULT;

		/* Check to make sure the codec supports S/PDIF transmitter */

		if(!(state->card->ac97_features & 4)) {
			if(dbg_ioctl){
				printk(KERN_WARNING "i810_audio: S/PDIF transmitter not avalible.\n");
			}
			val = 0;
		} else {
			val = i810_ac97_get(codec, AC97_SPDIF_CONTROL);
		}
		//return put_user((val & 0xcfff), (int *)arg);
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&val, 0, sizeof(int));
   			
	case SNDCTL_DSP_GETCHANNELMASK:
		if(dbg_ioctl){
			printk("SNDCTL_DSP_GETCHANNELMASK\n");
		}
		if(IPC_TransferFrom(call_handle, destin->desc_num, 
					(void *)&val, 0, sizeof(int)))
			return -EFAULT;
		
		/* Based on AC'97 DAC support, not ICH hardware */
		val = DSP_BIND_FRONT;
		if ( state->card->ac97_features & 0x0004 )
			val |= DSP_BIND_SPDIF;

		if ( state->card->ac97_features & 0x0080 )
			val |= DSP_BIND_SURR;
		if ( state->card->ac97_features & 0x0140 )
			val |= DSP_BIND_CENTER_LFE;

		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&val, 0, sizeof(int));

	case SNDCTL_DSP_BIND_CHANNEL:
		if(dbg_ioctl){
			printk("SNDCTL_DSP_BIND_CHANNEL\n");
		}
		if(IPC_TransferFrom(call_handle, destin->desc_num, 
					(void *)&val, 0, sizeof(int)))
			return -EFAULT;
		if ( val == DSP_BIND_QUERY ) {
			val = DSP_BIND_FRONT; /* Always report this as being enabled */
			if ( state->card->ac97_status & SPDIF_ON ) 
				val |= DSP_BIND_SPDIF;
			else {
				if ( state->card->ac97_status & SURR_ON )
					val |= DSP_BIND_SURR;
				if ( state->card->ac97_status & CENTER_LFE_ON )
					val |= DSP_BIND_CENTER_LFE;
			}
		} else {  /* Not a query, set it */
#if 0			
			if (!(file->f_mode & FMODE_WRITE))
				return -EINVAL;
#endif	
			if ( dmabuf->enable == DAC_RUNNING ) {
				stop_dac(state);
			}
			if ( val & DSP_BIND_SPDIF ) {  /* Turn on SPDIF */
				/*  Ok, this should probably define what slots
				 *  to use. For now, we'll only set it to the
				 *  defaults:
				 * 
				 *   non multichannel codec maps to slots 3&4
				 *   2 channel codec maps to slots 7&8
				 *   4 channel codec maps to slots 6&9
				 *   6 channel codec maps to slots 10&11
				 *
				 *  there should be some way for the app to
				 *  select the slot assignment.
				 */
	
				i810_set_spdif_output ( state, AC97_EA_SPSA_3_4, dmabuf->rate );
				if ( !(state->card->ac97_status & SPDIF_ON) )
					val &= ~DSP_BIND_SPDIF;
			} else {
				int mask;
				int channels;

				/* Turn off S/PDIF if it was on */
				if ( state->card->ac97_status & SPDIF_ON ) 
					i810_set_spdif_output ( state, -1, 0 );
				
				mask = val & (DSP_BIND_FRONT | DSP_BIND_SURR | DSP_BIND_CENTER_LFE);
				switch (mask) {
				case DSP_BIND_FRONT:
					channels = 2;
					break;
				case DSP_BIND_FRONT|DSP_BIND_SURR:
					channels = 4;
					break;
				case DSP_BIND_FRONT|DSP_BIND_SURR|DSP_BIND_CENTER_LFE:
					channels = 6;
					break;
				default:
					val = DSP_BIND_FRONT;
					channels = 2;
					break;
				}
				i810_set_dac_channels ( state, channels );

				/* check that they really got turned on */
				if ( !state->card->ac97_status & SURR_ON )
					val &= ~DSP_BIND_SURR;
				if ( !state->card->ac97_status & CENTER_LFE_ON )
					val &= ~DSP_BIND_CENTER_LFE;
			}
		}
		return IPC_TransferTo(call_handle, destout->desc_num, 
				      (void *)&val, 0, sizeof(int));

		
	case SNDCTL_DSP_MAPINBUF:
	case SNDCTL_DSP_MAPOUTBUF:
	case SNDCTL_DSP_SETSYNCRO:
	case SOUND_PCM_WRITE_FILTER:
	case SOUND_PCM_READ_FILTER:
		if(dbg_ioctl){
			printk("SNDCTL_* -EINVAL\n");
		}
		return -EINVAL;

	}
	return -EINVAL;
}

static int __attribute__((unused)) i810_open(struct inode *inode, struct file *file)
{
	printk("DAN: %s %d", __FILE__, __LINE__);
	return 0;
}

static struct file_operations i810_audio_fops = {
	owner:		THIS_MODULE,
	//llseek:		i810panic,
	read:		i810_read,
	write:		i810_write,
	poll:		i810_poll,
	ioctl:		i810_ioctl,
	mmap:		i810_mmap,
	open:		i810_open,
	//release:	i810_release
};

// NEXUS: derived from i810_open
int i810_myinit(void)
{
	int i = 0;
	struct i810_card *card = mycard;
	struct i810_state *state = NULL;
	struct dmabuf *dmabuf = NULL;

	default_audio_buf.block = NULL;
	default_audio_buf.waiting = 0;

	/* find an avaiable virtual channel (instance of /dev/dsp) */
	while (card != NULL) {
		/*
		 * If we are initializing and then fail, card could go
		 * away unuexpectedly while we are in the for() loop.
		 * So, check for card on each iteration before we check
		 * for card->initializing to avoid a possible oops.
		 * This usually only matters for times when the driver is
		 * autoloaded by kmod.
		 */
		for (i = 0; i < 50 && card && card->initializing; i++) {
			mdelay(600);
		}
		for (i = 0; i < NR_HW_CH && card && !card->initializing; i++) {
			if (card->states[i] == NULL) {
				state = card->states[i] = (struct i810_state *)
					kmalloc(sizeof(struct i810_state), 0);
				if (state == NULL)
					return -ENOMEM;
				memset(state, 0, sizeof(struct i810_state));
				dmabuf = &state->dmabuf;
				goto found_virt;
			}
		}
		card = card->next;
	}
	/* no more virtual channel avaiable */
	if (!state)
		return -ENODEV;

found_virt:
	/* initialize the virtual channel */
	state->virt = i;
	state->card = card;
	state->magic = I810_STATE_MAGIC;
	// init_waitqueue_head(&dmabuf->wait);
	// init_MUTEX(&state->open_sem);
	//printk("i810: setting state to 0x%p\n", state);
	//*private_data = (void*)state;
	dmabuf->trigger = 0;

	/* allocate hardware channels */
	{
		if((dmabuf->write_channel = card->alloc_pcm_channel(card)) == NULL) {
			/* make sure we free the record channel allocated above */
			kfree (card->states[i]);
			card->states[i] = NULL;;
			return -EBUSY;
		}
		/* Initialize to 8kHz?  What if we don't support 8kHz? */
		/*  Let's change this to check for S/PDIF stuff */
	
		dmabuf->trigger |= PCM_ENABLE_OUTPUT;
		// if ( spdif_locked ) {
		// i810_set_dac_rate(state, spdif_locked);
		// i810_set_spdif_output(state, AC97_EA_SPSA_3_4, spdif_locked);
		// } else {
			i810_set_dac_rate(state, 8000);
			/* Put the ACLink in 2 channel mode by default */
			i = inl(card->iobase + GLOB_CNT);
			outl(i & 0xffcfffff, card->iobase + GLOB_CNT);
			// }
	}
		
	/* set default sample format. According to OSS Programmer's Guide  /dev/dsp
	   should be default to unsigned 8-bits, mono, with sample rate 8kHz and
	   /dev/dspW will accept 16-bits sample, but we don't support those so we
	   set it immediately to stereo and 16bit, which is all we do support */
	dmabuf->fmt |= I810_FMT_16BIT | I810_FMT_STEREO;
	dmabuf->ossfragsize = 0;
	dmabuf->ossmaxfrags  = 0;
	dmabuf->subdivision  = 0;

	state->open_mode = FMODE_WRITE;

	nexus_audio_fops = &i810_audio_fops;
	return 0;
}

#if 0
static struct device_audio_ops i810_devops = {
	read:		i810_read_nexus,
	write:		i810_write,
	setrate:	reset_speed_nexus,
	ioctl:          i810_ioctl_nexus,
	set_current_audio_buf:   i810_set_current_audio_buf,
	unset_current_audio_buf:   i810_unset_current_audio_buf,
	//open:		i810_open,
};

NexusLog *audiolog;

void i810_dump_log(void){
	printk("dump of audiolog: \n");
	klog_dump(audiolog);
	printk("end of dump\n ");

	klog(audiolog, "hello");

	printk("dump of audiolog: \n");
	klog_dump(audiolog);
	printk("end of dump\n ");

	klog_send(audiolog, "LOG_AUDIO");
}
void i810_create_log(void){
	audiolog = klog_new(65536);
}

int i810_create_log_shell(int ac, char **av){
	i810_create_log();
	return 0;
}
int i810_dump_log_shell(int ac, char **av){
	i810_dump_log();
	return 0;
}
DECLARE_SHELL_COMMAND(audio_dumplog, i810_dump_log_shell, "-- dump audio log to disk");
DECLARE_SHELL_COMMAND(audio_createlog, i810_create_log_shell, "-- create audio log");
#endif

/* Write AC97 codec registers */
static u16 i810_ac97_get_mmio(struct ac97_codec *dev, u8 reg)
{
	struct i810_card *card = dev->private_data;
	int count = 100;
	u16 reg_set = IO_REG_OFF(dev) | (reg&0x7f);
	
	while(count-- && (readb(card->iobase_mmio + CAS) & 1)) 
		udelay(1);
	
#ifdef DEBUG_MMIO
	{
		u16 ans = readw(card->ac97base_mmio + reg_set);
		printk(KERN_DEBUG "i810_audio: ac97_get_mmio(%d) -> 0x%04X\n", ((int) reg_set) & 0xffff, (u32) ans);
		if(audiolog)
			klog(audiolog, "i810_audio: ac97_get_mmio(%d) -> 0x%04X\n", ((int) reg_set) & 0xffff, (u32) ans);
		return ans;
	}
#else
	return readw(card->ac97base_mmio + reg_set);
#endif
}

static u16 i810_ac97_get_io(struct ac97_codec *dev, u8 reg)
{
	struct i810_card *card = dev->private_data;
	int count = 100;
	u16 reg_set = IO_REG_OFF(dev) | (reg&0x7f);
	
	while(count-- && (inb(card->iobase + CAS) & 1)) 
		udelay(1);
	
	return inw(card->ac97base + reg_set);
}

static void i810_ac97_set_mmio(struct ac97_codec *dev, u8 reg, u16 data)
{
	struct i810_card *card = dev->private_data;
	int count = 100;
	u16 reg_set = IO_REG_OFF(dev) | (reg&0x7f);
	
	while(count-- && (readb(card->iobase_mmio + CAS) & 1)) 
		udelay(1);
	
	writew(data, card->ac97base_mmio + reg_set);

#ifdef DEBUG_MMIO
	printk(KERN_DEBUG "i810_audio: ac97_set_mmio(0x%04X, %d)\n", (u32) data, ((int) reg_set) & 0xffff);
	if(audiolog)
		klog(audiolog, "i810_audio: ac97_set_mmio(0x%04X, %d)\n", (u32) data, ((int) reg_set) & 0xffff);
#endif
}

static void i810_ac97_set_io(struct ac97_codec *dev, u8 reg, u16 data)
{
	struct i810_card *card = dev->private_data;
	int count = 100;
	u16 reg_set = IO_REG_OFF(dev) | (reg&0x7f);
	
	while(count-- && (inb(card->iobase + CAS) & 1)) 
		udelay(1);
	
        outw(data, card->ac97base + reg_set);
}

static u16 i810_ac97_get(struct ac97_codec *dev, u8 reg)
{
	struct i810_card *card = dev->private_data;
	u16 ret;
	
	spin_lock(&card->ac97_lock);
	if (card->use_mmio) {
		ret = i810_ac97_get_mmio(dev, reg);
	}
	else {
		ret = i810_ac97_get_io(dev, reg);
	}
	spin_unlock(&card->ac97_lock);
	
	return ret;
}

static void i810_ac97_set(struct ac97_codec *dev, u8 reg, u16 data)
{
	struct i810_card *card = dev->private_data;
	
	spin_lock(&card->ac97_lock);
	if (card->use_mmio) {
		i810_ac97_set_mmio(dev, reg, data);
	}
	else {
		i810_ac97_set_io(dev, reg, data);
	}
	spin_unlock(&card->ac97_lock);
}


/* OSS /dev/mixer file operation methods */

static int i810_open_mixdev(struct inode *inode, struct file *file)
{
	printk("DAN: %s %d", __FILE__, __LINE__);
	return -ENODEV;
}

static int i810_ioctl_mixdev(struct inode *inode, struct file *file, unsigned int cmd,
				unsigned long arg)
{
	struct ac97_codec *codec = (struct ac97_codec *)file->private_data;

	return codec->mixer_ioctl(codec, cmd, arg);
}

static /*const*/ struct file_operations i810_mixer_fops = {
	owner:		THIS_MODULE,
	//llseek:		i810panic,
	ioctl:		i810_ioctl_mixdev,
	open:		i810_open_mixdev,
};

/* AC97 codec initialisation.  These small functions exist so we don't
   duplicate code between module init and apm resume */

static inline int i810_ac97_exists(struct i810_card *card, int ac97_number)
{
	u32 reg = inl(card->iobase + GLOB_STA);
	//printk("read 0x%x from 0x%lx\n", reg, card->iobase + GLOB_STA);
	switch (ac97_number) {
	case 0:
		return reg & (1<<8);
	case 1: 
		return reg & (1<<9);
	case 2:
		return reg & (1<<28);
	}
	return 0;
}

static inline int i810_ac97_enable_variable_rate(struct ac97_codec *codec)
{
	i810_ac97_set(codec, AC97_EXTENDED_STATUS, 9);
	i810_ac97_set(codec,AC97_EXTENDED_STATUS,
		      i810_ac97_get(codec, AC97_EXTENDED_STATUS)|0xE800);
	
	return (i810_ac97_get(codec, AC97_EXTENDED_STATUS)&1);
}


static int i810_ac97_probe_and_powerup(struct i810_card *card,struct ac97_codec *codec)
{
	/* Returns 0 on failure */
	int i;

	if (ac97_probe_codec(codec) == 0) return 0;
	
	/* power it all up */
	i810_ac97_set(codec, AC97_POWER_CONTROL,
		      i810_ac97_get(codec, AC97_POWER_CONTROL) & ~0x7f00);

	/* wait for analog ready */
	for (i=10; i && ((i810_ac97_get(codec, AC97_POWER_CONTROL) & 0xf) != 0xf); i--)
	{
		//set_current_state(TASK_UNINTERRUPTIBLE);
		//schedule_timeout(HZ/20);
		//XXX do some alarms
		mdelay(600);
	} 
	return i;
}

/**
 *	i810_ac97_power_up_bus	-	bring up AC97 link
 *	@card : ICH audio device to power up
 *
 *	Bring up the ACLink AC97 codec bus
 */
 
static int i810_ac97_power_up_bus(struct i810_card *card)
{	
	u32 reg = inl(card->iobase + GLOB_CNT);
	int i;
	int primary_codec_id = 0;

	if((reg&2)==0)	/* Cold required */
		reg|=2;
	else
		reg|=4;	/* Warm */
		
	reg&=~8;	/* ACLink on */
	
	/* At this point we deassert AC_RESET # */
	outl(reg , card->iobase + GLOB_CNT);

	/* We must now allow time for the Codec initialisation.
	   600mS is the specified time */
	   	
	for(i=0;i<10;i++)
	{
		if((inl(card->iobase+GLOB_CNT)&4)==0)
			break;

		///set_current_state(TASK_UNINTERRUPTIBLE);
		//schedule_timeout(HZ/20);
		mdelay(600);
	}
	if(i==10)
	{
		printk(KERN_ERR "i810_audio: AC'97 reset failed.\n");
		return 0;
	}
	//set_current_state(TASK_UNINTERRUPTIBLE);
	//schedule_timeout(HZ/2);
	mdelay(600);

	/*
	 *	See if the primary codec comes ready. This must happen
	 *	before we start doing DMA stuff
	 */	
	/* see i810_ac97_init for the next 7 lines (jsaw) */
	inw(card->ac97base);
	if ((card->pci_id == PCI_DEVICE_ID_INTEL_ICH4 || card->pci_id == PCI_DEVICE_ID_INTEL_ICH5)
	    && (card->use_mmio)) {
		printk(KERN_INFO "i810_audio: Primary codec has ID %d\n",
		       primary_codec_id);
	}
	if(! i810_ac97_exists(card, primary_codec_id))
	{
		printk(KERN_INFO "i810_audio: Codec not ready.. wait.. ");
		//set_current_state(TASK_UNINTERRUPTIBLE);
		//schedule_timeout(HZ);	/* actually 600mS by the spec */
		mdelay(600);

		if(i810_ac97_exists(card, primary_codec_id))
			printk("OK\n");
		else 
			printk("no response.\n");
	}
	inw(card->ac97base);
	return 1;
}

static int __init i810_ac97_init(struct i810_card *card)
{
	int num_ac97 = 0;
	int ac97_id;
	int total_channels = 0;
	int nr_ac97_max = card_cap[card->pci_id_internal].nr_ac97;
	struct ac97_codec *codec;
	u16 eid;
	u32 reg;
	int dbg = 0;


	if(!i810_ac97_power_up_bus(card)) return 0;


	/* Number of channels supported */
	/* What about the codec?  Just because the ICH supports */
	/* multiple channels doesn't mean the codec does.       */
	/* we'll have to modify this in the codec section below */
	/* to reflect what the codec has.                       */
	/* ICH and ICH0 only support 2 channels so don't bother */
	/* to check....                                         */

	card->channels = 2;
	reg = inl(card->iobase + GLOB_STA);
	if ( reg & 0x0200000 )
		card->channels = 6;
	else if ( reg & 0x0100000 )
		card->channels = 4;
	printk(KERN_INFO "i810_audio: Audio Controller supports %d channels.\n", card->channels);
	printk(KERN_INFO "i810_audio: Defaulting to base 2 channel mode.\n");
	reg = inl(card->iobase + GLOB_CNT);
	outl(reg & 0xffcfffff, card->iobase + GLOB_CNT);
		
	for (num_ac97 = 0; num_ac97 < NR_AC97; num_ac97++) 
		card->ac97_codec[num_ac97] = NULL;

	/*@FIXME I don't know, if I'm playing to safe here... (jsaw) */
	if ((nr_ac97_max > 2) && !card->use_mmio) nr_ac97_max = 2;

	for (num_ac97 = 0; num_ac97 < nr_ac97_max; num_ac97++) {
		/* codec reset */
		printk(KERN_INFO "i810_audio: Resetting connection %d\n", num_ac97);
		if (card->use_mmio) readw(card->ac97base_mmio + 0x80*num_ac97);
		else inw(card->ac97base + 0x80*num_ac97);

		/* If we have the SDATA_IN Map Register, as on ICH4, we
		   do not loop thru all possible codec IDs but thru all 
		   possible IO channels. Bit 0:1 of SDM then holds the 
		   last codec ID spoken to. 
		*/
		if ((card->pci_id == PCI_DEVICE_ID_INTEL_ICH4 || card->pci_id == PCI_DEVICE_ID_INTEL_ICH5)
		    && (card->use_mmio)) {
			ac97_id = (int) readl(card->iobase_mmio + SDM) & 0x3;
			printk(KERN_INFO "i810_audio: Connection %d with codec id %d\n",
			       num_ac97, ac97_id);
		}
		else {
			ac97_id = num_ac97;
		}

		/* The ICH programmer's reference says you should   */
		/* check the ready status before probing. So we chk */
		/*   What do we do if it's not ready?  Wait and try */
		/*   again, or abort?                               */
		if (!i810_ac97_exists(card, ac97_id)) {
			if(num_ac97 == 0)
				printk(KERN_ERR "i810_audio: Primary codec not ready.\n");
		}
		
		if ((codec = ac97_alloc_codec()) == NULL)
			return -ENOMEM;

		/* initialize some basic codec information, other fields will be filled
		   in ac97_probe_codec */
		codec->private_data = card;
		codec->id = ac97_id;
		card->ac97_id_map[ac97_id] = num_ac97 * 0x80;

		if (card->use_mmio) {	
			codec->codec_read = i810_ac97_get_mmio;
			codec->codec_write = i810_ac97_set_mmio;
		}
		else {
			codec->codec_read = i810_ac97_get_io;
			codec->codec_write = i810_ac97_set_io;
		}
	
		if(!i810_ac97_probe_and_powerup(card,codec)) {
			printk(KERN_ERR "i810_audio: timed out waiting for codec %d analog ready.\n", ac97_id);
			ac97_release_codec(codec);
			break;	/* it didn't work */
		}
		/* Store state information about S/PDIF transmitter */
		card->ac97_status = 0;
		
		/* Don't attempt to get eid until powerup is complete */
		eid = i810_ac97_get(codec, AC97_EXTENDED_ID);

		if(eid==0xFFFF)
		{
			printk(KERN_WARNING "i810_audio: no codec attached ?\n");
			ac97_release_codec(codec);
			break;
		}
		
		/* Check for an AC97 1.0 soft modem (ID1) */
		
		if(codec->modem)
		{
			printk(KERN_WARNING "i810_audio: codec %d is a softmodem - skipping.\n", ac97_id);
			ac97_release_codec(codec);
			continue;
		}
		
		card->ac97_features = eid;

		/* Now check the codec for useful features to make up for
		   the dumbness of the 810 hardware engine */

		if(!(eid&0x0001))
			printk(KERN_WARNING "i810_audio: only 48Khz playback available.\n");
		else
		{
			if(!i810_ac97_enable_variable_rate(codec)) {
				printk(KERN_WARNING "i810_audio: Codec refused to allow VRA, using 48Khz only.\n");
				card->ac97_features&=~1;
			}			
		}
   		
		/* Turn on the amplifier */

		codec->codec_write(codec, AC97_POWER_CONTROL, 
			 codec->codec_read(codec, AC97_POWER_CONTROL) & ~0x8000);
				
		/* Determine how many channels the codec(s) support   */
		/*   - The primary codec always supports 2            */
		/*   - If the codec supports AMAP, surround DACs will */
		/*     automaticlly get assigned to slots.            */
		/*     * Check for surround DACs and increment if     */
		/*       found.                                       */
		/*   - Else check if the codec is revision 2.2        */
		/*     * If surround DACs exist, assign them to slots */
		/*       and increment channel count.                 */

		/* All of this only applies to ICH2 and above. ICH    */
		/* and ICH0 only support 2 channels.  ICH2 will only  */
		/* support multiple codecs in a "split audio" config. */
		/* as described above.                                */

		/* TODO: Remove all the debugging messages!           */

		if((eid & 0xc000) == 0) /* primary codec */
			total_channels += 2; 

		if(eid & 0x200) { /* GOOD, AMAP support */
			if (eid & 0x0080) /* L/R Surround channels */
				total_channels += 2;
			if (eid & 0x0140) /* LFE and Center channels */
				total_channels += 2;
			printk("i810_audio: AC'97 codec %d supports AMAP, total channels = %d\n", ac97_id, total_channels);
		} else if (eid & 0x0400) {  /* this only works on 2.2 compliant codecs */
			eid &= 0xffcf;
			if((eid & 0xc000) != 0)	{
				switch ( total_channels ) {
					case 2:
						/* Set dsa1, dsa0 to 01 */
						eid |= 0x0010;
						break;
					case 4:
						/* Set dsa1, dsa0 to 10 */
						eid |= 0x0020;
						break;
					case 6:
						/* Set dsa1, dsa0 to 11 */
						eid |= 0x0030;
						break;
				}
				total_channels += 2;
			}
			i810_ac97_set(codec, AC97_EXTENDED_ID, eid);
			eid = i810_ac97_get(codec, AC97_EXTENDED_ID);
			printk("i810_audio: AC'97 codec %d, new EID value = 0x%04x\n", ac97_id, eid);
			if (eid & 0x0080) /* L/R Surround channels */
				total_channels += 2;
			if (eid & 0x0140) /* LFE and Center channels */
				total_channels += 2;
			printk("i810_audio: AC'97 codec %d, DAC map configured, total channels = %d\n", ac97_id, total_channels);
		} else {
			printk("i810_audio: AC'97 codec %d Unable to map surround DAC's (or DAC's not present), total channels = %d\n", ac97_id, total_channels);
		}

		if ((codec->dev_mixer = register_sound_mixer(&i810_mixer_fops, -1)) < 0) {
			printk(KERN_ERR "i810_audio: couldn't register mixer!\n");
			ac97_release_codec(codec);
			break;
		}

		card->ac97_codec[num_ac97] = codec;
	}

	/* pick the minimum of channels supported by ICHx or codec(s) */
	card->channels = (card->channels > total_channels)?total_channels:card->channels;

	return num_ac97;
}

static void __init i810_configure_clocking (void)
{
	struct i810_card *card;
	struct i810_state *state;
	struct dmabuf *dmabuf;
	unsigned int i, offset, new_offset;
	unsigned long flags;

	card = devs;
	/* We could try to set the clocking for multiple cards, but
	 * can you even have more than one i810 in a machine?
	 * Besides, clocking is global, so unless someone actually
	 * thinks more than one i810 in a machine is possible and
	 * decides to rewrite that little bit, setting the rate for
	 * more than one card is a waste of time.
	 */
	if(card != NULL) {
		state = card->states[0] = (struct i810_state *)
			kmalloc(sizeof(struct i810_state), 0);
		if (state == NULL)
			return;
		memset(state, 0, sizeof(struct i810_state));
		dmabuf = &state->dmabuf;

		dmabuf->write_channel = card->alloc_pcm_channel(card);
		state->virt = 0;
		state->card = card;
		state->magic = I810_STATE_MAGIC;
		init_waitqueue_head(&dmabuf->wait);
		init_MUTEX(&state->open_sem);
		dmabuf->fmt = I810_FMT_STEREO | I810_FMT_16BIT;
		dmabuf->trigger = PCM_ENABLE_OUTPUT;
		i810_set_spdif_output(state, -1, 0);
		i810_set_dac_channels(state, 2);
		i810_set_dac_rate(state, 48000);
		if(prog_dmabuf(state, 0) != 0) {
			goto config_out_nodmabuf;
		}
		if(dmabuf->dmasize < 16384) {
			goto config_out;
		}
		dmabuf->count = dmabuf->dmasize;
		CIV_TO_LVI(card->iobase+dmabuf->write_channel->port, 31);
		flags = disable_intr();
		start_dac(state);
		offset = i810_get_dma_addr(state, 0);
		mdelay(50);
		new_offset = i810_get_dma_addr(state, 0);
		stop_dac(state);
		restore_intr(flags);
		i = new_offset - offset;
		printk("i810_audio: %d bytes in 50 milliseconds\n", i);
		if(i == 0)
			goto config_out;
		i = i / 4 * 20;
		int djwill_clocking_hack = 1;
		if(djwill_clocking_hack)printk("doing djwill clocking hack!\n");
		if ((i > 48500 || i < 47500) && (!djwill_clocking_hack)) {
			clocking = clocking * clocking / i;
			//clocking /= 2;
			printk("i810_audio: setting clocking to %d\n", clocking);
		}else
			printk("i810_audio: clocking stays at %d\n", clocking);
config_out:
		dealloc_dmabuf(state);
config_out_nodmabuf:
		state->card->free_pcm_channel(state->card,state->dmabuf.write_channel->num);
		kfree(state);
		card->states[0] = NULL;
		
		mycard = card;

	}
}

/* install the driver, we do not allocate hardware channel nor DMA buffer now, they are defered 
   until "ACCESS" time (in prog_dmabuf called by open/read/write/ioctl/mmap) */
   
static int __init i810_probe(struct pci_dev *pci_dev, const struct pci_device_id *pci_id)
{
	struct i810_card *card;
	if (pci_enable_device(pci_dev))
		return -EIO;

	if (pci_set_dma_mask(pci_dev, I810_DMA_MASK)) {
		printk(KERN_ERR "i810_audio: architecture does not support"
		       " 32bit PCI busmaster DMA\n");
		return -ENODEV;
	}
	
	if( pci_resource_start(pci_dev, 1) == 0)
	{
		/* MMIO only ICH5 .. here be dragons .. */
		printk(KERN_ERR "i810_audio: Pure MMIO interfaces not yet supported.\n");
		return -ENODEV;
	}

	if ((card = (struct i810_card *)kmalloc(sizeof(struct i810_card), 0)) == NULL) {
		printk(KERN_ERR "i810_audio: out of memory\n");
		return -ENOMEM;
	}
	memset(card, 0, sizeof(*card));

	card->initializing = 1;
	card->pci_dev = pci_dev;
	card->pci_id = pci_id->device;
	card->ac97base = pci_resource_start (pci_dev, 0);
	card->iobase = pci_resource_start (pci_dev, 1);


	/* if chipset could have mmio capability, check it */ 
	if (card_cap[pci_id->driver_data].flags & CAP_MMIO) {
		card->ac97base_mmio_phys = pci_resource_start (pci_dev, 2);
		card->iobase_mmio_phys = pci_resource_start (pci_dev, 3);

		if ((card->ac97base_mmio_phys) && (card->iobase_mmio_phys)) {
			card->use_mmio = 1;
		}
		else {
			card->ac97base_mmio_phys = 0;
			card->iobase_mmio_phys = 0;
		}
	}

	card->irq = pci_dev->irq;
	card->next = devs;
	card->magic = I810_CARD_MAGIC;
#ifdef CONFIG_PM
	card->pm_suspended=0;
#endif
	spin_lock_init(&card->lock);
	spin_lock_init(&card->ac97_lock);
	devs = card;

	pci_set_master(pci_dev);

	printk(KERN_INFO "i810: %s found at IO 0x%04lx and 0x%04lx, "
	       "MEM 0x%04lx and 0x%04lx, IRQ %d\n",
	       card_names[pci_id->driver_data], 
	       card->iobase, card->ac97base, 
	       card->ac97base_mmio_phys, card->iobase_mmio_phys,
	       card->irq);

	card->alloc_pcm_channel = i810_alloc_pcm_channel;
	card->alloc_rec_pcm_channel = i810_alloc_rec_pcm_channel;
	card->alloc_rec_mic_channel = i810_alloc_rec_mic_channel;
	card->free_pcm_channel = i810_free_pcm_channel;


	if ((card->channel = pci_alloc_consistent(pci_dev,
	    sizeof(struct i810_channel)*NR_HW_CH, &card->chandma)) == NULL) {
		printk(KERN_ERR "i810: cannot allocate channel DMA memory\n");
		goto out_mem;
	}

	{ /* We may dispose of this altogether some time soon, so... */
		struct i810_channel *cp = card->channel;

		cp[0].offset = 0;
		cp[0].port = 0x00;
		cp[0].num = 0;
		cp[1].offset = 0;
		cp[1].port = 0x10;
		cp[1].num = 1;
		cp[2].offset = 0;
		cp[2].port = 0x20;
		cp[2].num = 2;
	}

	/* claim our iospace and irq */
	request_region(card->iobase, 64, card_names[pci_id->driver_data]);
	request_region(card->ac97base, 256, card_names[pci_id->driver_data]);
	if (request_irq(card->irq, &i810_interrupt, SA_SHIRQ,
			card_names[pci_id->driver_data], card)) {
		printk(KERN_ERR "i810_audio: unable to allocate irq %d\n", card->irq);
		goto out_pio;
	}
	if (card->use_mmio) {
		if (request_mem_region(card->ac97base_mmio_phys, 512, "ich_audio MMBAR")) {
			if ((card->ac97base_mmio = ioremap(card->ac97base_mmio_phys, 512))) { /*@FIXME can ioremap fail? don't know (jsaw) */
				if (request_mem_region(card->iobase_mmio_phys, 256, "ich_audio MBBAR")) {
					if ((card->iobase_mmio = ioremap(card->iobase_mmio_phys, 256))) {
						printk(KERN_INFO "i810: %s mmio at 0x%04lx and 0x%04lx\n",
						       card_names[pci_id->driver_data], 
						       (unsigned long) card->ac97base_mmio, 
						       (unsigned long) card->iobase_mmio); 
					}
					else {
						iounmap(card->ac97base_mmio);
						release_mem_region(card->ac97base_mmio_phys, 512);
						release_mem_region(card->iobase_mmio_phys, 512);
						card->use_mmio = 0;
					}
				}
				else {
					iounmap(card->ac97base_mmio);
					release_mem_region(card->ac97base_mmio_phys, 512);
					card->use_mmio = 0;
				}
			}
		}
		else {
			card->use_mmio = 0;
		}
	}

	/* initialize AC97 codec and register /dev/mixer */
	if (i810_ac97_init(card) <= 0) {
		free_irq(card->irq, card);
		goto out_iospace;
	}
	pci_set_drvdata(pci_dev, card);
	if(clocking == 0) {
		clocking = 48000;
		i810_configure_clocking();
	}
	/* register /dev/dsp */
	if ((card->dev_audio = register_sound_dsp(&i810_audio_fops, -1)) < 0) {
		int i;
		printk(KERN_ERR "i810_audio: couldn't register DSP device!\n");
		free_irq(card->irq, card);
		for (i = 0; i < NR_AC97; i++)
		if (card->ac97_codec[i] != NULL) {
			unregister_sound_mixer(card->ac97_codec[i]->dev_mixer);
			ac97_release_codec(card->ac97_codec[i]);
		}
		goto out_iospace;
	}
 	card->initializing = 0;
	mycard = card;

	return 0;

out_iospace:
	if (card->use_mmio) {
		iounmap(card->ac97base_mmio);
		iounmap(card->iobase_mmio);
		release_mem_region(card->ac97base_mmio_phys, 512);
		release_mem_region(card->iobase_mmio_phys, 256);
	}
out_pio:	
	release_region(card->iobase, 64);
	release_region(card->ac97base, 256);
	//out_chan:
	pci_free_consistent(pci_dev, sizeof(struct i810_channel)*NR_HW_CH,
	    card->channel, card->chandma);
out_mem:
	kfree(card);
	return -ENODEV;
}

static void __devexit i810_remove(struct pci_dev *pci_dev)
{
	int i;
	struct i810_card *card = pci_get_drvdata(pci_dev);
	/* free hardware resources */
	free_irq(card->irq, devs);
	release_region(card->iobase, 64);
	release_region(card->ac97base, 256);
	if (card->use_mmio) {
		iounmap(card->ac97base_mmio);
		iounmap(card->iobase_mmio);
		release_mem_region(card->ac97base_mmio_phys, 512);
		release_mem_region(card->iobase_mmio_phys, 256);
	}

	/* unregister audio devices */
	for (i = 0; i < NR_AC97; i++)
		if (card->ac97_codec[i] != NULL) {
			unregister_sound_mixer(card->ac97_codec[i]->dev_mixer);
			ac97_release_codec(card->ac97_codec[i]);
			card->ac97_codec[i] = NULL;
		}
	unregister_sound_dsp(card->dev_audio);
	kfree(card);
}

#ifdef CONFIG_PM
static int i810_pm_suspend(struct pci_dev *dev, u32 pm_state)
{
        struct i810_card *card = pci_get_drvdata(dev);
        struct i810_state *state;
	unsigned long flags;
	struct dmabuf *dmabuf;
	int i,num_ac97;
#ifdef DEBUG
	printk("i810_audio: i810_pm_suspend called\n");
#endif
	if(!card) return 0;
	spin_lock_irqsave(&card->lock, flags);
	card->pm_suspended=1;
	for(i=0;i<NR_HW_CH;i++) {
		state = card->states[i];
		if(!state) continue;
		/* this happens only if there are open files */
		dmabuf = &state->dmabuf;
		if(dmabuf->enable & DAC_RUNNING ||
		   (dmabuf->count && (dmabuf->trigger & PCM_ENABLE_OUTPUT))) {
			state->pm_saved_dac_rate=dmabuf->rate;
			stop_dac(state);
		} else {
			state->pm_saved_dac_rate=0;
		}
		if(dmabuf->enable & ADC_RUNNING) {
			state->pm_saved_adc_rate=dmabuf->rate;	
			stop_adc(state);
		} else {
			state->pm_saved_adc_rate=0;
		}
		dmabuf->ready = 0;
		dmabuf->swptr = dmabuf->hwptr = 0;
		dmabuf->count = dmabuf->total_bytes = 0;
	}

	spin_unlock_irqrestore(&card->lock, flags);

	/* save mixer settings */
	for (num_ac97 = 0; num_ac97 < NR_AC97; num_ac97++) {
		struct ac97_codec *codec = card->ac97_codec[num_ac97];
		if(!codec) continue;
		for(i=0;i< SOUND_MIXER_NRDEVICES ;i++) {
			if((supported_mixer(codec,i)) &&
			   (codec->read_mixer)) {
				card->pm_saved_mixer_settings[i][num_ac97]=
					codec->read_mixer(codec,i);
			}
		}
	}
	pci_save_state(dev,card->pm_save_state); /* XXX do we need this? */
	pci_disable_device(dev); /* disable busmastering */
	pci_set_power_state(dev,3); /* Zzz. */

	return 0;
}


static int i810_pm_resume(struct pci_dev *dev)
{
	printk("DAN: %s %d", __FILE__, __LINE__);
	return 0;
}	
#endif /* CONFIG_PM */

MODULE_AUTHOR("");
MODULE_DESCRIPTION("Intel 810 audio support");
MODULE_LICENSE("GPL");
MODULE_PARM(ftsodell, "i");
MODULE_PARM(clocking, "i");
MODULE_PARM(strict_clocking, "i");
MODULE_PARM(spdif_locked, "i");

#define I810_MODULE_NAME "intel810_audio"

static struct pci_driver i810_pci_driver = {
	name:		I810_MODULE_NAME,
	id_table:	i810_pci_tbl,
	probe:		i810_probe,
	remove:		__devexit_p(i810_remove),
#ifdef CONFIG_PM
	suspend:	i810_pm_suspend,
	resume:		i810_pm_resume,
#endif /* CONFIG_PM */
};


int __init i810_init_module (void)
{
	if (!pci_present())   /* No PCI bus in this machine! */
		return -ENODEV;

	printk(KERN_INFO "Intel 810 + AC97 Audio, version "
	       DRIVER_VERSION ", " __TIME__ " " __DATE__ "\n");

	if (!pci_register_driver(&i810_pci_driver, DEVICE_AUDIO)) {
		pci_unregister_driver(&i810_pci_driver);
		printk("[i810] no device found\n");
                return -ENODEV;
	}

	if(ftsodell != 0) {
		printk("i810_audio: ftsodell is now a deprecated option.\n");
	}

	if(spdif_locked > 0 ) {
		if(spdif_locked == 32000 || spdif_locked == 44100 || spdif_locked == 48000) {
			printk("i810_audio: Enabling S/PDIF at sample rate %dHz.\n", spdif_locked);
		} else {
			printk("i810_audio: S/PDIF can only be locked to 32000, 44100, or 48000Hz.\n");
			spdif_locked = 0;
		}
	}
	
	return i810_myinit();
}

static void __exit i810_cleanup_module (void)
{
	pci_unregister_driver(&i810_pci_driver);
}

module_init(i810_init_module);
module_exit(i810_cleanup_module);

/*
Local Variables:
c-basic-offset: 8
End:
*/
