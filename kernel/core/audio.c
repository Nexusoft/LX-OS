// wrapper for underlying audio devices, implements nexus audio abstraction

#include <nexus/defs.h>
#include <nexus/ipd.h>
#include <nexus/device.h>
#include <nexus/audio_private.h>
#include <nexus/thread-inline.h>

static void audio_focus_handler(NexusOpenDevice *nod, int focus) {
	AudioBuf *ab = (AudioBuf *)nod->odata;
	struct device_audio_ops *ops = nod->nd->data;
	if (focus) {
	  ops->setrate(ab->hz);
	  ops->set_current_audio_buf(ab);
	    // resume saved play
	} else {
	  ops->unset_current_audio_buf();
		// cancel current play
	}
}

NexusOpenDevice *audio_init(NexusDevice *nd, IPD *ipd, int block) {
	assert(nd->type == DEVICE_AUDIO);
	if (!nd->focus_handler)
		nd->focus_handler = audio_focus_handler;

	AudioBuf *ab = galloc(sizeof(AudioBuf));
	memset(ab, 0, sizeof(AudioBuf));
	
	if(block == 1){
	  ab->block = sema_new();
	  printk_red("setting BLOCKING audio!");
	}else{
	  ab->block = NULL;
	}
	ab->waiting = 0;

	ab->hz = 44100; // todo: read from device instead?

	return nexus_open_device(nd, ab);
}

int audio_setrate(NexusOpenDevice *nod, int hz) {
	AudioBuf *ab = (AudioBuf *)nod->odata;
	struct device_audio_ops *ops = nod->nd->data;
	int old = ab->hz;
	ab->hz = hz;
	if (nod->focused) {
		ops->setrate(hz);
	}
	return old;
}

int audio_write(NexusOpenDevice *nod, char *data, int len) {
	struct device_audio_ops *ops = nod->nd->data;

	if (!nod->focused) return 0; // XXX don't just block like this

	return ops->write(data, len, 0);
}

int audio_ioctl(NexusOpenDevice *nod, unsigned int cmd, unsigned long argvaddr, Map *m) {
	struct device_audio_ops *ops = nod->nd->data;

	if (!nod->focused) return 0; // XXX don't just block like this

	return ops->ioctl(cmd, argvaddr, m);
}

