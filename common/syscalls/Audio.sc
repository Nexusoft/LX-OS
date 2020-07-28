syscall Audio {
  decls __callee__ {
    includefiles { "<nexus/defs.h>" }
    includefiles { "<nexus/ipd.h>" }
    includefiles { "<nexus/device.h>" }
    includefiles { "<nexus/audio.h>" }
    includefiles { "<nexus/thread-inline.h>" }
  }

  interface int Init(int block) {
    IPD *ipd = nexusthread_current_ipd();
    NexusDevice *nd = find_device(DEVICE_AUDIO, NULL);
    if (!nd) {
      printk_red("AudioInit: device not found!\n");
      return -SC_NOTFOUND;
    }
    NexusOpenDevice *nod = audio_init(nd, ipd, block);
    return ipd_add_open_device(ipd, nod);
  }

  interface int SetRate(int handle, int hz) {
    IPD *ipd = nexusthread_current_ipd();
    NexusOpenDevice *nod = ipd_get_open_device(ipd, DEVICE_AUDIO, handle);
    if (nod) return audio_setrate(nod, hz);
    else return -SC_INVALID;
  }

  interface int Ioctl(int handle, unsigned int cmd, unsigned int argvaddr) {
    int ret;

    IPD *ipd = nexusthread_current_ipd();
    Map *m = nexusthread_current_map();
    NexusOpenDevice *nod = ipd_get_open_device(ipd, DEVICE_AUDIO, handle);
    
    if (!nod) 
      return -SC_INVALID;

    ret = audio_ioctl(nod, cmd, argvaddr, m);

    return ret;
  }

  interface int Write(int handle, const void *data_src, unsigned int size) {
    if(size <= 0)
      return -1;

    IPD *ipd = nexusthread_current_ipd();
    unsigned char *data = galloc(size);
    //printk_red("malloced 0x%p\n", data);
#if 0
    if(((unsigned int)data == 0xc6903000)||((unsigned int)data == 0xc6902000)){
      printk_red("freeing2 0x%p %d\n", data, size);
      gfree(data);
    }
#endif

    if (!data) return -SC_NOMEM;

    NexusOpenDevice *nod = ipd_get_open_device(ipd, DEVICE_AUDIO, handle);
    if (!nod) return -1;

    if (peek_user(nexusthread_current_map(), (unsigned int)data_src, data, size) != 0) {
      gfree(data);
      printk_red("audio_write: access error\n");
      return -SC_ACCESSERROR;
    }

    int ret = audio_write(nod, data, size);
    //printk_red("freeing 0x%p\n", data);
    gfree(data);

    return ret;
  }
}
