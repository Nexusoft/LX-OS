/****************************************************************************/
/*                                                                          */
/*  transmit.c - send blobs to/from TPM, with optional debugging            */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/

#include <nexus/defs.h>
#include <nexus/device.h>
#include <libtcpa/tcpa.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>

/* optional verbose logging of data to/from tcpa chip */
#if 0
static void showBlob(unsigned char *blob, char *string, FILE * tcpa_logfp)
{
    uint32_t i, len;

    if (!tcpa_logfp)
        return;
    len = ntohl(*(uint32_t *) & blob[TCPA_PARAMSIZE_OFFSET]);
    fprintf(tcpa_logfp, "        %s length=%d\n        ", string, len);
    for (i = 0; i < len; i++) {
        if (i && !(i % 16)) {
            fprintf(tcpa_logfp, "\n        ");
        }
        fprintf(tcpa_logfp, "%.2X ", blob[i]);
    }
    fprintf(tcpa_logfp, "\n");
    fflush(tcpa_logfp);
}
#endif

uint32_t TPM_Transmit(unsigned char *blob, char *msg){
  int err, len;
  uint32_t size, ret;

  NexusDevice *dev = find_device(DEVICE_TPM, "tpm0");
  if (dev == NULL) {
    printk("TCPALIB: Can't find TPM Driver\n");
    return -1;
  }
  struct device_tpm_ops *tpm = dev->data;

  /* if (!tpm) {
    printk("Bad tpm struct\n");
    return -1;
  } */

  if ((err = tpm->open(NULL, NULL)) < 0) {
    printk("TCPALIB: Can't open TPM Driver %d\n", err);
    return -1;
  }

  size = ntohl(*(uint32_t *) & blob[TCPA_PARAMSIZE_OFFSET]);
  len = tpm->write(NULL, blob, size, NULL);
  if (len <= 0) {
    printk("TCPALIB: TPM write Error\n");
    tpm->release(NULL, NULL);
    return -1;
  }
  len = tpm->read(NULL, blob, TCPA_MAX_BUFF_SIZE, NULL);
  if (len <= 0) {
    printk("TCPALIB: TPM read Error\n");
    tpm->release(NULL, NULL);
    return -1;
  }
  //showBlob(blob, "From TPM", log);
  ret = ntohl(*(uint32_t *) & blob[TCPA_RETURN_OFFSET]);

  tpm->release(NULL, NULL);
#if 0
  close(tpmfp);
  if (log) {
    if (ret)
      fprintf(log, "    %s failed with error %d\n", msg, ret);
    else
      fprintf(log, "    %s succeeded\n", msg);
  }
#endif
  if (ret)
    printk("TPM_transmit %s failed with error %d\n", msg, ret);
  return (ret);
}
