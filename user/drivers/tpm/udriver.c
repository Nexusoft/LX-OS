/** NexusOS: userspace TPM driver */

#include <stdio.h>
#include <stdlib.h>

#include <nexus/FS.interface.h>
#include <nexus/IPC.interface.h>

#define TPM_BUFSIZE  4096

static int nexus_init(void)
{
    FSID parent;
    int port;

    port = IPC_CreatePort(0);
    if (port == -1) {
        fprintf(stderr, "[tpm] Failed to acquire IPC port\n");
        return -1;
    }

    parent = nexusfs_lookup(FSID_ROOT(KERNELFS_PORT), "dev");
    if (!FSID_isDir(parent)) {
        fprintf(stderr, "[tpm] Failed to find /dev\n");
        return -1;
    }

    nexusfs_mk_dev(parent, "tpm0", port);
    return port;
}

int main(int argc, char **argv)
{
    int tpmd_port, len, buflen;
    unsigned long reply_port;
    uint8_t buf[TPM_BUFSIZE];

    if (tpm_init()) {
        fprintf(stderr, "TPM driver not found\n");
        return -1;
    }

    tpmd_port = nexus_init();
    if (tpmd_port == -1)
        return -2;

    /* wait for incoming connections.
     * WARNING: RACE IN IPC CALLS WITH MULTIPLE CLIENTS
     * receive and handle commands
     *
     * NB: Loop does not terminate on bad input
     */
    while (1) {

        // retrieve request
        if ((buflen = IPC_Recv(tpmd_port, buf, sizeof(buf))) <= 0) {
            fprintf(stderr, "[tpm] IPC recv error\n");
            continue;
        }
        
        // retrieve reply port number
        if (IPC_Recv(tpmd_port, &reply_port, sizeof(reply_port)) != 
            sizeof(reply_port)) {
            fprintf(stderr, "[tpm] IPC recv (port) error\n");
            continue;
        }

        // write -- and read back response
        if ((len = tpm_write(NULL, buf, buflen, NULL)) <= 0) {
            fprintf(stderr, "[tpm] tpm_write error\n");
            continue;
        } 

        if ((buflen = tpm_read(NULL, buf, len, NULL) <= 0)) {
            fprintf(stderr, "[tpm] tpm_read error\n");
            continue;
        }
    
        // send back to device FS
        if (IPC_Send(reply_port, buf, buflen)) {
            fprintf(stderr, "[tpm] IPC send error\n");
            continue;
        }
    }

    IPC_DestroyPort(tpmd_port);

    return 0;
}
