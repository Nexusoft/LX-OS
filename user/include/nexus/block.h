/** NexusOS: block device driver interface

    This code enables a process to register an inode in /dev and handle
    random access block IO calls on this device. This interface serializes
    the request and automatically calls the correct callback from the
    passed nxblock_device_ops structure in the server.

    This code does not use a .svc interface to be fast. It is optimized for
    the IDE block device driver. Datatransfer occurs not through copying, 
    but through memory page sharing. 
 
    Underneath, it expects a device inode as implemented in RamFS. The inode
    interface is sequential, which is the main reason we need this interface
    on top */

#ifndef NXBLOCK_H
#define NXBLOCK_H

/// device implementation
//  supply to nxblock_serve to be called automatically when a process performs
//  an action on the registered device inode
//
//  calling conventions are similar to posix call equivalents
//  EXCEPT offset and length are in 512B SECTORS, NOT bytes
struct nxblock_device_ops {
	int (*read)(unsigned long addr, unsigned long off, unsigned long len);
	int (*write)(unsigned long addr, unsigned long off, unsigned long len);
};

/// client functions

int nxblock_client_open(const char *filepath);
int nxblock_client_close(int fd);
int nxblock_client_write(int fd, const void *data, int dlen, unsigned long dev_off);
int nxblock_client_read(int fd, void *data, int dlen, unsigned long dev_off);

/// server functions

int nxblock_server_register(const char *filename);
void nxblock_server_unregister(int port);
int nxblock_server_serve(int port, struct nxblock_device_ops *ops);

#endif /* NXBLOCK_H */

