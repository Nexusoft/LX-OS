#include <nexus/defs.h>
#include <nexus/tftp.h>
#include <nexus/net.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/initrd.h>
#include <nexus/thread.h>
#include <nexus/kernelfs.h>
#include <nexus/dlist.h>

#define TFTPLOCALPORT_BASE (0x07d1)
#define TFTPLOCALPORT_LAST (TFTPLOCALPORT_BASE + 500)
#define TFTPREMOTEPORT 69
#define TFTP_OPCODE_OFFSET 0
#define TFTP_OFFSET_OFFSET 2
#define TFTP_DATA_OFFSET   4
#define TFTP_DATABLOCK_SIZE  1432
#define TFTP_PKTBUF_SIZE 1514		// hold a full network packet
#define TFTP_PORT_MAXTRY 10
#define TFTP_MAXFILESZ (1 << 25)

static int tftp_nextport = TFTPLOCALPORT_BASE;
static Sema *tftpport_sema;

static Sema tftp_queue_sema = SEMA_INIT;
struct dlist_head_list tftp_queue;

static int tftp_send_file(char *filepath, int serverport, char *file, 
		          int filesize);

/**** A queue of files to transport in the background ********/

struct QueueFile {
  struct dlist_head link;

  char *filepath;
  char *file;
  int filesize;
};

#if 0
static struct QueueFile *
QueueFile_new(char *filepath, char *file, int filesize) 
{
	struct QueueFile *qf;

	assert(filesize > 0);

	// allocate and initialize base structures
	qf = galloc(sizeof(struct QueueFile));
	dlist_init_link(&qf->link);
	qf->filepath = strdup(filepath);

	// introduce data
	qf->file = galloc(filesize);
	memcpy(qf->file, file, filesize);
	qf->filesize = filesize;

	return qf;
}

static void 
QueueFile_send(struct QueueFile *qf) {
  tftp_send_file(qf->filepath, TFTP_PORT, qf->file, qf->filesize);
}

static void 
QueueFile_free(struct QueueFile *qf) 
{
  gfree(qf->filepath);
  gfree(qf->file);
  gfree(qf);
}

/**** Main TFTP code ********/

void tftp_init(void) {
	tftpport_sema = sema_new();
	sema_initialize(tftpport_sema, 1);
	dlist_init_head(&tftp_queue);
}

/** Select an available client port */
static int tftp_get_nextport(void) {
	int ret;

	P(tftpport_sema);

	ret = tftp_nextport++;
	if (tftp_nextport > TFTPLOCALPORT_LAST)
		tftp_nextport = TFTPLOCALPORT_BASE;

	V(tftpport_sema);
	return ret;
}

/** Create a TFTP request. 
    Protocol format is: |1|foofile|0|octet|0|blksize|0|1432|0| 
 
    @param reqlen must point to an integer. 
           On return it will hold the length of the request
    @return the request */
static char *
__tftp_fetch_createrequest(char *filepath, int *reqlen)
{
	char *req;
	int fplen, len;

	assert(reqlen);

	fplen = strlen(filepath);
	len = 2 + fplen + 1 + 6 + 8 + 5;

	req = galloc(len);
	putshort(req, TFTP_OPCODE_READREQUEST);
	memcpy(req + 2, filepath, fplen);
	memcpy(req + 2 + fplen, "\0octet\0blksize\0" "1432\0", 1 + 6 + 8 + 5);
	
	*reqlen = len;
	return req;
}

/** Process a piece of arriving data. 
    Handle acknowledgements and copy data into the file buffer
    @return number of bytes written on success, 
            -1 on failure (in which case caller must quit). */
static int
__tftp_fetch_readblock(const char *buf, char *filebuf, int fblen, 
		       char *ackbuf, uint16_t *serverport)
{
	PktUdp *udp;
	PktIp *ip;
	const char *payload;
	int off, payloadlen, len;
	uint16_t cmd, blockno;

	// setup protocol header pointers
	off = sizeof(PktEther);
	ip = (PktIp *) (buf + off);
	off += sizeof(PktIp);
	udp = (PktUdp *) (buf + off);
	off += sizeof(PktUdp);
	payload = buf + off;

	// parse interesting contents
	*serverport = ntohs(*(uint16_t *) udp->srcport);
	payloadlen = ntohs(*(uint16_t *) ip->len) - sizeof(PktIp) - sizeof(PktUdp);

	cmd = ntohs(*(uint16_t *) payload);

	// parse protocol header
	switch (cmd) {
		case TFTP_OPCODE_DATA:
			blockno = ntohs(*(uint16_t *) (payload + TFTP_OFFSET_OFFSET));
			assert(blockno >= 0);
			putshort(ackbuf + 2, blockno);
		break;

		case TFTP_OPCODE_ERROR:
			printk("[tftp] Error: code %d:%s]\n", 
			       ntohs(*(uint16_t *) (payload + 2)), payload + 4);
			return -1;
		break;

		case TFTP_OPCODE_OACK:
			// Things like OACK will be sent. We assume that these
			// are all correct, ack these and move on
			putshort(ackbuf, TFTP_OPCODE_ACK);
			putshort(ackbuf + 2, 0);
			return 0;
		break;

		default:
			printk("[tftp] Error: unexpected packet code %d\n",
			       ntohs(*(uint16_t *) payload));
			return -1;
	}

	// copy data
	payloadlen -= TFTP_DATA_OFFSET;
	if (payloadlen > fblen) {
		printk("[tftp] Error: file exceeds size limit\n");
		return -1;
	}
	memcpy(filebuf, payload + TFTP_DATA_OFFSET, payloadlen);

	return payloadlen;
}

/** Acquire a local port. Returns 0 on failure, a valid port otherwise. */
static uint16_t
__tftp_acquire_port(Port **outport)
{
	uint16_t localport;
	int try;

	for (try = 0; try < TFTP_PORT_MAXTRY; try++) {
		localport = tftp_get_nextport();
		*outport = port_open(localport);
		if (*outport)
			return localport;
	}

	return 0;
}

/** Fetch a file over TFTP.

    @param the block pointed to by filesize will be set to the size of the 
           file on return. The pointer may NOT be zero.

    @return a pointer to a buffer holding the file on success, NULL on failure.
           In case of failure, contents of filesize are undefined.
*/
static char *
tftp_fetch_file(char *filepath, char *serverip, int serverport, int *filesize) {
	Port *ipcport;
	char buf[TFTP_PKTBUF_SIZE], ackbuf[4];
	char *localip, *req, *filebuf, *tmpbuf;
	int localport, nleft, len, j;
	uint16_t __serverport = serverport;

	// initialize
	assert(filesize);
	filebuf = NULL;
	*filesize = -1;

	// acquire address and port 
	localip = getmyip();
	if (!localip) {
		printk("Error: network down, cannot send TFTP request\n");
		return NULL;
	}
	localport = __tftp_acquire_port(&ipcport);
	if (!localport) {
		printk("Error: no available port, cannot send TFTP request\n");
		return NULL;
	}
  	
	// send request
	req = __tftp_fetch_createrequest(filepath, &len);
	nexus_send_udp(localip, localport, serverip, __serverport, req, len);
	gfree(req);
	
 	// allocate temporary reception buffer. 
	// we do not know filelength in advance, so overprovision
	nleft = TFTP_MAXFILESZ;
	tmpbuf = galloc(nleft);
        putshort(ackbuf, TFTP_OPCODE_ACK);

	// receive data
	printk("[tftp] fetching tftp://%hu.%hu.%hu.%hu:%hu/%s\n.\n", 
	       serverip[0] & 0xff, serverip[1], serverip[2], serverip[3], 
	       serverport, filepath);
	j = 0;
	do {
		// receive and process block
		len = port_receive(ipcport, buf, TFTP_PKTBUF_SIZE);
		len = __tftp_fetch_readblock(buf, tmpbuf + TFTP_MAXFILESZ - nleft, 
				 	     nleft, ackbuf, &__serverport);
		if (len == -1)
			goto cleanup;
	
		// send acknowledgement	
		nexus_send_udp(localip, localport, serverip, __serverport, ackbuf, 4);
		nleft -= len;
		if(++j % 10 == 0)
			printk(".");
	} while (!len || len == TFTP_DATABLOCK_SIZE);
	printk("\n");

	// copy data to buffer of exact file size
	len = TFTP_MAXFILESZ - nleft;
	filebuf = galloc(len);
	memcpy(filebuf, tmpbuf, len);
	*filesize = len;

cleanup:
	// cleanup
	gfree(tmpbuf);
	port_close(ipcport);
	return filebuf;
}
#endif

/** Fetch a file. First try the cache, then TFTP */
char *
fetch_file(char *filepath, int *filesize) {
	char *server, *data;

	data = cache_find(filepath, filesize);
	return data;
}

int 
fetchpoke_file(char *filename, int *filesize, Map *m, unsigned int vaddr,
	       unsigned int maxsize) 
{
        char *data;
       
	data = fetch_file(filename, filesize);
        if (!data) 
		return -1;

        return poke_user(m, vaddr, data, min((int) maxsize, *filesize));
}

/** Deprecated TFP send from kernel */
int 
send_file(char *filepath, char *file, int filesize)
{
	printkx(PK_TFTP, PK_INFO, "[tftp] tx from kernel attempted [%s] %dB\n",
		filepath, filesize);
	return 0;
}

#if 0

int 
send_file(char *filepath, char *file, int filesize) 
{
	char *server;
	
	server = getserverip();
	if (!server)
		return 1;

	cache_remove(filepath);
	return tftp_send_file(filepath, TFTP_PORT, file, filesize);
}

int 
peeksend_file(char *filename, Map *m, unsigned int vaddr, unsigned int filesize) 
{
        char *buf;
	int ret;

	assert(filesize > 0);
	buf = galloc(filesize + 1);
        peek_user(m, vaddr, buf, filesize);
        
	ret = send_file(filename, buf, filesize);
        gfree(buf);
        return ret;
}


static int 
tftp_send_file(char *filepath, int serverport, char *file, int filesize) 
{
	Port *port;
	char buf[TFTP_PKTBUF_SIZE], *udppayload;
	int  nread; // raw packet size;
	int npayload; // UDP payload size
	char tftpreq[300], tftpdat[520];
	char *localip, *serverip;
	int  blockno=1, offset=0;
	int  j=0;
	int size = 0;
	int err = 0;
	int localport;

	localip = getmyip();
	serverip = getserverip();
	if (!localip || !serverip) {
		printkx(PK_TFTP, PK_WARN, "[tftp] network is down. cannot send\n");
		return 1;
	}


	int porttries = 0;
	do {
		porttries++;
		localport = tftp_get_nextport();
		port = port_open(localport);
	}while(port == NULL && porttries < 10);

	if(port == NULL){
	  printk_red("couldn't find a port for the tftp\n");
	  nexuspanic();
	}

	//|1|foofile|0|octet|0|blksize|0|1432|0|  -->  RRQ
	int fplen = strlen(filepath);
	int len = 2 + fplen + 6+1; // 6+8+5+1;
	tftpreq[0] = tftpreq[1] = '\0';
	memcpy(tftpreq+2, filepath, fplen);
	memcpy(tftpreq+2+fplen, "\0octet", 6+1); // "\0octet\0blksize\0" "1432\0", 6+8+5+1);

	putshort(tftpreq, TFTP_OPCODE_WRITEREQUEST);
	putshort(tftpdat, TFTP_OPCODE_DATA);

	printk("[t=%d, istate = %d: sending %s...", nexusthread_id(nexusthread_self()), check_intr(), filepath);
	nexus_send_udp(localip, localport, serverip, serverport, tftpreq, len);
	while (offset <= filesize) {
		nread = port_receive(port, buf, TFTP_PKTBUF_SIZE);

		if(++j % 5 == 0)
			printk(".");

		udppayload = buf + sizeof(PktEther) + sizeof(PktIp) + sizeof(PktUdp);
		npayload = nread - sizeof(PktEther) - sizeof(PktIp) - sizeof(PktUdp) - 2; // 2 for the ether checksum at the end
		serverport = ntohs(*(uint16_t *)((PktUdp*)(buf + sizeof(PktEther) + sizeof(PktIp)))->srcport);

		if (ntohs(*(uint16_t *) udppayload) == TFTP_OPCODE_ERROR) {
			printk("error %d : %s]\n", ntohs(*(uint16_t *) (udppayload+2)), udppayload+4);
			err = 1;
			goto done;
		}
		putshort(tftpdat+2, blockno++);
		size = min((int)filesize-offset, 512);
		memcpy(tftpdat + TFTP_DATA_OFFSET, file + offset, size);
		offset += 512;
		nexus_send_udp(localip, localport, serverip, serverport,
				tftpdat, size + TFTP_DATA_OFFSET);
	}
	printk("]\n");
done:
	port_close(port);
	return err;
}

int 
queue_and_send_file(char *filepath, char *file, int filesize) 
{
	struct QueueFile *qf;
	int intlevel;
 
	intlevel = disable_intr();
	qf = QueueFile_new(filepath, file, filesize);
	dlist_insert_tail(&tftp_queue, &qf->link);
	restore_intr(intlevel);

	V(&tftp_queue_sema);

	return 0;
}

int tftp_queued_send_thread(void *arg) {
	struct QueueFile *qf;
	struct dlist_head *head;
	int intlevel; 

	while(1) {
		P(&tftp_queue_sema);
		
		intlevel = disable_intr();
		head = tftp_queue.next;
		dlist_unlink(head);
		restore_intr(intlevel);

		qf = CONTAINER_OF(struct QueueFile, link, head);
		QueueFile_send(qf);
		QueueFile_free(qf);
	}
}

#endif

/**** Filecache holding tftp, nfs and initrd items ********/

/* This code is not thread-safe. */

typedef struct FileCacheItem {
	char *filename;
	int size;
	char *file;
} FileCacheItem;

#define CACHE_NLEN 100	///< maximum filename size

#define CACHESIZE 1763
static FileCacheItem *filecache[CACHESIZE];

static FileCacheItem *
__cache_find(char *filename, unsigned int *index_out)
{
	FileCacheItem *item;
	unsigned char hash[20];
	unsigned int index;

	// XXX support double hashing: use the standard hashtable
	sha1((unsigned char *) filename, strlen(filename), hash);
	index = (*(unsigned int *) hash) % CACHESIZE;	

	if (index_out)
		*index_out = index;

	return filecache[index];
}

static void
__cache_remove(unsigned int index)
{
	struct FileCacheItem *item;

	item = filecache[index];
	filecache[index] = NULL;
	assert(item);
	
	gfree(item->filename);
	gfree(item->file);
	gfree(item);
}

/** Return the item at index.

    @param size holds entry length IFF the return value is not NULL
           and size is a valid pointer. 
    @return a pointer to the entry or (void *) -1 on failure */
const char *
cache_entry(int index, const char **name, int *size)
{
	FileCacheItem *item;

	if (index < 0 || index >= CACHESIZE)
		return (void *) -1;

	item = filecache[index];
	if (!item)
		return NULL;

	if (size)
		*size = item->size;
	if (name)
		*name = item->filename;

	return item->file;
}

/** Lookup an item in the cache by name.
 
    @param size holds the size of the item on successful return; 
           it is undefined if the function returns NULL */
char *
cache_find(char* filename, int *size) 
{
	FileCacheItem *item;
	char *file;
	
	assert(filename);
	item = __cache_find(filename, NULL);
	if (!item) 
		return NULL;

	if (strncmp(filename, item->filename, CACHE_NLEN))
		return NULL;

	if (size)
		*size = item->size;
	file = galloc(item->size);
	assert(file);
	memcpy(file, item->file, item->size);
	
	printkx(PK_CACHE, PK_DEBUG, "[cache] found [%s]\n", filename);
	return file;
}

void 
cache_add(char *filename, char *file, int size) 
{
	FileCacheItem *item;
	unsigned int fnlen, index;

	fnlen = strlen(filename);
	if (fnlen > CACHE_NLEN) {
		printkx(PK_CACHE, PK_WARN, 
			"[cache] Error: filename [%s] exceeds max\n", filename);
		return;
	}

	item = __cache_find(filename, &index);

	if (item) {
		printkx(PK_CACHE, PK_WARN, "[cache] Error: [%s] collides with [%s]\n", 
		       filename, item->filename);
		return;
	}

	item = galloc(sizeof(FileCacheItem));
	item->filename = galloc(fnlen + 1);
	strncpy(item->filename, filename, fnlen);
	item->filename[fnlen] = 0;

	item->size = size;
	item->file = galloc(size);
	memcpy(item->file, file, size);
	
	filecache[index] = item;
	printkx(PK_CACHE, PK_DEBUG, "[cache] inserted [%s] (at %d)\n", filename, index);

	// XXX.1 also support remove and clear
	// XXX.2 replace basic cache with the fs
	KernelFS_mk(item->filename, item->file, item->size);
}

void 
cache_remove(char *filename) 
{
	FileCacheItem *item;
	unsigned int index;

	item = __cache_find(filename, &index);
	if (item) {
		__cache_remove(index);
		printkx(PK_CACHE, PK_DEBUG, "[cache] removed [%s]\n", filename);
	}
}

/** Remove all items from the cache */
int cache_clear(void) {
	int i, cleared = 0;

	for (i = 0; i < CACHESIZE; i++) {
		if (filecache[i]) {
			__cache_remove(i);
			cleared++;
		}
	}

	return cleared;
}

void cache_list(void) {
	int i;

	for(i = 0; i < CACHESIZE; i++)
		if (filecache[i]) 
			printk("[cache] entry [%s] (%dB)\n",
				filecache[i]->filename, filecache[i]->size);
}

/** Populate the cache with the files in the initrd file. */
void cache_init(void) 
{
	struct InitRD_File *te;

	for (te = initrd_first(); te ; te = te->next) {
		cache_add(te->name, te->data, te->len);
	}
}

