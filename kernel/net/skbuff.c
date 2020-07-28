/** NexusOS: implementation of selected linux sk_buff functions for drivers. */

#include <linux/skbuff.h>

#include <nexus/defs.h>
#include <nexus/net.h>
#include <nexus/mem.h>
#include <nexus/machineprimitives.h>

/** deprecated, but called from sk_buff.h */
void __out_of_line_bug(int line)
{
	nexuspanic();
	while (1) {}; // please gcc
}

#define DUMP_SKB(SKB, offset) dump_skb(SKB, __LINE__, offset)
void dump_skb(struct sk_buff *skb, int line, int offset) {
	char sbuf[20], dbuf[20];
	PktEther *ether;
	
	ether = (PktEther *) (((const char *) skb->data) + offset);

	void getipstr(char *ip, char *buf) {
		sprintf(buf, "%d.%d.%d.%d", ip[0]&0xff, ip[1]&0xff, ip[2]&0xff, ip[3]&0xff); 
	}
	getipstr(((PktIp *) (ether + 1))->src, sbuf);
	getipstr(((PktIp *) (ether + 1))->dst, dbuf);

	printk("%d: packet arrived, ether proto %hu, ip %s => %s\n", 
	       line, ntohs(*(uint16_t *) ether->proto), sbuf, dbuf);
}

static void skb_shinfo_init(struct sk_buff *skb) {
	atomic_set(&(skb_shinfo(skb)->dataref), 1);
	skb_shinfo(skb)->nr_frags  = 0;
	skb_shinfo(skb)->frag_list = NULL;
}

/* allocate an skb */
struct sk_buff *skb_allocate(int datasize) {
	struct sk_buff *skb;
	unsigned char *data;
	int size, totalsize; 

	if(datasize > 1700) {
		printk_red("skb_allocate: unsupported data size!\n");
		nexuspanic();
	}

	skb = (struct sk_buff *)galloc(sizeof(struct sk_buff));
	memset(skb, 0, sizeof(struct sk_buff));

	size = SKB_DATA_ALIGN(datasize);
	totalsize = size + sizeof(struct skb_shared_info);
#ifdef DO_L2SEC
	totalsize += sizeof(struct l2sechdr);
#endif
	data = galloc(totalsize);

	skb->truesize = size + sizeof(struct sk_buff);

	/* Load the data pointers. */
	skb->head = data;
	skb->data = data;
	skb->tail = data;
	skb->end = data + size;

	skb->mac.raw = data;

	/* Set up other state */
	skb->len = 0;
	skb->cloned = 0;
	skb->data_len = 0;
	skb_shinfo_init(skb);

	skb->allocator = GALLOC;
	return skb;
}

struct sk_buff *skb_page_init(struct Page *page, char *data, int datasize)
{
	struct sk_buff *skb;
	unsigned char *ucdata, *ucpage, *ucpg_off, *ucpg_end;
	
	ucdata = (unsigned char *) data;
	ucpage = (unsigned char *) VADDR(page);
	ucpg_off = ucpage + sizeof(struct sk_buff);
	ucpg_end = ucpage + PAGE_SIZE - sizeof(struct skb_shared_info) - 1; 

#ifndef NDEBUG
	if(ucdata < ucpg_off || ucdata + datasize > ucpg_end)
		printk_red("skbpage: start %p <= %p? end %p <= %p?\n", 
			   ucpg_off, ucdata, ucdata + datasize, ucpg_end);
#endif
	assert(ucdata >= ucpg_off && ucdata + datasize <= ucpg_end);
	assert(ucdata - sizeof(struct sk_buff) >= ucpage);

	skb = (struct sk_buff *) (ucdata - sizeof(struct sk_buff));
	memset(skb, 0, sizeof(struct sk_buff));
	
	skb->truesize = datasize + sizeof(struct sk_buff);
	skb->head = ucdata;
	skb->data = ucdata;
	skb->tail = ucdata;
	skb->end  = ucdata + datasize;

	skb->mac.raw = ucdata;

	skb->len = 0;
	skb->cloned = 0;
	skb->data_len = 0;
	skb_shinfo_init(skb);

	skb->allocator = PAGE;
	atomic_set(&skb->users, 1);
	return skb;
}

struct sk_buff *skb_page_allocate(int datasize) {
	void *vaddr;

	if(datasize > 1700) {
		printk_red("skb_page_allocate: unsupported data size!\n");
		nexuspanic();
	}

	Map_pagesused_inc(kernelMap, 1);
	vaddr = getKernelPages(1);
	return skb_page_init(VIRT_TO_PAGE(vaddr), (char *) vaddr + SKB_DATA_ALIGN(sizeof(struct sk_buff)), datasize);
}

struct sk_buff *skb_alloc_indirect(Page *page, int offset, int datasize) {
	struct sk_buff *skb = (struct sk_buff *)galloc(sizeof(struct sk_buff));
	memset(skb, 0, sizeof(struct sk_buff));
	skb->truesize = PAGE_SIZE - offset;
	assert(datasize + sizeof(struct skb_shared_info) <= skb->truesize);

	unsigned char *data = (unsigned char *)VADDR(page) + offset;
	Page_get(page);
	skb->head = data;
	skb->data = data;
	skb->tail = data + datasize;
	skb->end = skb->head + skb->truesize - sizeof(struct skb_shared_info);

	skb->mac.raw = data;

	skb->len = datasize;
	skb->cloned = 0;
	skb->data_len = 0;
	skb_shinfo_init(skb);

	skb->allocator = INDIRECT_PAGE;
	atomic_set(&skb->users, 1);

	return skb;
}

Page *skb_to_page(struct sk_buff *skb) {
	return PHYS_TO_PAGE(VIRT_TO_PHYS(((int)skb) & ~0xfff));
}

static inline struct sk_buff *skb_nexus_copy(struct sk_buff *skb) {
	int len = skb->len;
	struct sk_buff *new_skb = skb_allocate(len);
	memcpy(skb_put(new_skb, len), skb->data, len);
	return new_skb;
}

/* free an skb allocated by the nexus */
void skb_destroy(struct sk_buff *skb) { 
  // skb->data may be readjusted to lie on byte boundaries
  // but skb->head will remain pointing to the start of the data segment
  switch(skb->allocator) {
  case GALLOC:
    gfree(skb->head);
    gfree(skb);
    break;
  case PAGE:
    Map_pagesused_dec(kernelMap, 1);
    nfree_page(skb_to_page(skb));
    break;
  case INDIRECT_PAGE: {
    Map_pagesused_dec(kernelMap, 1);
    // XXX This expression is an ugly hack to deal with the fact that
    // skb->data is the Page
    Page *p = skb_to_page((struct sk_buff *)skb->data);
    nfree_page(p);
    gfree(skb);
    break;
  }
  default:
    printk_red("unknown skb allocator!\n");
    nexuspanic();
  }
}
