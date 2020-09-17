#include <nexus/defs.h>
#include <nexus/initrd.h>

#define INITRD_BLOCKLEN (512)

long initrd_start, initrd_size;

static InitRD_File *
parse_tar_header(struct InitRD_File *te, struct InitRD_File *te_last) 
{
	char *next;
	int size = 0;
	int i, blocks;
	
	for (i = 0; i < sizeof(te->file_size) - 1; i++) {
		size = size << 3;
		size +=  te->file_size[i] - '0';
	}

	te->len = size;
	te->name[sizeof(te->name) - 1] = 0;
	te->data = ((void *) te) + 512;

	blocks = (size + (INITRD_BLOCKLEN - 1)) / INITRD_BLOCKLEN;
	next = te->data + (blocks * INITRD_BLOCKLEN);

	if (next > (char *) te_last || next[0] == 0)
		te->next = NULL;
	else
		te->next = (void *) next;

	return te->next;
}

void init_initrd() 
{
	struct InitRD_File *te, *te_first, *te_last;

	if (!initrd_start) {
	   printk_red("[initrd] not found\n");
	   return;
	}

	printk("[initrd] %ld MB\n", initrd_size >> 20);

	te_first = (void *) initrd_start;
	te_last  = (void *) initrd_start + initrd_size - 512;
	
	te = te_first;
	while (te && te < te_last)
		te = parse_tar_header(te, te_last);
}

void initrd_show(void) {
	struct InitRD_File *te, *te_first, *te_last;

	if (!initrd_start) {
	   printk("[initrd] no initrd\n");
	   return;
	}

	te_first = (struct InitRD_File *) initrd_start;
	te_last = (struct InitRD_File *)(initrd_start+initrd_size-512);
	if (!te_first->name[0]) {
	        printk("[initrd] empty initrd\n");
		return;
	}

	for (te = te_first ; te && te < te_last; te = te->next) {
		printk("%s [%dB]\n", te->name, te->len);
	}

}

struct InitRD_File *initrd_first() {
	return (struct InitRD_File *)initrd_start;
}

struct InitRD_File *initrd_find(const char *name) {
	struct InitRD_File *te;
	for (te = initrd_first(); te != 0; te = te->next) {
		if (!strcmp(name, te->name))
			return te;
	}
	return 0;
}

