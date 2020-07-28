#include <nexus/defs.h>
#include <nexus/initrd.h>

long initrd_start, initrd_size;

static void 
parse_tar_header(struct InitRD_File *te) 
{
	int size = 0;
	int i;
	
	for (i = 0; i < sizeof(te->file_size) - 1; i++)
		size = size * 8 + (te->file_size[i]-'0');

	// printk("INITRD: filesize: %d name: \"%s\"\n", te->len, te->name);

	te->len = size;
	te->name[sizeof(te->name)-1] = 0;
	te->data = ((void *)te) + 512;
	int n = (size + 512 - 1)/512;
	te->next = (struct InitRD_File *)(te->data + n * 512);
	if (!te->next->name[0])
		te->next = 0;
}

void init_initrd() 
{
	struct InitRD_File *te, *te_first, *te_last;

	if (!initrd_start) {
	   printk_red("Can't find initrd!  Maybe the bootloader didn't grab it?");
	   return;
	}

	//printk("Initial ram disk at 0x%lx: %ld bytes\n", initrd_start, initrd_size);

	te_first = (struct InitRD_File *) initrd_start;
	te_last = (struct InitRD_File *)(initrd_start+initrd_size-512);
	if (!te_first->name[0]) {
		printk("empty ramdisk: no files in tarball\n");
		return;
	}
	int n = 0;
	for (te = te_first ; te && te < te_last; te = te->next) {
		parse_tar_header(te);
		n++;
	}

	//printk("\tholds %d files\n", n);
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

struct InitRD_File *initrd_find(char *name) {
	struct InitRD_File *te;
	for (te = initrd_first(); te != 0; te = te->next) {
		if (!strcmp(name, te->name))
			return te;
	}
	return 0;
}

