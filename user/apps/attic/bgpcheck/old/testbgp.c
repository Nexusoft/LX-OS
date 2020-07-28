#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "bgp.h"

extern int bgp_dump_data(int len, PIPE_TYPE pipe);

int main(int argc, char **argv){
	bgp_packet packet;
	bgp_datasource f;
	int totbytes = 0, count = 0;
	f.contents.pipe = open("binary", O_RDONLY, 755);
	if (f.contents.pipe == -1) { perror("binary"); exit(1); }
	f.type = BGP_PIPE;
#ifndef PARSE_ONE
	while(1){
		printf("==== %d ====\n", ++count);
#endif
		bgp_dump_data(DUMP_LENGTH, &f);
		int len = bgp_read_packet(&f, &packet);
		if (len == 0) break;  /* eof */
		totbytes += DUMP_LENGTH + len;
		bgp_print_packet(&packet);
		bgp_cleanup_packet(&packet);
#ifndef PARSE_ONE
	}
#endif
	return 0;
}
