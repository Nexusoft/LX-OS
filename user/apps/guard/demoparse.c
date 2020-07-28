
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <nexus/formula.h>

char *readfile(char *filename) {
	printf("reading file: %s\n", filename);
	FILE *f = fopen(filename, "r");
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	int size = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *buf = malloc(size+1);
	if (fread(buf, size, 1, f) != 1) {
		fclose(f);
		free(buf);
		return NULL;
	}
	fclose(f);
	buf[size] = '\0';
	return buf;
}

extern void init_gdb_remote(int port, int activate);

int main(int ac, char **av) {
	int i;
	extern int yydebug;
	//yydebug = 1;
	for (i = 1; i < ac; i++) {
		if (av[i][0] == '-') {
		  if (!strcmp(av[i], "-d")) {
#ifdef NEXUS
		    init_gdb_remote(3333, 0);
#endif
		  } else if (av[i][1] == 'd') {
#ifdef NEXUS
		    int port = atoi(av[i]+2);
		    init_gdb_remote(port, 0);
#endif
		  } else {
		    printf("usage: demoparse [-d|-dPORT] formula1 formula2 ... formulaN");
		    exit(1);
		  }
		  continue;
		}
		fprintf(stderr, "parsing: %s\n", av[i]);
		Form *f = form_from_pretty(av[i]);
		if (!f) {
			fprintf(stderr, "error in parsing\n");
			continue;
		}

		char *str = form_to_pretty(f, 80);
		if (!str) {
			fprintf(stderr, "error in pretty conversion\n");
			continue;
		}
		fprintf(stderr, "FIRST PARSING:\n %s\n", str);
		free(str);

		int x = form_check_proper(f);
		fprintf(stderr, "IS PROPER? : %s\n", x ? "yes" : "no");

		/* Formula *der = form_to_der(f);
		if (!der) {
			fprintf(stderr, "error in der conversion\n");
			continue;
		}
		fwrite(der->body, der_msglen(der->body), 1, stdout);
		fflush(stdout);
		free(der); */

		char *pem = form_to_pem(f);
		if (!pem) {
			fprintf(stderr, "error in pem conversion\n");
			continue;
		}
		fprintf(stderr, "PEM ENCODING:\n");
		fflush(stderr);
		fwrite(pem, strlen(pem), 1, stdout);
		fwrite("\n", 1, 1, stdout);
		fflush(stdout);

		f = form_from_pem(pem);
		if (!f) {
			fprintf(stderr, "error parsing pem\n");
			continue;
		}

		free(pem);

		str = form_to_pretty(f, 80);
		if (!str) {
			fprintf(stderr, "error in pretty conversion\n");
			continue;
		}
		fprintf(stderr, "REPARSED:\n %s\n", str);
		free(str);

		x = form_check_proper(f);
		fprintf(stderr, "IS PROPER? : %s\n", x ? "yes" : "no");
		

	}
	return 0;
}
