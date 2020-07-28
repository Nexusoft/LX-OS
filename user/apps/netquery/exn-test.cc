#include <stdio.h>

int main(void) {
        int argc;
        try {
                int i=1;
                throw 1;
        } catch(int x) {
                printf("exn %d\n", x);
        }
}

