#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>

int error_count;
#define TEST
// #define CHECK_INTEGRITY

#if 0
#define USE_GENERIC_CHECK

#define BITMAP_TYPE FastBitmap
#define BITMAP_NEW FastBitmap_new
#define BITMAP_FFZ(X) FastBitmap_ffz(X)
#define BITMAP_SET FastBitmap_set
#define BITMAP_TEST FastBitmap_test
#define BITMAP_CLEAR FastBitmap_clear
#define BITMAP_DUMP(X) // bitmap_dump(X)
#define BITMAP_DEEPCOPY FastBitmap_deep_copy

#define BITMAP_FIRST_CHECK(X) bitmap_first_check_generic(X)

#define LIMIT0 (32 * 32 / 2)
#define LIMIT1 (32 * 32 / 4)
#else

#define USE_GENERIC_CHECK

#define BITMAP_TYPE BigFastBitmap
#define BITMAP_NEW BigFastBitmap_new
#define BITMAP_FFZ(X) BigFastBitmap_ffz(X)
#define BITMAP_SET BigFastBitmap_set
#define BITMAP_TEST BigFastBitmap_test
#define BITMAP_CLEAR BigFastBitmap_clear
#define BITMAP_DUMP(X) // bitmap_dump(X)
#define BITMAP_DEEPCOPY BigFastBitmap_deep_copy

#define BITMAP_FIRST_CHECK(X) bitmap_first_check_generic(X)
#define LIMIT0 (32 * 32 * 32 / 2)
#define LIMIT1 (32 * 32)
#endif

#define galloc malloc
#define gfree free
#define printk printf

#include <nexus/bitmap.h>
#include "../../../common/code/bitmap-code.c"

int main(int argc, char **argv) {
  int err_count = bitmap_runtest();
}
