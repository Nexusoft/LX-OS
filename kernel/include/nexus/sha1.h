#ifndef _SHA1_H_
#define _SHA1_H_

#include <linux/types.h>

struct sha1_ctx {
        u64 count;
        u32 state[5];
        u8 buffer[64];
};

/* DAN: This is just a simplified way of using crypto.h */
void sha1_init(void *ctx);
void sha1_update(void *ctx, const void *data, unsigned int len);
void sha1_final(void *ctx, u8 *out);

#endif // _SHA1_H_
