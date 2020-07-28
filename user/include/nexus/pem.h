#include <nexus/base64.h>
#include <nexus/der.h>

static inline unsigned char *der_from_pem(char *pem) {
  unsigned char *der;
  size_t len;

  if (!base64_decode_alloc(pem, strlen(pem), &der, &len))
    return NULL;

  // sanity check der length
  if (len != der_msglen(der)) {
    free(der);
    return NULL;
  }

  return der;
}

static inline char *der_to_pem(unsigned char *der) {
  char *pem;
  if (!base64_encode_alloc(der, der_msglen(der), &pem))
    return NULL;
  return pem;
}
