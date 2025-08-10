#include "postgres.h"

int b64url_encode(const uint8 *src, int len, char *dst, int dstlen);
int b64url_decode(const char *src, int len, uint8 *dst, int dstlen);
