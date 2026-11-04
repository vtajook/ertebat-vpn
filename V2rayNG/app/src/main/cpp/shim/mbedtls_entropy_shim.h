// mbedTLS 3.x keeps the platform entropy source in a private header, but the symbol is still in
// libmbedcrypto. OpenVPN 3's random number setup calls it, so declare it for every translation unit.
#pragma once
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
int mbedtls_platform_entropy_poll(void *data, unsigned char *output, size_t len, size_t *olen);
#ifdef __cplusplus
}
#endif
