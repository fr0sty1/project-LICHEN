#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "lichen/subsys/lichen/l2/lichen_util.h"

int main(void) {
    uint32_t h1 = lichen_hash_32(NULL, 0);
    uint32_t h2 = lichen_hash_32((const uint8_t*)"test", 4);
    uint8_t z[32] = {0};
    uint32_t h3 = lichen_hash_32(z, 32);
    printf("hash empty: 0x%08x (expected 0x811c9dc5)\n", h1);
    printf("hash test: 0x%08x (expected 0xafd071e5)\n", h2);
    printf("hash zeros: 0x%08x (expected 0x0b2ae445)\n", h3);
    int ok = (h1 == 0x811c9dc5u && h2 == 0xafd071e5u && h3 == 0x0b2ae445u);
    printf("Test %s\n", ok ? "PASSED" : "FAILED");
    return ok ? 0 : 1;
}
