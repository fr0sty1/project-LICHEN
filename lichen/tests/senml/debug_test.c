#include <stdio.h>
#include <string.h>
#include <math.h>
#include <lichen/senml.h>

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02x ", buf[i]);
    printf("\n");
}

int main(void) {
    struct senml_pack pack;
    uint8_t buf[64];
    int ret;

    printf("=== temp test ===\n");
    memset(&pack, 0, sizeof(pack));
    ret = senml_pack_init(&pack, NULL, 0);
    printf("init: %d\n", ret);
    ret = senml_add_float(&pack, "temp", "Cel", 25.0f);
    printf("add_float: %d\n", ret);
    ret = senml_encode_cbor(&pack, buf, sizeof(buf));
    printf("encode: %d\n", ret);
    print_hex("output", buf, (size_t)(ret > 0 ? ret : 0));
    printf("expected: 81 a4 22 00 00 64 74 65 6d 70 01 63 43 65 6c 02 fa 41 c8 00 00 (21 bytes)\n\n");

    printf("=== bool test ===\n");
    memset(&pack, 0, sizeof(pack));
    ret = senml_pack_init(&pack, NULL, 0);
    printf("init: %d\n", ret);
    ret = senml_add_bool(&pack, "charging", true);
    printf("add_bool: %d\n", ret);
    ret = senml_encode_cbor(&pack, buf, sizeof(buf));
    printf("encode: %d\n", ret);
    print_hex("output", buf, (size_t)(ret > 0 ? ret : 0));
    printf("expected: 81 a3 22 00 00 68 63 68 61 72 67 69 6e 67 04 f5 (16 bytes)\n\n");

    printf("=== uint64 high test ===\n");
    memset(&pack, 0, sizeof(pack));
    ret = senml_pack_init(&pack, NULL, 0x8000000000000000ULL);
    printf("init: %d\n", ret);
    ret = senml_add_bool(&pack, "ok", true);
    printf("add_bool: %d\n", ret);
    ret = senml_encode_cbor(&pack, buf, sizeof(buf));
    printf("encode: %d\n", ret);
    print_hex("output", buf, (size_t)(ret > 0 ? ret : 0));

    printf("\n=== null name test ===\n");
    memset(&pack, 0, sizeof(pack));
    ret = senml_pack_init(&pack, NULL, 0);
    ret = senml_add_float(&pack, "x", NULL, 1.0f);
    printf("add_float with NULL unit: %d\n", ret);
    ret = senml_encode_cbor(&pack, buf, sizeof(buf));
    printf("encode: %d\n", ret);
    if (ret > 0) print_hex("output", buf, (size_t)ret);

    /* test NULL name with volatile trick */
    {
        volatile const char *vn = NULL;
        memset(&pack, 0, sizeof(pack));
        senml_pack_init(&pack, NULL, 0);
        ret = senml_add_float(&pack, (const char *)vn, "Cel", 1.0f);
        printf("add_float with NULL name (volatile): %d (expect -EINVAL)\n", ret);
    }

    return 0;
}
