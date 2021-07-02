#define MODE KS_MODE_32

#include <stdio.h>
#include <keystone/keystone.h>

typedef struct MCode {
    unsigned char* encode;
    size_t size;
} MCode;

MCode j_assemble(const char *code, ks_arch asm_type) {
    ks_engine *ks;
    size_t count;
    unsigned char *encode;
    size_t size;

    if (ks_open(asm_type, MODE, &ks) != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit\n");
        // return -1;
    }

    if (ks_asm(ks, code, 0, &encode, &size, &count) != KS_ERR_OK) {
        printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
                count, ks_errno(ks));
    }

    // NOTE: free encode after usage to avoid leaking memory
    // ks_free(encode);

    // close Keystone instance when done
    ks_close(ks);

    MCode mcode = { .encode = encode, .size = size };
    return mcode;
}