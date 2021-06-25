#define ARCH KS_ARCH_X86
#define MODE KS_MODE_32

#include <stdio.h>
#include <keystone/keystone.h>

unsigned char* j_assemble(const char *code) {
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode;
    size_t size;

    err = ks_open(ARCH, MODE, &ks);
    if (err != KS_ERR_OK) {
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

    return encode;
}