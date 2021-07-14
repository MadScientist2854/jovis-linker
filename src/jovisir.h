#include "stdlib.h"
#include "stdio.h"
#include <keystone/keystone.h>

typedef struct JovisIRHeader {
    size_t data_ptr; // pointer to data in the file
    size_t data_size; //  size of data in bytes
    size_t code_ptr; // pointer to code in the file
    size_t fn_no; // number of functions
} JovisIRHeader;

typedef struct Fn {
    size_t size;
    char *text;
    ks_arch asm_arch;
    ks_mode asm_mode; //currently hard-coded to x86 32-bit Intel syntax
    // maybe stores some flags
} Fn;

typedef struct JovisIR {
    char* data;
    size_t data_size;
    Fn* code;
    size_t fn_no;
} JovisIR;

Fn read_fn(FILE *file) {
    Fn code;
    fread(&code.size, sizeof(size_t), 1, file);
    char *text = (char*)malloc(code.size);
    fread(text, sizeof(char), code.size, file);
    code.text = text;
    code.asm_arch = KS_ARCH_X86;
    code.asm_mode = KS_MODE_32;

    return code;
}

JovisIR open_jir(char* file_name) {
    FILE *file = fopen(file_name, "rb");
    // add null-check TODO
    JovisIRHeader header;
    fread(&header, sizeof(JovisIRHeader), 1, file);

    fseek(file, header.data_ptr, SEEK_SET);
    char *data = (char*)malloc(sizeof(size_t) * header.data_size);
    fread(data, header.data_size, 1, file);

    fseek(file, header.code_ptr, SEEK_SET);
    Fn *fns = NULL;
    if (header.fn_no > 0) fns = malloc(sizeof(Fn)*header.fn_no);
    for (size_t i = 0; i < header.fn_no; i++) {
        fns[i] = read_fn(file);
    }

    fclose(file);

    JovisIR ir = {
        .data = data,
        .data_size = header.data_size,
        .code = fns,
        .fn_no = header.fn_no
    };
    return ir;
}

void create_ir(char *out_name, JovisIR ir) {
    FILE *file = fopen(out_name, "w");
    JovisIRHeader header;
    header.data_ptr = sizeof(JovisIRHeader);
    header.data_size = ir.data_size;
    header.code_ptr = sizeof(JovisIRHeader) + ir.data_size - 1;
    header.fn_no = 0;

    fwrite(&header, sizeof(JovisIRHeader), 1, file);

    fwrite(ir.data, ir.data_size, 1, file);

    fclose(file);
}