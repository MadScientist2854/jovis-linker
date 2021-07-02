#include "stdlib.h"
#include "stdio.h"
#include <keystone/keystone.h>

typedef struct JovisIRHeader {
    size_t data_ptr; // pointer to data in the file
    size_t data_size; //  size of data in bytes
    size_t code_ptr; // pointer to code in the file
    size_t no_of_fns;
} JovisIRHeader;

typedef struct Fn {
    size_t size;
    char *text;
    struct Fn *next;
    ks_arch asm_type; //currently hard-coded to x86 32-bit Intel syntax
    // maybe stores some flags
} Fn;

typedef struct JovisIR {
    char* data;
    size_t data_size;
    Fn* code;
} JovisIR;

Fn *read_code(FILE *file) {
    Fn *code = (Fn*)malloc(sizeof(Fn));
    fread(&code->size, sizeof(size_t), 1, file);
    char *text = (char*)malloc(code->size);
    fread(text, sizeof(char), code->size, file);
    code->text = text;
    code->next = NULL;
    code->asm_type = KS_ARCH_X86;

    free(text);
    return code;
}

JovisIR jir_from_file(char* file_name) {
    FILE *file = fopen(file_name, "rb");
    // add null-check TODO
    JovisIRHeader header;
    fread(&header, sizeof(JovisIRHeader), 1, file);

    fseek(file, header.data_ptr, SEEK_SET);
    char *data = (char*)malloc(sizeof(size_t) * header.data_size);
    fread(data, header.data_size, 1, file);

    fseek(file, header.code_ptr, SEEK_SET);
    Fn *first = read_code(file);
    Fn *last = first;
    for (size_t i = 0; i < header.no_of_fns; i++) {
        Fn *tmp = last;
        last = read_code(file);
        tmp->next = last;
    }

    fclose(file);

    JovisIR ir = {
        .data = data,
        .data_size = header.data_size,
        .code = first
    };
    return ir;
}