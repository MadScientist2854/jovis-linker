#include "stdlib.h"
#include "stdio.h"

typedef struct JovisIRHeader {
    size_t data_ptr; // pointer to data in the file
    size_t data_size; //  size of data in bytes
    size_t code_ptr; // pointer to code in the file
    size_t no_of_fns;
} JovisIRHeader;

typedef struct Code {
    size_t size;
    char *text;
    struct Code *next;
    // ASMType asm_type; currently hard-coded to x86 32-bit Intel syntax
    // maybe stores some flags
} Code;

typedef struct JovisIR {
    char* data;
    size_t data_size;
    Code* code;
} JovisIR;

Code *read_code(FILE *file) {
    size_t *size;
    fread(size, sizeof(size_t), 1, file);
    char *text = (char*)malloc(*size);
    fread(text, sizeof(char), *size, file);
    Code *code = (Code*)malloc(sizeof(Code));
    code->size = *size;
    code->text = text;
    code->next = NULL;
    free(text);
    return code;
}

JovisIR jir_from_file(char* file_name) {
    FILE *file = fopen(file_name, "rb");
    // add null-check
    JovisIRHeader header;
    fread(&header, sizeof(JovisIRHeader), 1, file);

    fseek(file, header.data_ptr, SEEK_SET);
    char *data = (char*)malloc(sizeof(size_t) * header.data_size);
    fread(data, header.data_size, 1, file);

    fseek(file, header.code_ptr, SEEK_SET);
    Code *first = read_code(file);
    Code *last = first;
    for (size_t i = 0; i < header.no_of_fns; i++) {
        Code *tmp = last;
        last = read_code(file);
        tmp->next = last;
    }

    fclose(file);

    JovisIR ir;
    ir.data = data;
    ir.data_size = header.data_size;
    ir.code = first;
    return ir;
}