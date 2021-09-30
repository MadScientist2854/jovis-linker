#include "stdlib.h"
#include "stdio.h"
#include <keystone/keystone.h>

typedef struct JovisIRHeader {
    size_t data_ptr; // pointer to data in the file
    size_t data_size; //  size of data in bytes
    size_t code_ptr; // pointer to code in the file
    size_t fn_no; // number of functions
    size_t dep_ptr; // pointer to dependencies in file
    size_t dep_no; // number of dependencies
} JovisIRHeader;

typedef struct Fn {
    size_t size;
    char *text;
    ks_arch asm_arch;
    ks_mode asm_mode;
    // TODO: store asm type
} Fn;

typedef struct Dependency {
    bool is_absolute_path;
    size_t path_size;
    char *path;
} Dependency;

typedef struct JovisIR {
    char* data;
    size_t data_size;
    Fn* code;
    size_t fn_no;
    size_t text_size;
    Dependency *deps;
    size_t dep_no;
} JovisIR;

Fn read_fn(FILE *file) {
    Fn code;
    fread(&code.size, sizeof(size_t), 1, file);
    char *text = (char*)malloc(code.size);
    fread(text, sizeof(char), code.size, file);
    code.text = text;
    code.asm_arch = KS_ARCH_X86;
    code.asm_mode = KS_MODE_64;

    return code;
}

JovisIR open_jir(char *const file_name) {
    FILE *file = fopen(file_name, "rb");
    // add null-check TODO
    JovisIRHeader header;
    fread(&header, sizeof(JovisIRHeader), 1, file);

    // read data
    fseek(file, header.data_ptr, SEEK_SET);
    char *data = (char*)malloc(header.data_size);
    fread(data, header.data_size, 1, file);

    // read code
    fseek(file, header.code_ptr, SEEK_SET);
    Fn *fns = NULL;
    size_t text_size = 0;
    if (header.fn_no > 0) fns = malloc(sizeof(Fn)*header.fn_no);
    for (size_t i = 0; i < header.fn_no; i++) {
        fns[i] = read_fn(file);
        text_size += fns[i].size;
    }

    // read dependencies
    fseek(file, header.dep_ptr, SEEK_SET);
    Dependency *deps = NULL;
    if (header.dep_no > 0) deps = malloc(sizeof(Dependency)*header.dep_no);
    for (size_t i = 0; i < header.dep_no; i++) {
        fread(&deps[i].is_absolute_path, sizeof(bool), 1, file);
        fread(&deps[i].path_size, sizeof(size_t), 1, file);
        deps[i].path = malloc(deps[i].path_size);
        fread(deps[i].path, sizeof(deps[i].path_size), 1, file);
    }

    fclose(file);

    JovisIR ir = {
        .data = data,
        .data_size = header.data_size,
        .code = fns,
        .fn_no = header.fn_no,
        .text_size = text_size
    };
    return ir;
}

void create_ir(char *const out_name, JovisIR ir) {
    FILE *file = fopen(out_name, "w");
    JovisIRHeader header;
    header.data_ptr = sizeof(JovisIRHeader);
    header.data_size = ir.data_size;
    header.code_ptr = header.data_ptr + ir.data_size;
    header.fn_no = ir.fn_no;
    header.dep_ptr = header.code_ptr + ir.text_size + (ir.fn_no*8);
    header.dep_no = ir.dep_no;

    fwrite(&header, sizeof(JovisIRHeader), 1, file);

    fwrite(ir.data, ir.data_size, 1, file);

    for (size_t i = 0; i < ir.fn_no; i++) {
        fwrite(&ir.code[i].size, sizeof(size_t), 1, file); // write code size
        fwrite(ir.code[i].text, ir.code[i].size, 1, file); // write code text
    }

    // write dependencies to file
    for (size_t i = 0; i < ir.dep_no; i++) {
        Dependency dep = ir.deps[i];
        fwrite(&dep.is_absolute_path, sizeof(bool), 1, file);
        fwrite(&dep.path_size, sizeof(size_t), 1, file);
        fwrite(dep.path, dep.path_size, 1, file);
    }
    

    fclose(file);
}