#include <bfd.h>
#include "jovisir.h"
#include "assemble.h"

bfd *create_bfd(JovisIR ir, char* out_name) {
    // TODO: generate target based on target given in ir
    bfd *abfd = bfd_openw(out_name, "elf64-x86-64");
    if (abfd == NULL) printf("err creating bfd: %s\n", bfd_errmsg(bfd_get_error()));
    if (!bfd_set_format(abfd, bfd_object))
        printf("err setting format to object: %s\n", bfd_errmsg(bfd_get_error()));
    bfd_set_arch_info(abfd, bfd_scan_arch("i386:x86-64:intel"));
    
    asection *data = bfd_make_section_old_way(abfd, ".data");
    if (data == NULL) printf("err creating data section: %s\n", bfd_errmsg(bfd_get_error()));
    asection *code;
    if (ir.fn_no > 0) {
        code = bfd_make_section_old_way(abfd, ".text");
        bfd_set_section_flags(code, SEC_HAS_CONTENTS);
        if (code == NULL) printf("err creating code section: %s ", bfd_errmsg(bfd_get_error()));
    }

    if (!bfd_set_section_size(data, ir.data_size))
        printf("err setting .data size: %s\n", bfd_errmsg(bfd_get_error()));
    if (!bfd_set_section_flags(data, SEC_HAS_CONTENTS))
        printf("err setting .data contents flag: %s\n", bfd_errmsg(bfd_get_error()));
    asymbol *data_sym = bfd_make_empty_symbol(abfd);
    if (data_sym == NULL) printf("data_sym null err");
    data_sym->name = "ldata";
    data_sym->section = data;
    data_sym->flags = BSF_LOCAL;
    data_sym->value = 0;

    size_t sym_no = ir.fn_no;
    sym_no += 1;

    asymbol *sym_tab[sym_no+1];
    sym_tab[sym_no-1] = data_sym;
    sym_tab[sym_no] = (asymbol *)0;

    MCode mcodes[ir.fn_no];
    size_t mcode_size = 0;

    // loop through fns
    for (int i = 0; i < ir.fn_no; i++) {
        Fn fn = ir.code[i];
        // for each fn, assemble it's code
        MCode mcode = j_assemble(fn.text, fn.asm_arch, fn.asm_mode);
        // add symbol that points to start of fn
        asymbol *fn_sym = bfd_make_empty_symbol(abfd);
        if (fn_sym == NULL) printf("fn_sym null err");
        char name[5];
        sprintf(name, "f%d", i);
        fn_sym->name = name;
        fn_sym->section = code;
        fn_sym->flags = BSF_LOCAL;
        fn_sym->value = code->size;

        sym_tab[i] = fn_sym;

        // append mcode to the array
        mcodes[i] = mcode;
        mcode_size += mcode.size;

        // free mallocated data
        free(fn.text);
    }
    // set symbol table on bfd
    if (sym_no > 0) {
        if (!bfd_set_symtab(abfd, sym_tab, sym_no))
            printf("err setting symbol table: %s\n", bfd_errmsg(bfd_get_error()));
    }
    if (ir.fn_no > 0) free(ir.code);
    if (!bfd_set_section_size(code, mcode_size))
        printf("err setting .text size: %s\n", bfd_errmsg(bfd_get_error()));

    // start writing to bfd
    if (!bfd_set_section_contents(abfd, data, ir.data, 0, ir.data_size))
        printf("err setting .data contents: %s\n", bfd_errmsg(bfd_get_error()));
    // free mallocated data in ir
    free(ir.data);

    size_t cur_code_ptr = 0;
    for (size_t i = 0; i < ir.fn_no; i++) {
        // put machine code into the .code section
        MCode *mcode = &mcodes[i];
        if (!bfd_set_section_contents(abfd, code, mcode->encode, cur_code_ptr, mcode->size))
            printf("err setting .text contents: %s\n", bfd_errmsg(bfd_get_error()));
        cur_code_ptr += mcode->size;
            
        ks_free(mcode->encode);
    }

    // add bfd_error checks TODO (done for the most part, need to actually halt on error though)

    return abfd;
}

void link(char *entry_file) {
    // create ir from file
    JovisIR ir = open_jir(entry_file);
    // create bfd from ir
    // char file_name[10];
    // sprintf(file_name, "test%ld.o", i+1);
    bfd *abfd = create_bfd(ir, "jexec.o");
    // generate object file
    bool err = !bfd_close(abfd);
    if (err) printf("err at close: %s\n", bfd_errmsg(bfd_get_error()));
    // add bfd_error checks TODO

    // link all object files together TODO
}