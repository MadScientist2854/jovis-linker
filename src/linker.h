#include <bfd.h>
#include "jovisir.h"
#include "assemble.h"

bfd *create_bfd(JovisIR ir, char* out_name) {
    // TODO: generate target based on target given in ir
    bfd *abfd = bfd_openw(out_name, "elf64-x86-64");
    bfd_set_format(abfd, bfd_object);
    bfd_set_arch_info(abfd, bfd_scan_arch("i386:x86-64:intel"));
    
    asection *data = bfd_make_section_old_way(abfd, ".data");
    if (data == NULL) printf("null err");
    bfd_set_section_size(data, ir.data_size);
    bfd_set_section_flags(data, SEC_HAS_CONTENTS);
    bfd_set_section_contents(abfd, data, ir.data, 0, ir.data_size);
    // free mallocated data in ir
    free(ir.data);
    
    asection *code;
    if (ir.fn_no > 0) {
        code = bfd_make_section_old_way(abfd, ".code");
        if (code == NULL) printf("null err");
    }

    // create object-file symbols for data section starting point TODO

    asymbol *sym_tab[ir.fn_no];

    // loop through fns
    for (int i = 0; i < ir.fn_no; i++) {
        Fn fn = ir.code[i];
        // for each fn, assemble it's code
        MCode mcode = j_assemble(fn.text, fn.asm_arch, fn.asm_mode);
        // add symbol that points to start of fn
        asymbol *fn_sym = bfd_make_empty_symbol(abfd);
        sprintf(fn_sym->name, "f%d", i);
        fn_sym->section = code;
        fn_sym->flags = BSF_LOCAL;
        fn_sym->value = code->size;

        sym_tab[i] = fn_sym;
        // put the machine code into the .code section
        bfd_set_section_contents(abfd, code, mcode.encode, code->size, mcode.size);

        // free mallocated data
        free(fn.text);
        ks_free(mcode.encode);
    }
    if (ir.fn_no > 0) free(ir.code);

    // set symbol table on bfd
    if (ir.fn_no > 0) bfd_set_symtab(abfd, sym_tab, ir.fn_no);
    // add bfd_error checks TODO

    return abfd;
}

void link(char **ir_files, size_t no_of_files) {
    // for each IR file
    for (size_t i = 0; i < no_of_files; i++) {
        // create ir from file
        JovisIR ir = open_jir(ir_files[i]);
        // create bfd from ir
        char file_name[10];
        sprintf(file_name, "test%d.o", i+1);
        bfd *abfd = create_bfd(ir, file_name);
        // generate object file
        bool err = bfd_close(abfd);
        if (err) printf("%s", bfd_errmsg(bfd_get_error()));
        // add bfd_error checks TODO
    }

    // link all object files together TODO
}