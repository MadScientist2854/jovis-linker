#include <bfd.h>
#include "jovisir.h"
#include "assemble.h"

int generate_obj(char *const ir_path, char *const out_file);

bfd *create_bfd(JovisIR ir, char*const out_name) {
    // Create BFD
    bfd *abfd = bfd_openw(out_name, "elf64-x86-64"); // TODO: generate target based on target given in ir
    if (abfd == NULL) printf("err creating bfd: %s\n", bfd_errmsg(bfd_get_error()));
    if (!bfd_set_format(abfd, bfd_object))
        printf("err setting format to object: %s\n", bfd_errmsg(bfd_get_error()));
    bfd_set_arch_info(abfd, bfd_scan_arch("i386:x86-64:intel"));
    
    // Create sections and then set attributes
    asection *data = bfd_make_section_old_way(abfd, ".data");
    if (data == NULL) printf("err creating data section: %s\n", bfd_errmsg(bfd_get_error()));
    asection *text;
    if (ir.fn_no > 0) {
        text = bfd_make_section_old_way(abfd, ".text");
        bfd_set_section_flags(text, SEC_HAS_CONTENTS);
        if (text == NULL) printf("err creating text section: %s ", bfd_errmsg(bfd_get_error()));
    }
    if (!bfd_set_section_size(data, ir.data_size))
        printf("err setting .data size: %s\n", bfd_errmsg(bfd_get_error()));
    if (!bfd_set_section_flags(data, SEC_HAS_CONTENTS))
        printf("err setting .data contents flag: %s\n", bfd_errmsg(bfd_get_error()));

    // create data section symbol
    asymbol *data_sym = bfd_make_empty_symbol(abfd);
    if (data_sym == NULL) printf("data_sym null err");
    data_sym->name = "data";
    data_sym->section = data;
    data_sym->flags = BSF_LOCAL;
    data_sym->value = 0;

    // create symbol table
    size_t sym_no = ir.fn_no + ir.dep_no + 1;

    asymbol *sym_tab[sym_no+1];
    sym_tab[sym_no-1] = data_sym;
    sym_tab[sym_no] = (asymbol *)0;

    // add dependencies
    for (size_t i = 0; i < ir.dep_no; i++) {
        Dependency dep = ir.deps[i];
        // add external symbol
        char *path = malloc(dep.path_size+1);
        sprintf(path, "o%s", dep.path); // TODO: transform path to be relative to root directory of compilation, or system root
        // TODO: instead of making symbol, add to symbol resolver
        asymbol *dep_sym = bfd_make_empty_symbol(abfd);
        if (dep_sym == NULL) printf("data_sym null err");
        dep_sym->name = path;
        dep_sym->section = data;
        dep_sym->flags = BSF_WEAK;
        dep_sym->value = 0;
        sym_tab[ir.fn_no + i] = dep_sym;
        // TODO: generate dependency's object file
        char out_file[5];
        sprintf(out_file, "d%ld", i);
        generate_obj(path, out_file);
    }

    MCode mcodes[ir.fn_no];
    size_t mcode_size = 0;
    // loop through fns
    for (int i = 0; i < ir.fn_no; i++) {
        Fn fn = ir.code[i];

        // add symbol that points to start of fn
        asymbol *fn_sym = bfd_make_empty_symbol(abfd);
        if (fn_sym == NULL) printf("fn_sym null err");
        char *name = malloc(5);
        sprintf(name, "f%d", i);
        fn_sym->name = name;
        fn_sym->section = text;
        fn_sym->flags = BSF_LOCAL;
        fn_sym->value = mcode_size;

        sym_tab[i] = fn_sym;

        // assemble fn's code
        MCode mcode = j_assemble(fn.text, fn.asm_arch, fn.asm_mode);

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

    // free mallocated code
    if (ir.fn_no > 0) free(ir.code);
    // set .text size now that we know for sure
    if (!bfd_set_section_size(text, mcode_size))
        printf("err setting .text size: %s\n", bfd_errmsg(bfd_get_error()));

    // START WRITING TO BFD

    // set data section contents directly to data from ir
    if (!bfd_set_section_contents(abfd, data, ir.data, 0, ir.data_size))
        printf("err setting .data contents: %s\n", bfd_errmsg(bfd_get_error()));
    // free mallocated data in ir
    free(ir.data);

    // set text section contents to all of the compiled code
    size_t cur_code_ptr = 0;
    for (size_t i = 0; i < ir.fn_no; i++) {
        // put machine code into the .text section
        MCode *mcode = &mcodes[i];
        if (!bfd_set_section_contents(abfd, text, mcode->encode, cur_code_ptr, mcode->size))
            printf("err setting .text contents: %s\n", bfd_errmsg(bfd_get_error()));
        cur_code_ptr += mcode->size;
            
        ks_free(mcode->encode);
    }

    // TODO: demallocate deps

    return abfd;
}

int generate_obj(char *const ir_path, char *const out_file) {
    // create ir from file
    JovisIR ir = open_jir(ir_path);
    // create bfd from ir
    bfd *abfd = create_bfd(ir, out_file);
    // generate object file
    bool err = !bfd_close(abfd);
    if (err) {
        printf("err at close: %s\n", bfd_errmsg(bfd_get_error()));
        return -1;
    }

    return 0;
}

int j_link(char *const entry_file) {
    int bfd_err = generate_obj(entry_file, "jexec.o");
    if (bfd_err == -1) return -1;

    // link all object files together TODO

    return 0;
}