#include <bfd.h>
#include "jovisir.h"
#include "assemble.h"

bfd create_bfd(JovisIR ir) {
    bfd abfd;
    asection *data = bfd_make_section_old_way(&abfd, ".data");
    bfd_set_section_contents(&abfd, data, ir.data, 0, ir.data_size);
    asection *code = bfd_make_section_old_way(&abfd, ".code");

    // create object-file symbols for code and data section starting points TODO
    // check how relocations are done to make sure this is needed

    typedef struct SymLLNode {
        asymbol *sym;
        struct SymLLNode *next;
    } SymLLNode;
    SymLLNode *last;
    SymLLNode *first = last;

    // loop through fns
    Fn *cur_fn = ir.code;
    int count = 0;
    for (;cur_fn->next != NULL; count++) {
        // for each fn, assemble it's code
        MCode mcode = j_assemble(cur_fn->text, cur_fn->asm_type);
        // add symbol that points to start of fn
        asymbol *fn_sym = bfd_make_empty_symbol(&abfd);
        sprintf(fn_sym->name, "f%d", count);
        fn_sym->section = code;
        fn_sym->flags = BSF_LOCAL;
        fn_sym->value = code->size;

        last->sym = fn_sym;
        SymLLNode *next = malloc(sizeof(SymLLNode));
        last->next = next;
        last = next;
        // put the machine code into the .code section
        bfd_set_section_contents(&abfd, code, mcode.encode, code->size, mcode.size);
        cur_fn = cur_fn->next;
    }
    last->sym = (asymbol *)0;
    last->next = NULL;
    // turn linked list into array
    asymbol *sym_tab[count+1];
    SymLLNode *cur = first;
    for (size_t i = 0; i <= count; i++) {
        sym_tab[i] = cur;
        cur = cur->next;
    }
    // set sym tab on bfd
    bfd_set_symtab(&abfd, sym_tab, count);
    // add bfd_error checks TODO

    return abfd;
}

void link(char **ir_files, size_t no_of_files) {
    // for each IR file
    for (size_t i = 0; i < no_of_files; i++) {
        JovisIR ir = jir_from_file(ir_files[i]);
        // create bfd from ir
        bfd abfd = create_bfd(ir);
        // generate object file TODO
        // add bfd_error checks TODO
    }

    // free all mallocated stuff TODO

    // link all object files together TODO
}