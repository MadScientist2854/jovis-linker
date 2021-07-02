#include <bfd.h>
#include "jovisir.h"
#include "assemble.h"

bfd create_bfd(JovisIR ir) {
    bfd abfd;
    asection *data = bfd_make_section_old_way(&abfd, ".data");
    bfd_set_section_contents(&abfd, data, ir.data, 0, ir.data_size);
    asection *code = bfd_make_section_old_way(&abfd, ".code");

    // create object-file symbols for code and data section starting points TODO

    // loop through fns
    Fn *cur_fn = ir.code;
    while (cur_fn->next != NULL) {
        // for each fn, assemble it's code
        MCode mcode = j_assemble(cur_fn->text, cur_fn->asm_type);
        // put the machine code into the .code section
        bfd_set_section_contents(&abfd, code, mcode.encode, code->size, mcode.size);
        // add symbol that points to start of fn TODO
        cur_fn = cur_fn->next;
    }
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