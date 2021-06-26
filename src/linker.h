#include <bfd.h>
#include "jovisir.h"

bfd create_bfd(JovisIR ir) {
    bfd abfd;
    asection *data = bfd_make_section_old_way(&abfd, ".data");
    bfd_set_section_contents(&abfd, data, ir.data, data->size, ir.data_size);
    // add bfd_error checks

    return abfd;
}

void link(char **ir_files, size_t no_of_files) {
    for (size_t i = 0; i < no_of_files; i++) {
        JovisIR ir = jir_from_file(ir_files[i]);
        bfd abfd = create_bfd(ir);
        // add bfd_error checks
    }
    
    // for each IR file
    // create object-file labels for IR labels that are relative to code and data section starting points
    // assemble code section
    // generate object file

    // link all object files together
}