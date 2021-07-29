#include "linker.h"

int main(int argc, char **argv) {
    JovisIR ir;
    ir.data = "hello, world!";
    ir.data_size = 14;
    Fn fn1;
    fn1.size = 17;
    fn1.text = "push 40";
    fn1.asm_arch = KS_ARCH_X86;
    fn1.asm_mode = KS_MODE_64;
    ir.code = &fn1;
    ir.fn_no = 1;
    create_ir("test1.jir", ir);
    create_ir("test2.jir", ir);

    char *ir_files[2];
    ir_files[0] = "test1.jir";
    ir_files[1] = "test2.jir";

    link(ir_files, 2);

    // char **targets = bfd_arch_list();
    // for (int i = 0; targets[i] != NULL; i++) {
    //     printf("%s\n", targets[i]);
    // }

    return 0;
}