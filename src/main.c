#include "assembler.h"

#define CODE "INC ecx; DEC edx"

int main(int argc, char **argv)
{
    unsigned char* encode = j_assemble(CODE);

    return 0;
}