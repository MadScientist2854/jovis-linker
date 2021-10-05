KEYSTONE_LDFLAGS = -lkeystone -lstdc++ -lm
BFD_LDFLAGS = -lbfd

all:
	${CC} -o bin/main src/main.c ${KEYSTONE_LDFLAGS} ${BFD_LDFLAGS}

lib:
	${CC} -c -o bin/linker.o src/lib.c -lkeystone ${BFD_LDFLAGS}
	ar rcs bin/libjlinker.a bin/linker.o 

clean:
	rm -rf *.o test1