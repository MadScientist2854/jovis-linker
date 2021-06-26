KEYSTONE_LDFLAGS = -lkeystone -lstdc++ -lm
BFD_LDFLAGS = -lbfd

all:
	${CC} -o bin/main src/main.c ${KEYSTONE_LDFLAGS} ${BFD_LDFLAGS}

clean:
	rm -rf *.o test1