KEYSTONE_LDFLAGS = -lkeystone -lstdc++ -lm

all:
	${CC} -o bin/main src/main.c ${KEYSTONE_LDFLAGS}

clean:
	rm -rf *.o test1