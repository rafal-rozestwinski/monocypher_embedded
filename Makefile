all: gcc run

CFLAGS= -fPIC -std=gnu11 -ggdb -fwrapv -fno-strict-aliasing -fno-omit-frame-pointer -fverbose-asm -Wall -Wfatal-errors

gcc:
	$(CC) $(CFLAGS) test.c
musl:
	musl-gcc -static $(CFLAGS) test.c

run:
	./a.out
