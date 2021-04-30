all: gcc run

gcc:
	gcc test.c
musl:
	musl-gcc -static test.c

run:
	./a.out
