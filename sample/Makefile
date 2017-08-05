CC=gcc
CFLAGS=-I.

bar: libfoo.a
	gcc main.c libfoo.a -o bar

.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

libfoo.a: a.o b.o
	ar rcs libfoo.a a.o b.o

