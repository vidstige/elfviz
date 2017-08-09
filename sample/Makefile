all: bar

a.o: a.c
	gcc -c a.c

b.o: b.c
	gcc -c b.c

main.o: main.c
	gcc -c main.c

libfoo.a: a.o b.o
	ar rvs libfoo.a a.o b.o

bar: main.o libfoo.a
	gcc -L. main.o -lfoo -o bar

clean:
	rm -f *.o libfoo.a bar

.PHONY: all clean
