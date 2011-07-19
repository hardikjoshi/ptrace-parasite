all: main.c parasite-blob.o
	gcc -g -Wall -c main.c
	gcc -o parasite main.o parasite-blob.c

parasite-blob.o: parasite.bin parasite-blob.c
	gcc -g -Wall -c parasite-blob.c

parasite.bin: parasite.c parasite.lds
	gcc -Wall -fpic -c parasite.c
	ld -T parasite.lds -o parasite.bin parasite.o

clean:
	rm -f parasite *.o *.bin
