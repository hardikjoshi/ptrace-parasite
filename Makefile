all: main.c parasite-blob.c
	gcc -g -Wall -c -o main.o main.c
	gcc -g -Wall -c -o parasite-blob.o parasite-blob.c
	gcc -o parasite main.o parasite-blob.c

clean:
	rm -f parasite *.o
