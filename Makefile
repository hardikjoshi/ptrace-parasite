all: parasite.c parasite-blob.c
	gcc -g -Wall -c -o parasite.o parasite.c
	gcc -g -Wall -c -o parasite-blob.o parasite-blob.c
	gcc -o parasite parasite.o parasite-blob.c

clean:
	rm -f parasite *.o
