all: parasite.c
	gcc -g -Wall -c -o parasite.o parasite.c
	gcc -o parasite parasite.o

clean:
	rm -f parasite *.o
