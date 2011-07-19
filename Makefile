all: main.c parasite-blob.o
	gcc -g -Wall -c main.c
	gcc -o parasite main.o parasite-blob.c

parasite-blob.o: parasite.c parasite.lds
	gcc -Wall -fpic -c parasite.c
	ld -T parasite.lds -o parasite.bin parasite.o
	echo 'char parasite_blob[] = {' > parasite-blob.c
	hexdump -v -e '8/1 "0x%02x, "' -e '"\n"' parasite.bin >> parasite-blob.c
	echo -e '};\nint parasite_blob_size = sizeof(parasite_blob);' >> parasite-blob.c
	gcc -g -Wall -c parasite-blob.c

clean:
	rm -f parasite parasite-blob.c *.o *.bin
