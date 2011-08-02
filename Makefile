all: parasite simple-host net-host

parasite: main.c parasite-blob.h parasite.h
	gcc -Wall -o parasite main.c -lnetfilter_queue

parasite-blob.h: parasite.c parasite.lds parasite.h
	gcc -Wall -fpic -c parasite.c
	ld -T parasite.lds -o parasite.bin parasite.o
	echo 'static char parasite_blob[] = {' > parasite-blob.h
	hexdump -v -e '"\t"' -e '8/1 "0x%02x, "' -e '"\n"' parasite.bin >> parasite-blob.h
	echo '};' >> parasite-blob.h

simple-host: simple-host.c
	gcc -Wall -o simple-host simple-host.c -lpthread

net-host: net-host.c
	gcc -Wall -o net-host net-host.c -lpthread

clean:
	rm -f parasite parasite-blob.h *.o *.bin simple-host net-host
