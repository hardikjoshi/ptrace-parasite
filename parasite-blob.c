#include <sys/types.h>

/* syscall; int $0x03; "hello, world!\n" */
static const char blob[24] = "\x0f\x05\xcd\x03hello, world!\n";
const char *parasite_blob = blob;
const size_t parasite_blob_size = sizeof(blob);
