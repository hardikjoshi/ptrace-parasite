	.file	"parasite-blob.c"
	.section	.rodata
	.align 16
	.type	blob, @object
	.size	blob, 24
blob:
	.string	"\017\005\315\003hello, world!\n"
	.zero	5
	.globl	parasite_blob
	.data
	.align 8
	.type	parasite_blob, @object
	.size	parasite_blob, 8
parasite_blob:
	.quad	blob
	.globl	parasite_blob_size
	.section	.rodata
	.align 8
	.type	parasite_blob_size, @object
	.size	parasite_blob_size, 8
parasite_blob_size:
	.quad	24
	.text
	.type	dummy_container_fn, @function
dummy_container_fn:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
#APP
# 10 "parasite-blob.c" 1
	movq $1, %rax			
	movq $1, %rdx			
	movq 1f, %rsi			
	movq $14, %rdx		
	syscall			
	int $0x03			
	1: .ascii "hello, world!\n"
	
# 0 "" 2
#NO_APP
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	dummy_container_fn, .-dummy_container_fn
	.ident	"GCC: (GNU) 4.6.0 20110530 (Red Hat 4.6.0-9)"
	.section	.note.GNU-stack,"",@progbits
