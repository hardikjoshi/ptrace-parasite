OUTPUT_FORMAT("binary")
OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	.text : {
		*(.entry.text)
		*(.text)
	}

	.data : {
		*(.data)
		*(.rodata)
		*(.bss)
	}
}
