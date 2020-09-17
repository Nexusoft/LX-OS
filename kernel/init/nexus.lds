/* ld script to make nexus multiboot kernel
 */
OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
SECTIONS
{
  . = 0xC0000000 + 0x100000;
  _text = .;			/* Text and read-only data */
  .text : {
	*(.text)
	*(.fixup)
	*(.gnu.warning)
	} = 0x9090
  _etext = .;			/* End of text section */

  .rodata : {
    *(.rodata)
    *(.rodata.*)
    }

  __ksymtab : {
    *(__ksymtab)
    }

  .data : {			    /* Data */
	*(.data)
	}
  _edata = .;			/* End of data section */

  .bss : {              /* BSS */
	*(.bss)
	}
  _end = . ;
}
