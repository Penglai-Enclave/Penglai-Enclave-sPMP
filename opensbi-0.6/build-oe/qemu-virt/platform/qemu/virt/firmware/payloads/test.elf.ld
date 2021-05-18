OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{

 . = 0x80000000 + 0x200000;




 PROVIDE(_payload_start = .);

 . = ALIGN(0x1000);



 .text :
 {
  PROVIDE(_text_start = .);
  *(.entry)
  *(.text)
  . = ALIGN(8);
  PROVIDE(_text_end = .);
 }

 . = ALIGN(0x1000);





 . = ALIGN(0x1000);

 .rodata :
 {
  PROVIDE(_rodata_start = .);
  *(.rodata .rodata.*)
  . = ALIGN(8);
  PROVIDE(_rodata_end = .);
 }





 . = ALIGN(0x1000);

 .data :
 {
  PROVIDE(_data_start = .);

  *(.data)
  *(.data.*)
  *(.readmostly.data)
  *(*.data)
  . = ALIGN(8);

  PROVIDE(_data_end = .);
 }

 . = ALIGN(0x1000);

 .bss :
 {
  PROVIDE(_bss_start = .);
  *(.bss)
  *(.bss.*)
  . = ALIGN(8);
  PROVIDE(_bss_end = .);
 }



 . = ALIGN(0x1000);

 PROVIDE(_payload_end = .);
}
