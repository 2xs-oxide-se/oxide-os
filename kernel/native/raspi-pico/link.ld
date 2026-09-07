ENTRY(_start)

__OXIDE_SE_BOOT_ABI_SIZE = 0x20;

__StackLimit = ORIGIN(RAM);
__StackTop = __StackLimit + __STACK_SIZE_CPU0;
__oxide_se_boot_abi_start = __StackTop;
__fae_ram_start = __oxide_se_boot_abi_start + __OXIDE_SE_BOOT_ABI_SIZE;
__oxide_se_kernel_mutable_ram_start = ORIGIN(RAM);
__oxide_se_kernel_mutable_ram_size = 0xc000;
__oxide_se_kernel_mutable_ram_end = __oxide_se_kernel_mutable_ram_start + __oxide_se_kernel_mutable_ram_size;
__oxide_se_critical_kernel_fct_ram_start = ORIGIN(RAM) + 0x10000;
__fae_ram_end = ORIGIN(RAM) + LENGTH(RAM);

__registry_persistence_page_size = 0x100;
__registry_persistence_erase_sector_size = 0x1000;
__registry_persistence_page_count = 1024;
__registry_persistence_size = __registry_persistence_page_size * __registry_persistence_page_count;
__registry_persistence_end = ORIGIN(FLASH) + LENGTH(FLASH);
__registry_persistence_start = __registry_persistence_end - __registry_persistence_size;

SECTIONS
{
  . = ORIGIN(FLASH);

  .boot2 : ALIGN(4)
  {
    KEEP(*(.boot2))
    . = ALIGN(4);
  } > FLASH

  ASSERT(SIZEOF(.boot2) == 256, "RP2040 boot2 must be exactly 256 bytes")

  .vectors : ALIGN(4)
  {
    KEEP(*(.vectors))
    . = ALIGN(4);
  } > FLASH

  .text : ALIGN(4)
  {
    *(.text .text.*)
    *(.rodata .rodata.*)
    . = ALIGN(4);
  } > FLASH

  .data __fae_ram_start : ALIGN(4)
  {
    __data_start = .;
    *(.data .data.*)
    . = ALIGN(4);
    __data_end = .;
  } > RAM AT > FLASH
  __data_load = LOADADDR(.data);

  .bss (NOLOAD) : ALIGN(4)
  {
    __bss_start = .;
    *(.bss .bss.*)
    *(COMMON)
    . = ALIGN(4);
    __bss_end = .;
  } > RAM

  __ram_end = ALIGN(8);

  .critical.kernel.fct __oxide_se_critical_kernel_fct_ram_start : ALIGN(4)
  {
    __critical_kernel_fct_start = .;
    KEEP(*(.critical.kernel.fct .critical.kernel.fct.*))
    KEEP(*(.text.*p256*))
    KEEP(*(.text.*elliptic_curve*))
    KEEP(*(.text.*crypto_bigint*))
    KEEP(*(.text.*primeorder*))
    KEEP(*(.text.*sec1*))
    KEEP(*(.text.*subtle*))
    KEEP(*(.text.*_2ff*))
    . = ALIGN(4);
    __critical_kernel_fct_end = .;
  } > RAM AT > FLASH
  __critical_kernel_fct_load = LOADADDR(.critical.kernel.fct);

  __flash_image_end = LOADADDR(.critical.kernel.fct) + SIZEOF(.critical.kernel.fct);

  /DISCARD/ :
  {
    *(.ARM.exidx*)
    *(.eh_frame*)
    *(.comment)
    *(.note*)
    *(.ARM.attributes)
  }
}

ASSERT(__fae_ram_end >= __fae_ram_start, "Invalid RAM window for native ELF")
ASSERT(__ram_end <= __oxide_se_kernel_mutable_ram_end, "Native ELF mutable RAM sections overflow the Pico kernel RAM-XN window")
ASSERT(__ram_end <= __fae_ram_end, "Native ELF RAM sections overflow target RAM")
ASSERT(__registry_persistence_start % __registry_persistence_page_size == 0, "Registry persistence start must be page-aligned")
ASSERT(__registry_persistence_start % __registry_persistence_erase_sector_size == 0, "Registry persistence start must be erase-sector-aligned")
ASSERT(__flash_image_end <= __registry_persistence_start, "Native ELF flash image overlaps registry persistence area")
