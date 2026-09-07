ENTRY(_start)

__OXIDE_SE_BOOT_ABI_SIZE = 0x20;

SECTIONS
{
  . = ORIGIN(FLASH);

  ._start : ALIGN(4)
  {
    KEEP(*("._start"))
    . = ALIGN(4);
  } > FLASH

  __metadataOff = .;
  ASSERT(__metadataOff == _end, "_end must stay at end of ._start")

  /DISCARD/ :
  {
    *(.ARM.exidx*)
    *(.eh_frame*)
    *(.comment)
    *(.note*)
    *(.ARM.attributes)
  }
}

__StackLimit    = ORIGIN(RAM);
__StackTop      = __StackLimit + __STACK_SIZE_CPU0;
__oxide_se_boot_abi_start = __StackTop;
__fae_ram_start = __oxide_se_boot_abi_start + __OXIDE_SE_BOOT_ABI_SIZE;
__fae_ram_end   = ORIGIN(RAM) + LENGTH(RAM);

ASSERT(__fae_ram_end >= __fae_ram_start, "Invalid RAM window for FAE")
