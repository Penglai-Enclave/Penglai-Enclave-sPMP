# SPDX-License-Identifier: GPL-2.0
#
# Building a vDSO image for AArch64.
#
# Author: Will Deacon <will.deacon@arm.com>
# Heavily based on the vDSO Makefiles for other archs.
#

# Absolute relocation type $(ARCH_REL_TYPE_ABS) needs to be defined before
# the inclusion of generic Makefile.
ARCH_REL_TYPE_ABS := R_AARCH64_JUMP_SLOT|R_AARCH64_GLOB_DAT|R_AARCH64_ABS64
include $(srctree)/lib/vdso/Makefile

obj-ilp32-vdso := vgettimeofday-ilp32.o note-ilp32.o sigreturn-ilp32.o

# Build rules
targets := $(obj-ilp32-vdso) vdso-ilp32.so vdso-ilp32.so.dbg
obj-ilp32-vdso := $(addprefix $(obj)/, $(obj-ilp32-vdso))

btildflags-$(CONFIG_ARM64_BTI_KERNEL) += -z force-bti

# -Bsymbolic has been added for consistency with arm, the compat vDSO and
# potential future proofing if we end up with internal calls to the exported
# routines, as x86 does (see 6f121e548f83 ("x86, vdso: Reimplement vdso.so
# preparation in build-time C")).
ldflags-y := -shared -nostdlib -soname=linux-ilp32-vdso.so.1 --hash-style=sysv	\
	     -Bsymbolic $(call ld-option, --no-eh-frame-hdr) --build-id -n	\
	     $(btildflags-y) -T

ccflags-y := -fno-common -fno-builtin -fno-stack-protector -ffixed-x18
ccflags-y += -DDISABLE_BRANCH_PROFILING
#ccflags-y += -nostdlib
ccflags-y += -nostdlib -Wl,-soname=linux-ilp32-vdso.so.1 \
		$(call cc-ldoption, -Wl$(comma)--hash-style=sysv)

CFLAGS_REMOVE_vgettimeofday-ilp32.o = $(CC_FLAGS_FTRACE) -Os $(CC_FLAGS_SCS) $(GCC_PLUGINS_CFLAGS)
KBUILD_CFLAGS			+= $(DISABLE_LTO)
KASAN_SANITIZE			:= n
UBSAN_SANITIZE			:= n
OBJECT_FILES_NON_STANDARD	:= y
KCOV_INSTRUMENT			:= n

CFLAGS_vgettimeofday-ilp32.o = -O2 -mcmodel=tiny -fasynchronous-unwind-tables -mabi=ilp32

ifneq ($(c-gettimeofday-y),)
  CFLAGS_vgettimeofday-ilp32.o += -include $(c-gettimeofday-y)
endif

# Clang versions less than 8 do not support -mcmodel=tiny
ifeq ($(CONFIG_CC_IS_CLANG), y)
  ifeq ($(shell test $(CONFIG_CLANG_VERSION) -lt 80000; echo $$?),0)
    CFLAGS_REMOVE_vgettimeofday-ilp32.o += -mcmodel=tiny
  endif
endif

# Disable gcov profiling for VDSO code
GCOV_PROFILE := n

obj-y += vdso-ilp32.o
extra-y += vdso-ilp32.lds
CPPFLAGS_vdso-ilp32.lds += -P -C -U$(ARCH) -mabi=ilp32

# Force dependency (incbin is bad)
$(obj)/vdso-ilp32.o : $(obj)/vdso-ilp32.so

# Link rule for the .so file, .lds has to be first
$(obj)/vdso-ilp32.so.dbg: $(obj)/vdso-ilp32.lds $(obj-ilp32-vdso)
	$(call if_changed,vdso-ilp32ld_and_vdso_check)

# Strip rule for the .so file
$(obj)/%.so: OBJCOPYFLAGS := -S
$(obj)/%.so: $(obj)/%.so.dbg FORCE
	$(call if_changed,objcopy)

# Generate VDSO offsets using helper script
gen-vdsosym := $(srctree)/$(src)/../vdso/gen_vdso_offsets.sh
quiet_cmd_vdsosym = VDSOSYM $@
      cmd_vdsosym = $(NM) $< | $(gen-vdsosym) | LC_ALL=C sort > $@

include/generated/vdso-ilp32-offsets.h: $(obj)/vdso-ilp32.so.dbg FORCE
	$(call if_changed,vdsosym)

$(obj)/vgettimeofday-ilp32.o: $(src)/../vdso/vgettimeofday.c
	$(call if_changed_dep,vdso-ilp32cc)

$(obj)/note-ilp32.o: $(src)/../vdso/note.S
	$(call if_changed_dep,vdso-ilp32as)

$(obj)/sigreturn-ilp32.o: $(src)/../vdso/sigreturn.S
	$(call if_changed_dep,vdso-ilp32as)

# Actual build commands
quiet_cmd_vdso-ilp32ld_and_vdso_check = LD      $@
      cmd_vdso-ilp32ld_and_vdso_check = $(CC) $(c_flags) -mabi=ilp32 -Wl,-n -Wl,-T $^ -o $@
quiet_cmd_vdso-ilp32cc = VDSOILP32C $@
      cmd_vdso-ilp32cc= $(CC) $(c_flags) -mabi=ilp32 -c -o $@ $<
quiet_cmd_vdso-ilp32as = VDSOILP32A $@
      cmd_vdso-ilp32as = $(CC) $(a_flags) -mabi=ilp32 -c -o $@ $<

# Install commands for the unstripped file
quiet_cmd_vdso_install = INSTALL $@
      cmd_vdso_install = cp $(obj)/$@.dbg $(MODLIB)/vdso/$@

vdso-ilp32.so: $(obj)/vdso-ilp32.so.dbg
	@mkdir -p $(MODLIB)/vdso
	$(call cmd,vdso_install)

vdso_install: vdso-ilp32.so
