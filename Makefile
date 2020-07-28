# main Nexus makefile
#
# builds tools, user and kernel (in that order)
# places binaries, headers and libs in build/ 

###### layout

# [TODO] explain the order of targets: it's simple, but the file is quite long

###### bugs

# * make stops immediately after building openssl. 
#   reissuing the command suffices to continue.

###### top-level targets

.PHONY: all first tools boot user kernel clean distclean \
	libs setup kern_setup kcore kdriver udriver apps version \
	packages_post initrd initrd_clean reinitrd kernel_clean user_clean \
	config oldconfig menuconfig iso dist doc help

ifeq ($(wildcard .config),)
all:
	@echo "\033[1;32mBuilding Nexus"
	@echo "\033[1;31mConfiguration options missing"
	@echo "First run 'make config'"
	@echo "       or 'make menuconfig'"
	@echo "       or 'make oldconfig'\033[0m"
	@false
else
all: tools user kernel iso
	@echo "Built Nexus successfully"

include .config
endif

help:
	@echo "Run make menuconfig	to configure your build"
	@echo "    make            	to compile and build an iso image"
	@echo "    make doc        	to generate documentation"
	@echo "    make dist        	to roll a distribution"
	@echo "    make help		to see this message"

doc:
	@which doxygen > /dev/null || { echo "make doc requires the doxygen package "; exit 1; }
	@which dot > /dev/null || { echo "make doc requires the graphviz package "; exit 1; }
	@rm -rf build/doc
	@doxygen build/tools/doxygen/nexus.doxygen
	@echo "Build documentation successfully"
	@echo "Point your browser to build/doc/html/index.html"

###### configuration options

config:
	./tools/kconfig/conf Config.in

oldconfig:
	./tools/kconfig/conf -o Config.in

menuconfig:
	./tools/kconfig/mconf Config.in

ifdef VERBOSE
CONFIG_QUIET =
endif

# intermediate files that make builds on depend. This label
# tells it not to remove them: to avoid frequent rebuilding
.SECONDARY: $(LIBNEXUS_OBJ)\
	    $(LIBNXSEC_OBJ)\
	    $(LIBNXSYS_OBJ)\
	    $(KERN_HDR) $(KERN_SRC) $(KERN_OBJ)

###### environtment variables

STDOUT		:= /tmp/nexus.stdout
STDERR		:= /tmp/nexus.stderr

# top level build directories
NEXUSROOT	:= $(shell pwd)
BUILDROOT	:= $(NEXUSROOT)/build
PREFIX		:= $(BUILDROOT)	# compatibility

# source directories
COMMONROOT	:= $(BUILDROOT)/common
SCROOT		:= $(COMMONROOT)/syscalls
SVCROOT		:= $(COMMONROOT)/services

USER_ROOT	:= $(BUILDROOT)/user
USER_LIBS	:= $(USER_ROOT)/lib
USER_INCL	:= $(USER_ROOT)/include
LIBNEXUS_ROOT	:= $(USER_ROOT)/libs/core
LIBNXSEC_ROOT	:= $(USER_ROOT)/libs/security
LIBNXSYS_ROOT	:= $(USER_ROOT)/libs/syscall
APPROOT		:= $(USER_ROOT)/apps
UDRV_ROOT	:= $(USER_ROOT)/drivers

KERN_ROOT	:= $(BUILDROOT)/kernel
KERN_CORE	:= $(KERN_ROOT)/core
KDRV_ROOT	:= $(KERN_ROOT)/drivers

# final targets
BINDIR		:= $(BUILDROOT)/boot/bin
INITRD_DIR	:= $(BUILDROOT)/boot/initrd
ISOROOT		:= $(BUILDROOT)/boot/isoroot
INITRD		:= $(ISOROOT)/initrd.tar
NEXUSBOOT	:= $(BUILDROOT)/boot/stage1

LINUXVERSION	:= legacy

#### tools

IDLGEN		:= build/tools/idlgen/nexus-idl/nexus-idlgen

# we rely on the system gcc, instead of adding gcc headers/libs to the build
# this is more maintainable; we get away with it because we build from scratch.
CC		:= gcc
GCC_MAJOR       := $(shell gcc -dumpversion | cut -d'.' -f1)
GCC_MINOR       := $(shell gcc -dumpversion | cut -d'.' -f2)
GCC_HOME	:= /usr/lib/gcc/$(shell gcc -dumpmachine)/$(shell gcc -dumpversion)
GCC_34PLUS      := $(shell if [ $(GCC_MAJOR) -ge 4 -o $(GCC_MINOR) -ge 3 ]; then echo 1; else echo 0; fi)
GCC_42PLUS      := $(shell if [ $(GCC_MAJOR) -ge 4 -a $(GCC_MINOR) -ge 2 ]; then echo 1; else echo 0; fi)
NXVERSION	:= BUILD-$(shell whoami)-$(shell date +%Y%m%d%H%m)-gcc$(shell gcc -dumpversion)

ifdef CONFIG_QUIET
LINK		:= ln -sf
TAROPTS		:= cvf	# temporary, so that I don't forget to reduce initrd size
Q		:= @
ERRORMSG	:="\033[1;31mERROR. Replaying error log: \033[0m"
IOREDIR		:= 1>>$(STDOUT) 2>$(STDERR) || (echo $(ERRORMSG); cat $(STDERR); exit 1)
else
LINK		:= ln -vsf
TAROPTS		:= cvf
Q		:= 
IOREDIR		:= 
endif

## gcc parameters

# include the standard GCC directories, but not the standard libC dirs,
# which we override with our own uClibc versions
INC_COMMON	:= -I . -I $(BUILDROOT)/common/include -nostdinc \
		   -isystem $(GCC_HOME)/include \
		   -isystem $(GCC_HOME)/include-fixed

INC_USER	:= -I $(USER_INCL) $(INC_COMMON)

# INC_USER, but with duct tape to help internal libnexus code 
# and old applications compile.
#
# for new apps we want to enforce INC_USER
INC_LEGACY	:= -I $(BUILDROOT)/common/include/nexus \
		   -I $(USER_INCL)/nexus \
		   -I $(BUILDROOT)/common/code \
		   $(INC_USER)    

INC_UDRIVER	:= \
		   -I $(BUILDROOT)/user/drivers/include \
		   -I $(USER_INCL) \
		   $(INC_COMMON)

INC_KERNEL	:= -I $(BUILDROOT)/common/include/nexus \
		   -I $(BUILDROOT)/common/code \
		   -I $(BUILDROOT)/kernel/include/nexus \
		   -I $(BUILDROOT)/kernel/include \
		   -I $(BUILDROOT)/kernel/core\
		   -I $(BUILDROOT)/kernel/core/crypto \
		   -I $(BUILDROOT)/kernel/core/lib \
		   -I $(BUILDROOT)/kernel \
		   $(INC_COMMON)

INC_KDRIVER	:= -I $(BUILDROOT)/kernel/drivers/include \
		   -I $(BUILDROOT)/kernel/include \
		   -I $(BUILDROOT)/kernel/include/nexus \
		   -I $(BUILDROOT)/common/include/nexus \
		   $(INC_COMMON)

WARNFLAGS	:= -Wall -Werror -Wno-pointer-sign -Wstrict-prototypes \
		   -Wno-trigraphs -Wno-unused
CFLAGS_COMMON	:= $(WARNFLAGS) -D_GNU_SOURCE -MD -D__NEXUS__ -pipe \
		   -mpreferred-stack-boundary=2 -march=i686 \
		   -fno-strict-aliasing -fexceptions

ifdef CONFIG_RELEASE
CFLAGS_COMMON	+= -DNO_DEBUG -O2
else
CFLAGS_COMMON	+= -g -O2	# NB: kernel build depends on optimizations
endif

# GCC's stack protector breaks uclibc.
ifeq ($(GCC_42PLUS), 1)
        CFLAGS_COMMON   += -fno-stack-protector
endif

ifdef CONFIG_XEN
CFLAGS_COMMON	+= -D__NEXUSXEN__
endif

# Flags for both the kernel cde compiler and assembler
CS_FLAGS_KERNEL	:= -D__KERNEL__ -D__NEXUSKERNEL__ -DDIRECT_NEXUS_INTERRUPT -D__DEBUG__

CFLAGS_USER	:= $(CFLAGS_COMMON) -DHAVE_FULL_LIBC
CFLAGS_UDRV	:= $(CFLAGS_COMMON) -DNEXUS_UDRIVER -D__KERNEL__
CFLAGS_KERNEL	:= $(CFLAGS_COMMON) $(CS_FLAGS_KERNEL)

# DISABLED because probably not needed
#-iwithprefix include

## other tool parameters

LD		:= ld
LDFLAGS		:= -m elf_i386

## output

color-red 	= \\033[1\;31m
color-green	= \\033[1\;32m
color-blue 	= \\033[1\;34m
color-reset 	= \\033[0m

ifdef CONFIG_QUIET
cmd_exec=@set -e; echo $(color-green)  $(1)$(color-reset); $(2)
else
cmd_exec=@set -e; echo $(color-green)$(2)$(color-reset); $(2)
endif

cmd_info=@set -e;echo $(color-green)$(1)$(color-reset);

###### implicit rules

# generate service sourcecode from IDL
%.client.c %.server.c %.interface.h: %.svc
	$(call cmd_exec,"[IDL] $<",$(IDLGEN) $< $(IOREDIR))
	@ln -sf $*.interface.h $(USER_INCL)/nexus/$(notdir $*).interface.h

%.kernel-client.c %.kernel-server.c %.kernel-interface.h: %.svc
	$(call cmd_exec,"[IDL] $<",$(IDLGEN) -k $< $(IOREDIR))

# generate userspace syscall sourcecode from IDL
# WARNING: nexus-idlgen generates different, but identically named interface.h 
#	   files for user and kernelspace. We rename them to distinguish them.
# NB: as work-around for files X.sc that except the X.interface.h in 
# common/syscalls, we copy instead of move.
# XXX have IDL generate distinguishable headers
%.user.c %.server.c %.ucall-interface.h %.interface.h: %.sc
	@-rm -f $*.user.c $*.ucall-interface.h	# may be a leftover
	$(call cmd_exec,"[IDL] $<",$(IDLGEN) $< $(IOREDIR))
	@-cp -f $*.interface.h $*.ucall-interface.h
	@-cp -uf $*.ucall-interface.h \
		$(USER_INCL)/nexus/$(notdir $*).interface.h
	         

# generate kernelspace syscall sourcecode from IDL
# see above statement
%.kernel.c %.kcall-interface.h: %.sc
	@-rm -f $*.kernel.c $*.kcall-interface.h # may be a leftover
	$(call cmd_exec,"[IDL] $<",$(IDLGEN) -k $< $(IOREDIR))
	@-cp -f $*.interface.h $*.kcall-interface.h
	@-cp -uf $*.kcall-interface.h \
		$(BUILDROOT)/kernel/include/nexus/$(notdir $*).interface.h

# generate a linux/nexus kernel keymap 
%.loadkeys.c : %.map
	@loadkeys --mktable $< | sed -e 's/^static *//' > $@

%.user.o: %.c
	@$(call cmd_exec,"[CC] $@",$(CC) -c -o $@ $(CFLAGS_USER) $< $(INC_LEGACY) $(IOREDIR))

# like user.o, but override the -Werror flag. For code that brings in ugly headers
%.nowarn.user.o: %.c
	@$(call cmd_exec,"[CC] $@",$(CC) -c -o $@ $(CFLAGS_USER) -Wno-error $< $(INC_LEGACY) $(IOREDIR))

%.user.o: %.S
	@$(call cmd_exec,"[ASM] $@",$(CC) $(INC_LEGACY) -c -o $@ $< $(IOREDIR))

# disabled -Werror for old Linux drivers
%.udriver.o: %.c
	@$(call cmd_exec,"[CC] $@",$(CC) -c -o $@ $(CFLAGS_UDRV) -Wno-error $< $(INC_UDRIVER) $(IOREDIR))

%.kern.o: %.c
	@$(call cmd_exec,"[CC] $@",$(CC) -c -o $@ $(CFLAGS_KERNEL) $< $(INC_KERNEL) $(IOREDIR))

# disabled -Werror for old Linux code
%.kold.o: %.c
	@$(call cmd_exec,"[CC] $@",$(CC) -c -o $@ $(CFLAGS_KERNEL) -Wno-error $< $(INC_KERNEL) $(IOREDIR))

%.kern.o: %.S
	@$(call cmd_exec,"[ASM] $@",$(CC) -m32 -D__ASSEMBLY__ $(CS_FLAGS_KERNEL) $(INC_KDRIVER) -c -o $@ $< $(IOREDIR))

# disabled -Werror for old Linux drivers
%.kdriver.o: %.c
	@$(call cmd_exec,"[CC] $@",$(CC) -c -o $@ $(CFLAGS_KERNEL) -Wno-error $< $(INC_KDRIVER) $(IOREDIR))

%.tab.c %.tab.h: %.y
	$(call cmd_info,' [YACC] $<')
	@(cd $(dir $*) && bison -d $<) $(IOREDIR)

# compilation is integrated to get around flex issue described here
# http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=191168
# in short: need to compile as strict C99
#
# NB: delete intermediate file to avoid having that picked up by regular .user.o compiler
%.yy.user.o %.yy.h: %.lex %.tab.c %.tab.user.o
	$(call cmd_info,' [FLEX] $<')
	@(cd $(dir $*) && flex -o $*.yy.c $<) $(IOREDIR)
	@$(call cmd_exec,"[CC] $@",$(CC) -c -std=c99 -o $@ $(CFLAGS_USER) $*.yy.c $(INC_LEGACY) $(IOREDIR))
	@-rm $*.yy.c $*.yy.kern.d $(IOREDIR)

# kernel version of above. also replaces stdio dependencies
%.yyk.kern.o: %.lex %.tab.c %.tab.kern.o
	$(call cmd_info,' [FLEX] $<')
	@(cd $(dir $*) && flex --nounput -stdout $< | sed 's/#include <[a-z]*.h>/#include "NAL.h"/' > $*.yyk.c ) $(IOREDIR)
	@$(call cmd_exec,"[CC] $@",$(CC) -c -o $@ $(CFLAGS_KERNEL) $*.yyk.c $(INC_KERNEL) $(IOREDIR))
	@-rm $*.yyk.c $*.yyk.kern.d $(IOREDIR)


###### build process targets (setup before real compilation can start)

BUILDDIRS	:= $(BUILDROOT) \
		   $(USER_INCL)/linux \
		   $(BUILDROOT)/kernel/include/linux \
		   $(BUILDROOT)/kernel/drivers/include/linux \
		   $(BINDIR) \
		   $(INITRD_DIR)

$(BUILDROOT):
	$(call cmd_info,Setting up build directory skeleton)
	@mkdir -p $(BUILDROOT)
	@mkdir -p $(USER_LIBS)
	@mkdir -p $(BUILDROOT)/boot/stage1
	@cp -al tools $(BUILDROOT)
	@cp -al common $(BUILDROOT)
	@cp -al user $(BUILDROOT)
	@cp -al kernel $(BUILDROOT)

$(BUILDROOT)/README:
	@cp -al README $(BUILDROOT)

$(BUILDROOT)/LICENSE:
	@cp -al LICENSE $(BUILDROOT)

$(ISOROOT):
	@mkdir -p $(ISOROOT)

$(BINDIR):
	@mkdir -p $(BINDIR)

$(INITRD_DIR):
	@mkdir -p $(INITRD_DIR)

$(USER_INCL)/linux: $(BUILDROOT)
	$(call cmd_info,Unpacking linux header files)
	@mkdir -p build/user/include
	@(cd build/user/include; tar xjf $(BUILDROOT)/common/packages/linux-headers/linux-headers-$(LINUXVERSION).tbz2)

$(BUILDROOT)/kernel/include/linux: $(BUILDROOT)
	@mkdir -p build/kernel/include
	@(cd build/kernel/include; tar xjf $(BUILDROOT)/common/packages/linux-headers/linux-headers-$(LINUXVERSION)-kernel.tbz2)

$(BUILDROOT)/kernel/drivers/include/linux: $(BUILDROOT)
	@mkdir -p build/kernel/drivers/include
	@(cd build/kernel/drivers/include; tar xjf $(BUILDROOT)/common/packages/linux-headers/linux-headers-$(LINUXVERSION)-kdrivers.tbz2)

$(BUILDROOT)/common/include/nexus/version.h:
	$(call cmd_info,Rebuilding version.h)
	@echo "#define NEXUSVERSION \"$(NXVERSION)\"" > $@

first:
	$(call cmd_info,Building Nexus. Redirecting output to $(STDOUT) and $(STDERR))
	$(call cmd_info,Make may fail once at IPC.interface.h. Call again and it will continue)
	@-rm $(STDOUT) $(STDERR) 2>/dev/null
	@-rm `find . -name NAL.yy.*.d` >/dev/null 2>/dev/null
	@-rm `find . -name NAL.yyk.*.d`>/dev/null 2>/dev/null

# a PHONY target to ensure that the file is rebuilt each time
version: 
	@-rm -f $(BUILDROOT)/common/include/nexus/version.h $(IOREDIR)

setup: first $(BUILDDIRS) version 

$(IDLGEN):
	$(call cmd_info,Building Idlgen)
	@make -C build/tools/idlgen

$(NEXUSBOOT)/nexus-gpxe.bzimage:
	$(call cmd_info,Building network booting tool)
	@make -C build/tools/gpxe		$(IOREDIR)
	@make -C build/tools/gpxe install	$(IOREDIR)
	$(call cmd_info,Copying boot images to $(dir $@))
	@cp build/tools/gpxe/nexus-gpxe.bzimage $(NEXUSBOOT)
	@cp build/tools/gpxe/nexus-gpxe.iso $(NEXUSBOOT)
	@cp build/tools/gpxe/nexus-gpxe.usb $(NEXUSBOOT)

ifdef CONFIG_GPXE
boot: $(NEXUSBOOT)/nexus-gpxe.bzimage
else
boot:
endif

tools: setup $(IDLGEN) boot

#### clean

CLEANTARGETSi 	:= .user.c .kernel.c .kernel-interface.h .interface.h \
		   .client.c .server.c .kernel-client.c .kernel-server.c \
		   .tab.h .yy.c .yyk.c .tab.c .kcall-interface.h \
		   .yy.user.d .yyk.kern.d
CLEANTARGETS	:= -name \*.o
CLEANTARGETS  	+= $(patsubst %, -or -name \*%, $(CLEANTARGETSi))

clean: kernel_clean
	@-rm -f $(shell find $(BUILDROOT) $(CLEANTARGETS))

distclean:  
	@-rm -rf build $(IOREDIR)

#### clean

dist: $(BUILDROOT)/boot/stage1/nexus.iso
	@echo "Generating distribution"
	-@rm -rf $(BUILDROOT)/dist
	@mkdir $(BUILDROOT)/dist
	@git archive --format=tar HEAD --prefix nexus-`date +%Y%m%d`/ | gzip > $(BUILDROOT)/dist/nexus-`date +%Y%m%d`.tgz
	@cp -al $^ $(BUILDROOT)/dist/nexus-`date +%Y%m%d`.iso
	@(cd $(BUILDROOT)/dist; for file in nexus*; do md5sum $$file > $$file.md5; done)
	@echo "Built distribution files in $(BUILDROOT)/dist"
	@echo "Run git tag release-`date +%Y%m%d` if you make this public"

###### userspace

#### packages

$(USER_LIBS)/libc.a: 
	@echo "Building libc"
	@make -C build/user/packages/uclibc 		$(IOREDIR)
	@make -C build/user/packages/uclibc install 	$(IOREDIR)

$(USER_LIBS)/libcrypto.a:
	@echo "Building openssl"
	@make -C build/user/packages/openssl 		$(IOREDIR)
	@make -C build/user/packages/openssl install 	$(IOREDIR)

$(BINDIR)/busybox: $(PACKAGES_PRE)
	@echo "Building busybox"
	@make -C build/user/packages/busybox		$(IOREDIR)
	@make -C build/user/packages/busybox install 	$(IOREDIR)

$(USER_LIBS)/liblwip.a: $(PACKAGES_PRE) $(USER_LIBS)/libnexus.a
	@echo "Building lwIP network stack"
	@make -C build/user/packages/lwip		$(IOREDIR)
	@make -C build/user/packages/lwip install	$(IOREDIR)

$(BINDIR)/mplayer $(BINDIR)/demo.mpg: $(PACKAGES_PRE) $(USER_LIBS)/liblwip.a 
	@echo "Building mplayer (go grab some coffee)"
	@make -C build/user/packages/mplayer 		$(IOREDIR)
	@make -C build/user/packages/mplayer install	$(IOREDIR)

$(BINDIR)/nc: $(PACKAGES_PRE) $(USER_LIBS)/liblwip.a $(USER_LIBS)/libnexus.a \
	      $(USER_LIBS)/liblwip.a
	@echo "Building netcat"
	@make -C build/user/packages/netcat		$(IOREDIR)
	@make -C build/user/packages/netcat install	$(IOREDIR)

# packages that are needed for the rest of user to build (e.g., libc)
PACKAGES_PRE	:= $(USER_LIBS)/libc.a \
		   $(USER_LIBS)/libcrypto.a

PACKAGES_POST	= 

ifdef CONFIG_MPLAYER
PACKAGES_POST	+= $(BINDIR)/mplayer 
endif
ifdef CONFIG_BUSYBOX
PACKAGES_POST	+= $(BINDIR)/busybox 
endif
ifdef CONFIG_NETCAT
PACKAGES_POST	+= $(BINDIR)/nc
endif

# packages on which no nexus code depends
packages_post:  $(PACKAGES_POST) 

#### library targets

## libnexus

# manually supplied list of targets
LIBNEXUS_USERi	:= IPC Net Thread Console Audio Debug Log Mem Profile Time 
LIBNEXUS_CLTi	:= FS 
LIBNEXUS_SRVi	:= RamFS
LIBNEXUS_OTHi	:= atomic debug init synch_asm synch tls ipc util \
		   env pthread trap pci_pfault ipc-server
#ns ns-util

# derived lists of required .c and .h objects
LIBNEXUS_CLT  	:= $(patsubst %, $(LIBNEXUS_ROOT)/%.client.user.o, $(LIBNEXUS_CLTi))
LIBNEXUS_SRV  	:= $(patsubst %, $(LIBNEXUS_ROOT)/%.server.user.o, $(LIBNEXUS_SRVi))
LIBNEXUS_USER 	:= $(patsubst %, $(LIBNEXUS_ROOT)/%.user.user.o,   $(LIBNEXUS_USERi))
LIBNEXUS_OTH 	:= $(patsubst %, $(LIBNEXUS_ROOT)/%.user.o,        $(LIBNEXUS_OTHi))
LIBNEXUS_OBJ	:= $(LIBNEXUS_USER) $(LIBNEXUS_CLT) $(LIBNEXUS_SRV) $(LIBNEXUS_OTH)

# derived list of IDL generated headers
# these have to be copied into the library include/nexus directory
LIBNEXUS_HDRi 	:= $(LIBNEXUS_USERi) $(LIBNEXUS_CLTi) $(LIBNEXUS_SRVi)
LIBNEXUS_HDR	:= $(patsubst %, $(USER_ROOT)/include/nexus/%.interface.h, $(LIBNEXUS_HDRi))

## START -- REPLACE FOR SHORTER IMPLICIT RULES
#
# unfortunately we cannot use implicit rules to automate this copy.
# VPATH/vpath seems an option, until you see that it behaves differently with/without
# directories in the target (GNU Makefile Manual Sec. 4.5)
#
# headers are copied to two locations: 
#	- inside the include dir belonging to the library: for packaging
#	- to shared user/nexus/include: for linking
$(LIBNEXUS_ROOT)/%.c: $(BUILDROOT)/common/code/%.c
	$(call cmd_exec,"[LINK] $@",$(LINK) $(abspath $<) $(dir $@) $(IOREDIR))

$(LIBNEXUS_ROOT)/%.c: $(SVCROOT)/%.c
	$(call cmd_exec,"[LINK] $@",$(LINK) $(abspath $<) $(dir $@) $(IOREDIR))

$(LIBNEXUS_ROOT)/%.c: $(SCROOT)/%.c
	$(call cmd_exec,"[LINK] $@",$(LINK) $(abspath $<) $(dir $@) $(IOREDIR))

$(USER_INCL)/nexus/%.interface.h: $(SCROOT)/%.ucall-interface.h
	$(call cmd_exec,"[LINK] $@", $(LINK) $(abspath $<) $@ $(IOREDIR))

$(USER_INCL)/nexus/%.interface.h: $(SVCROOT)/%.interface.h
	$(call cmd_exec,"[LINK] $@", $(LINK) $(abspath $<) $@ $(IOREDIR))

## END -- REPLACE FOR SHORTER IMPLICIT RULES

$(USER_LIBS)/libnexus.a: $(PACKAGES_PRE) $(LIBNEXUS_HDR) $(LIBNEXUS_OBJ)
	$(call cmd_exec,"[LD] $@",$(LD) $(LDFLAGS) -r -static -nostdlib -o $@ $(LIBNEXUS_OBJ) $(IOREDIR))

## libnexus-sec

LIBNXSEC_USERi	:= Attestation Crypto LabelStore nrk nsk SMR VDIR VKey
LIBNXSEC_HDRi 	:= $(LIBNXSEC_USERi)
LIBNXSEC_OTHi	:= tcpa_buildbuff formula guard base64 vkey \
		   aes timing x509parse \
		   tcpa_keys NAL.tab NAL.yy \
		   tpmcompat tpmidentity
# TODO: replace some imported security code, such as aes, with openssl equivalents (?)

LIBNXSEC_USER 	:= $(patsubst %, $(LIBNXSEC_ROOT)/%.user.user.o,   $(LIBNXSEC_USERi))
LIBNXSEC_OTH 	:= $(patsubst %, $(LIBNXSEC_ROOT)/%.user.o,        $(LIBNXSEC_OTHi))
LIBNXSEC_HDR	:= $(patsubst %, $(USER_ROOT)/include/nexus/%.interface.h, $(LIBNXSEC_HDRi))
LIBNXSEC_OBJ	:= $(LIBNXSEC_USER) $(LIBNXSEC_OTH)

## START -- REPLACE FOR SHORTER IMPLICIT RULES
#  see above for explanation
$(LIBNXSEC_ROOT)/%.c: $(BUILDROOT)/common/code/%.c
	$(call cmd_exec,"[LINK] $@",$(LINK) $(abspath $<) $(dir $@) $(IOREDIR))

$(LIBNXSEC_ROOT)/%.c: $(SVCROOT)/%.c
	$(call cmd_exec,"[LINK] $@",$(LINK) $(abspath $<) $(dir $@) $(IOREDIR))

$(LIBNXSEC_ROOT)/%.c: $(SCROOT)/%.c
	$(call cmd_exec,"[LINK] $@",$(LINK) $(abspath $<) $(dir $@) $(IOREDIR))

$(USER_INCL)/nexus/%.interface.h: $(SVCROOT)/%.interface.h
	$(call cmd_exec,"[LINK] $@", $(LINK) $(abspath $<) $@ $(IOREDIR))

$(USER_INCL)/nexus/%.interface.h: $(SCROOT)/%.ucall-interface.h
	$(call cmd_exec,"[LINK] $@", $(LINK) $(abspath $<) $@ $(IOREDIR))

## END -- REPLACE FOR SHORTER IMPLICIT RULES

$(USER_LIBS)/libnexus-sec.a: $(PACKAGES_PRE) $(LIBNEXSEC_STAGE) $(LIBNXSEC_HDR) $(LIBNXSEC_OBJ)
	$(call cmd_exec,"[LD] $@",$(LD) $(LDFLAGS) -r -static -nostdlib -o $@ $(LIBNXSEC_OBJ) $(IOREDIR))

## libnexus-sys

LIBNXSYS_CLTi	:= UserAudio
LIBNXSYS_OTHi	:= fs_path linuxcalls \
		   generic_file special_file posixfile net.nowarn

LIBNXSYS_CLT 	:= $(patsubst %, $(LIBNXSYS_ROOT)/%.client.user.o,   $(LIBNXSYS_CLTi))
LIBNXSYS_OTH 	:= $(patsubst %, $(LIBNXSYS_ROOT)/%.user.o,        $(LIBNXSYS_OTHi))
LIBNXSYS_OBJ	:= $(LIBNXSYS_CLT) $(LIBNXSYS_OTH)

## START -- REPLACE FOR SHORTER IMPLICIT RULES
#  see above for explanation
$(LIBNXSYS_ROOT)/%.c: $(SVCROOT)/%.c
	$(call cmd_exec,"[LINK] $@",$(LINK) $(abspath $<) $(dir $@) $(IOREDIR))
#endif

$(USER_LIBS)/libnexus-sys.a: $(PACKAGES_PRE) $(USER_LIBS)/liblwip.a $(LIBNXSYS_OBJ)
	$(call cmd_exec,"[LD] $@",$(LD) $(LDFLAGS) -r -static -nostdlib -o $@ $(LIBNXSYS_OBJ) $(IOREDIR))

## main targets

NEXUSLIBS	:= $(USER_LIBS)/libnexus.a \
		   $(USER_LIBS)/libnexus-sec.a \
		   $(USER_LIBS)/libnexus-sys.a

NEXUSLIBS: $(PACKAGES_PRE)

libs: $(NEXUSLIBS)

#### apps

APP_LIBS = $(NEXUSLIBS) \
	   $(USER_LIBS)/liblwip.a \
	   $(USER_LIBS)/libcrypto.a \
	   $(USER_LIBS)/libc.a \
	   $(USER_LIBS)/crti.o \
	   $(USER_LIBS)/crt1.o \
	   $(USER_LIBS)/crtn.o \
	   $(GCC_HOME)/libgcc.a

## build command
define LDAPP
	@$(call cmd_exec,"[LD] app: $@",$(LD) -Bstatic -e compatmain -o $@ $^)
	@$(call cmd_exec,"[STRIP] $@",(cp $@ $@.debug && strip $@))
endef

## applications that follow a basic order:
#     single source in a standard location 
DEFAULT_APPS	:= explorer dhcp ownership httpget
#analysis httpd nskgen tls_test \
		   helloworld helloworld-posix profilestart profileend

# rule for simple applications
DEFAULT_APP_OBJ	:= $(patsubst %, $(BINDIR)/%.app, $(DEFAULT_APPS))
$(BINDIR)/%.app: $(APPROOT)/simple/%.user.o $(APP_LIBS)
	$(LDAPP)

TEST_APPS	:= fs syscall libc thread
TEST_APP_OBJ	:= $(patsubst %, $(BINDIR)/%.test, $(TEST_APPS))
$(BINDIR)/%.test: $(APPROOT)/test/%.user.o $(APP_LIBS)
	$(LDAPP)

LWIP_APPS 	:= chargen httpd ping sntp
LWIP_APP_OBJ	:= $(patsubst %, $(BINDIR)/lwip_%.app, $(LWIP_APPS))
$(BINDIR)/lwip_%.app: $(APPROOT)/net/lwip/%.nowarn.user.o $(APP_LIBS)
	$(LDAPP)

GUARD_APPS 	:= svc demo fstest
GUARD_APP_OBJ	:= $(patsubst %, $(BINDIR)/guard_%.app, $(GUARD_APPS))
$(BINDIR)/guard_%.app: $(APPROOT)/guard/%.user.o $(APP_LIBS)
	$(LDAPP)

GRDTEST_APPS	:= cred auth
GRDTEST_APP_OBJ	:= $(patsubst %, $(BINDIR)/guard_%.test, $(GRDTEST_APPS))
$(BINDIR)/guard_%.test: $(APPROOT)/test/guard/%.user.o $(APP_LIBS)
	$(LDAPP)

## applications that diverge from the basic order
OTHER_APPS	:= minserver minclient daemon\
		   dhcp net_loopback net_udp nslookup nfs proofchecker
#tcpmgr
OTHER_APP_OBJ	:= $(patsubst %, $(BINDIR)/%.app, $(OTHER_APPS))

# the manually created rules for the non-standard applications
$(BINDIR)/net_loopback.app: $(APPROOT)/test/net/loopback.nowarn.user.o \
			 $(APP_LIBS)
	$(LDAPP)

# the manually created rules for the non-standard applications
$(BINDIR)/net_udp.app: $(APPROOT)/test/net/udp.nowarn.user.o \
			 $(APP_LIBS)
	$(LDAPP)

# the manually created rules for the non-standard applications
$(BINDIR)/nslookup.app: $(APPROOT)/test/net/nslookup.user.o \
			 $(APP_LIBS)
	$(LDAPP)

# the manually created rules for the non-standard applications
$(BINDIR)/net_loopsocket.app: $(APPROOT)/test/net/loopsocket.nowarn.user.o \
			 $(APP_LIBS)
	$(LDAPP)

# the manually created rules for the non-standard applications
$(BINDIR)/dhcp.app: $(APPROOT)/simple/dhcp.nowarn.user.o \
			 $(APP_LIBS)
	$(LDAPP)

# the manually created rules for the non-standard applications
$(BINDIR)/usertrap.test: $(APPROOT)/regression/gpf_vs_pf.user.o \
			 $(APP_LIBS)
	$(LDAPP)

$(BINDIR)/ipc.test: $(APPROOT)/../../common/test/ipc.user.o \
			 $(APP_LIBS)
	$(LDAPP)

$(BINDIR)/proofchecker.app: $(APPROOT)/guard/proofchecker.user.o \
			 $(APP_LIBS)
	$(LDAPP)

$(BINDIR)/minserver.app: $(APPROOT)/test/ipc/minimal_server.user.o \
			 $(APP_LIBS)
	$(LDAPP)

$(BINDIR)/minclient.app: $(APPROOT)/test/ipc/minimal_client.user.o \
			 $(APP_LIBS)
	$(LDAPP)

$(BINDIR)/tcpmgr.app: $(APPROOT)/tcpmgr/TCP.server.user.o \
		      $(APPROOT)/tcpmgr/tcpmgr.user.o \
		      $(APP_LIBS)
	$(LDAPP)

$(BINDIR)/nfs.app: $(APPROOT)/nfs/nfs.user.o \
		   $(APPROOT)/nfs/xdr.user.o \
		   $(APPROOT)/nfs/nfs_fh.user.o \
		   $(APPROOT)/nfs/nfs_cache.user.o \
		   $(APPROOT)/nfs/nfscompat.user.o \
		   $(APP_LIBS)
	$(LDAPP)

apps: libs $(DEFAULT_APP_OBJ) $(LWIP_APP_OBJ) $(TEST_APP_OBJ) $(OTHER_APP_OBJ)


#### userspace drivers

$(USER_LIBS)/libnexus-udriver.a: \
			       $(SCROOT)/ddrm.user.udriver.o \
			       $(SCROOT)/pci.user.udriver.o \
			       $(UDRV_ROOT)/compat/user_interrupts.udriver.o \
			       $(UDRV_ROOT)/compat/nexuscompat.udriver.o \
			       $(UDRV_ROOT)/compat/nexuspcicompat.udriver.o \
			       $(UDRV_ROOT)/compat/nexusethcompat.udriver.o \
			       $(UDRV_ROOT)/compat/nexuseth.udriver.o \
			       $(UDRV_ROOT)/compat/skbuff.udriver.o \
			       $(COMMONROOT)/net/device.udriver.o 
	$(call cmd_exec,"[LD] $@",$(LD) $(LDFLAGS) -r -static -nostdlib -o $@ $^ $(IOREDIR))

$(BINDIR)/audio-i810.drv: $(USER_LIBS)/libnexus-udriver.a \
			  $(SVCROOT)/UserAudio.server.udriver.o \
			  $(UDRV_ROOT)/sound/i810_audio/ac97_codec.udriver.o \
			  $(UDRV_ROOT)/sound/i810_audio/i810_audio.udriver.o \
			  $(UDRV_ROOT)/sound/i810_audio/sound_core.udriver.o \
			  $(UDRV_ROOT)/sound/i810_audio/sound_firmware.udriver.o \
			  $(UDRV_ROOT)/sound/i810_audio/udriver.udriver.o \
		  	  $(APP_LIBS)
	$(LDAPP)

$(BINDIR)/net-e1000.drv: $(USER_LIBS)/libnexus-udriver.a \
			 $(UDRV_ROOT)/net/e1000/e1000_hw.udriver.o \
			 $(UDRV_ROOT)/net/e1000/e1000_main.udriver.o \
			 $(UDRV_ROOT)/net/e1000/e1000_param.udriver.o \
			 $(UDRV_ROOT)/net/e1000/e1000_ethtool.udriver.o \
			 $(UDRV_ROOT)/net/e1000/udriver.udriver.o \
		  	 $(APP_LIBS)
	$(LDAPP)

udriver: $(BINDIR)/audio-i810.drv $(BINDIR)/net-e1000.drv

user: tools $(PACKAGES_PRE) libs packages_post apps udriver

## user cleaning.
#  don't destroy packages: they are in tools (and take a long time to compile)
user_clean:
	@-rm -f `find $(BUILDROOT)/user -name *.o` $(BUILDROOT)/lib/*.a
	@cp -al user $(BUILDROOT)

###### kernel

#### kernel core

KERN_CLTi 	:= FS 

KERN_SRVi 	:= RamFS

KERN_SYSCALLi	:= IPC Audio Console Crypto ddrm Debug \
		   Log Mem Net pci Profile SMR \
		   Thread Time Attestation nrk nsk VDIR VKey

KERN_NOIDLi	:= core/audio.c core/clock.c core/ddrm.c core/ddrm_i810_reset.c\
		   core/ddrm_intr.c core/ddrm_pci.c core/ddrm_region.c \
		   core/ddrm_sample_spec.c core/device.c core/devicelog.c \
		   core/eventqueue.c core/idtgdt.c core/init.c core/initrd.c \
		   core/ipd.c core/kbd.c core/kernelfs.c core/log.c \
		   core/machineprimitives.c core/mem.c core/mouse.c \
		   core/mtrr.c core/elf.c core/printk.c core/resource.c \
		   core/screen.c core/shell.c core/task.c core/thread.c \
		   core/syscall.c core/trap.c core/test.c core/util.c \
		   core/timing.c core/ksymbols.c core/debug.c core/malloc.c\
		   core/asm.S core/synch.c \
		   \
		   net/io.c net/skbuff.c net/switch.c net/tftp.c \
		   ../common/net/device.c net/debug.c net/filter.c \
		   \
		   ipc/iface.c ipc/impl.c ipc/registry.c \
		   \
		   security/hashtree.c \
		   security/tcpa.c \
		   security/libtcpa/attestation.c security/libtcpa/buildbuff.c\
		   security/libtcpa/certifykey.c security/libtcpa/dirs.c \
		   security/libtcpa/owner.c security/libtcpa/emulator.c \
		   security/libtcpa/hmac.c security/libtcpa/identity.c \
		   security/libtcpa/keys.c security/libtcpa/oiaposap.c \
		   security/libtcpa/pcrs.c security/libtcpa/quote.c \
		   security/libtcpa/seal.c security/libtcpa/signature.c \
		   security/libtcpa/tcpa.c security/libtcpa/transmit.c \
		   security/kvkey.c security/vdir.c \
		   security/crypto/aes.c security/crypto/rsa.c\
		   security/crypto/bignum.c security/crypto/sha1.c\
		   security/x509.c security/formula.c security/guard.c security/NAL.y\
		   security/NAL.lex security/base64.c security/encblocks.c \
		   \
		   test/mem.c test/various.c ../common/test/ipc.c \
		   \
		   xen/xen-stubs.c


ifdef CONFIG_XEN
KERN_SYSCALLi	+= Xen
KERN_NOIDLi	+= xen/xen.c xen/xen-asm.S xen/xen-bitmap.c xen/xen_gpf.c \
		   xen/x86_emulate.c
endif

KERN_HDRi 	:= $(KERN_CLTi) $(KERN_SRVi)
KERN_HDRj 	:= $(KERN_SYSCALLi)

# generated list of required .c sources and headers
# from shorthand versions [NAME]i, above
KERN_CLT  	:= $(patsubst %, $(KERN_CORE)/%.kernel-client.c, $(KERN_CLTi))
KERN_SRV  	:= $(patsubst %, $(KERN_CORE)/%.kernel-server.c, $(KERN_SRVi))
KERN_SYSCALL 	:= $(patsubst %, $(KERN_CORE)/%.kernel.c,   $(KERN_SYSCALLi))
KERN_NOIDL 	:= $(patsubst %, $(KERN_ROOT)/%,   	      $(KERN_NOIDLi))
KERN_SRC	:= $(KERN_SYSCALL) $(KERN_CLT) $(KERN_SRV) $(KERN_NOIDL)
KERN_HDR	:= $(patsubst %, $(BUILDROOT)/kernel/include/nexus/%.interface.h, $(KERN_HDRj)) \
		   $(patsubst %, $(BUILDROOT)/kernel/include/nexus/%.kernel-interface.h, $(KERN_HDRi))

## START -- REPLACE FOR SHORTER IMPLICIT RULES
# rules to link needed headers and sources from common/
# see above for explanation
$(KERN_CORE)/%.kernel-client.c: $(SVCROOT)/%.kernel-client.c
	$(call cmd_exec,"[LINK] $@",$(LINK) $(abspath $<) $(dir $@))

$(KERN_CORE)/%.kernel-server.c: $(SVCROOT)/%.kernel-server.c
	$(call cmd_exec,"[LINK] $@",$(LINK) $(abspath $<) $(dir $@))

$(KERN_CORE)/%.kernel.c: $(SCROOT)/%.kernel.c
	$(call cmd_exec,"[LINK] $@",$(LINK) $(abspath $<) $(dir $@))

$(BUILDROOT)/kernel/include/nexus/%.kernel-interface.h: $(SVCROOT)/%.kernel-interface.h
	$(call cmd_exec,"[LINK] $@",$(LINK) $(abspath $<) $(dir $@))

$(BUILDROOT)/kernel/include/nexus/%.interface.h: $(SCROOT)/%.kcall-interface.h
	$(call cmd_exec,"[LINK] $@",$(LINK) $(abspath $<) $@)
## END -- REPLACE FOR SHORTER IMPLICIT RULES

KERN_OBJC	:= $(patsubst %.c, %.kern.o, $(KERN_SRC)) 	
KERN_OBJSC	:= $(patsubst %.S, %.kern.o, $(KERN_OBJC))	
KERN_OBJYSC	:= $(patsubst %.y, %.tab.kern.o, $(KERN_OBJSC))	
KERN_OBJ	:= $(patsubst %.lex, %.yyk.kern.o, $(KERN_OBJYSC))

kcore: $(BUILDROOT)/common/include/nexus/version.h $(KERN_SRC) $(KERN_HDR) $(KERN_OBJ)

#### kernel drivers

KDRIVER_SRC	:= sound/i810_audio sound/ac97_codec sound/sound_core \
		   sound/sound_firmware char/keyboard\
		   char/pc_keyb net/tg3 net/setup net/3c59x net/mii net/net_init\
		   tpm/tpm_core tpm/tpm_atmel tpm/tpm_nsc video/vesafb \
		   video/fbcmap video/font_8x16 video/terminus_8x16 \
		   video/fixed_8x16 video/fbcon-cfb32 \
		   video/fbcon pci/pci pci/names pci/quirks pci/setup-bus \
		   pci/setup-irq pci/setup-res compat

KDRIVER_OBJ	:= $(KDRV_ROOT)/char/defkeymap.loadkeys.kdriver.o \
		   $(patsubst %, $(KDRV_ROOT)/%.kdriver.o, $(KDRIVER_SRC)) 

$(KDRV_ROOT)/pci/devlist.h:
	@ $(CC) -o $(KDRV_ROOT)/pci/gen-devlist $(KDRV_ROOT)/pci/gen-devlist.c
	@(cd $(KDRV_ROOT)/pci && ./gen-devlist < pci.ids)


kdriver: $(KDRV_ROOT)/pci/devlist.h $(KDRIVER_OBJ)

#### kernel linking

KINITROOT	:= build/kernel/init
BZLINKFLAGS	:= -Ttext 0x100000 -e startup_32
OBJCOPY		:= objcopy -O binary -R .note -R .comment -S

#export ROOT_DEV	
export SVGA_MODE	:= -DSVGA_MODE=NORMAL_VGA

## main nexus library
#  it combines raw .o files along with a set of libraries
#  the first goals setup these libraries
$(KINITROOT)/kernel/head.kern.o: $(BUILDROOT)/kernel/include/nexus/asm-offsets.h
$(KINITROOT)/kernel/entry.kern.o: $(BUILDROOT)/kernel/include/nexus/asm-offsets.h

# nexus.o: largest 'sub' library
$(BUILDROOT)/kernel/core/nexus.o: $(KERN_OBJ)
	$(call cmd_exec,"[LD] $@",ld -r -o $@ $+)

# kernel.o
KERNINIT_BASE	:= i8259 setup time pci-dma pci-i386 pci-pc pci-irq
KERNINIT_OBJ	:= $(patsubst %, $(KINITROOT)/kernel/%.kold.o, $(KERNINIT_BASE))

$(KINITROOT)/kernel/kernel.o: $(KINITROOT)/kernel/entry.kern.o $(KERNINIT_OBJ)
	$(call cmd_exec,"[LD] $@",ld -r -o $@ $+)

# nexus/lib/lib.a
NEXUSLIB_BASE	:= errno ctype string vsprintf cmdline dec_and_lock
NEXUSLIB_OBJ	:= $(patsubst %, $(BUILDROOT)/kernel/core/lib/%.kold.o, $(NEXUSLIB_BASE))

$(BUILDROOT)/kernel/core/lib/lib.a: $(NEXUSLIB_OBJ)
	$(call cmd_exec,"[LD] $@",ld -r -o $@ $+)

# init/lib/lib.a
$(KINITROOT)/lib/lib.a: $(KINITROOT)/lib/checksum.kern.o \
			$(KINITROOT)/lib/getuser.kern.o \
			$(KINITROOT)/lib/memcpy.kold.o \
			$(KINITROOT)/lib/strstr.kold.o
	$(call cmd_exec,"[LD] $@",ld -r -o $@ $+)

# init/mm/mm.a
$(KINITROOT)/mm/mm.o: $(KINITROOT)/mm/ioremap.kold.o
	$(call cmd_exec,"[LD] $@",ld -r -o $@ $+)

# offsets. must be recalculated on each change to sources
$(BUILDROOT)/kernel/include/nexus/asm-offsets.h: \
			$(BUILDROOT)/kernel/core/nexus.o \
			$(BUILDROOT)/kernel/core/lib/lib.a \
			$(KINITROOT)/lib/lib.a
	$(call cmd_info,Computing asm-offset.h)
	@$(KINITROOT)/tools/compute-offsets.pl > $(KINITROOT)/kernel/comp-offsets.c
	@$(CC) $(CFLAGS_KERNEL) -I $(BUILDROOT)/common/include -I $(BUILDROOT)/kernel/include -o $(KINITROOT)/kernel/comp-offsets $(KINITROOT)/kernel/comp-offsets.c 
	@$(KINITROOT)/kernel/comp-offsets > $@
	@-rm $(KINITROOT)/kernel/comp-offsets $(KINITROOT)/kernel/comp-offsets.c

VMNEXUS_OBJ	:= $(KINITROOT)/kernel/head.kern.o \
		   $(KINITROOT)/kernel/init_task.kold.o \
		   $(BUILDROOT)/kernel/core/main.kold.o

# Combine everything. This is where linker errors will show
# NB: we add libgcc only because some functions perform 64 bit division.
$(KINITROOT)/vmnexus:	$(BUILDROOT)/kernel/include/nexus/asm-offsets.h \
			$(VMNEXUS_OBJ) \
			$(KINITROOT)/kernel/kernel.o \
			$(KINITROOT)/mm/mm.o \
			$(BUILDROOT)/kernel/core/nexus.o \
			$(BUILDROOT)/kernel/core/lib/lib.a \
			$(KINITROOT)/lib/lib.a \
			$(KDRIVER_OBJ)
	$(call cmd_exec,"[LD] $@",ld -T $(KINITROOT)/vmnexus.lds -e stext \
		$(VMNEXUS_OBJ) \
                --start-group \
		$(KINITROOT)/kernel/kernel.o \
		$(KINITROOT)/mm/mm.o \
		$(BUILDROOT)/kernel/core/nexus.o \
                $(KDRIVER_OBJ) \
		$(BUILDROOT)/kernel/core/lib/lib.a \
		$(KINITROOT)/lib/lib.a \
		$(GCC_HOME)/libgcc.a \
                --end-group \
                -o $@)
	
# created a compressed object
$(KINITROOT)/piggy.o: $(KINITROOT)/vmnexus
	$(call cmd_info,[LD] $@)
	@rm -f $(KINITROOT)/tmp $(KINITROOT)/tmp.gz $(KINITROOT)/tmp.lnk
	@$(OBJCOPY) $(KINITROOT)/vmnexus $(KINITROOT)/tmp
	@gzip -f -9 < $(KINITROOT)/tmp > $(KINITROOT)/tmp.gz
	@echo "SECTIONS { .data : { input_len = .; LONG(input_data_end - input_data) input_data = .; *(.data) input_data_end = .; }}" > $(KINITROOT)/tmp.lnk
	@ld -r -o $@ -b binary $(KINITROOT)/tmp.gz -b elf32-i386 -T ${KINITROOT}/tmp.lnk
	@rm -f $(KINITROOT)/tmp $(KINITROOT)/tmp.gz $(KINITROOT)/tmp.lnk

# create a self-deflating compressed image
$(KINITROOT)/bvmnexus: $(KINITROOT)/boot/compressed/head.kern.o \
		       $(KINITROOT)/boot/compressed/misc.kold.o \
		       $(KINITROOT)/piggy.o 
	$(call cmd_exec,"[LD] $@",ld $(BZLINKFLAGS) -o $@ $+)

## bootloader
#  see also http://tldp.org/LDP/lki/lki-1.html 
$(KINITROOT)/boot/bbootsect:$(KINITROOT)/boot/bbootsect.lko
	$(call cmd_exec,"[LD] $@",ld -Ttext 0x0 -s --oformat binary -o $@ $<)

$(KINITROOT)/boot/bsetup: $(KINITROOT)/boot/bsetup.lko
	$(call cmd_exec,"[LD] $@",ld -Ttext 0x0 -s --oformat binary -e begtext -o $@ $<)

$(KINITROOT)/boot/%.lko: $(KINITROOT)/boot/%.s
	$(call cmd_exec,"[AS] $@",as --32 -o $@ $<)

$(KINITROOT)/boot/bbootsect.s: $(KINITROOT)/boot/bootsect.S 
	$(call cmd_exec,"[CC] $@",$(CC) -E -D__NEXUSKERNEL__ -D__KERNEL__ $(INC_KERNEL) -D__BIG_KERNEL__ -traditional $(SVGA_MODE) -o $@ $<)

$(KINITROOT)/boot/bsetup.s: $(KINITROOT)/boot/setup.S $(KINITROOT)/boot/video.S 
	$(call cmd_exec,"[CC] $@",$(CC) -E -D__NEXUSKERNEL__ -D__KERNEL__ $(INC_KERNEL) -D__BIG_KERNEL__ -D__ASSEMBLY__ -traditional $(SVGA_MODE) -o $@ $<)

$(KINITROOT)/tools/build: $(KINITROOT)/tools/build.c
	@$(CC) -o $@ $+ -I $(BUILDROOT)/kernel/include

## the bzImage-formatted kernel
$(ISOROOT)/vmnexuz: $(ISOROOT) $(KINITROOT)/boot/bbootsect \
		$(KINITROOT)/boot/bsetup $(KINITROOT)/bvmnexus \
		$(KINITROOT)/tools/build
	$(call cmd_info,Creating bzImage)
	@$(OBJCOPY) $(KINITROOT)/bvmnexus $(KINITROOT)/bvmnexus.out
	@$(KINITROOT)/tools/build -b $(KINITROOT)/boot/bbootsect $(KINITROOT)/boot/bsetup $(KINITROOT)/bvmnexus.out $(ROOT_DEV) > $@

## initrd
$(KINITROOT)/boot/initrd/System.map : $(KINITROOT)/vmnexus
	@nm $^ | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' | sort > $@

# files that are packed into the initial root directory (initrd)
INITRD_FILES :=	$(KINITROOT)/boot/initrd/initscript \
		$(KINITROOT)/boot/initrd/System.map \
						\
		$(BINDIR)/net-e1000.drv 	\
						\
		$(BINDIR)/usertrap.test 	\
		$(BINDIR)/ipc.test 		\
	        $(BINDIR)/fs.test 		\
	        $(BINDIR)/libc.test 		\
	        $(BINDIR)/thread.test 		\
	        $(BINDIR)/syscall.test 		\
		$(BINDIR)/guard_cred.test 	\
	        $(BINDIR)/guard_auth.test 	\
	        $(BINDIR)/net_loopback.app 	\
	        $(BINDIR)/net_udp.app 		\
						\
		$(BINDIR)/lwip_chargen.app	\
		$(BINDIR)/lwip_httpd.app	\
		$(BINDIR)/lwip_ping.app		\
						\
		$(BINDIR)/dhcp.app 		\
		$(BINDIR)/httpget.app 		\
		$(BINDIR)/minserver.app 	\
		$(BINDIR)/minclient.app 	\
	        $(BINDIR)/explorer.app 		\
		$(BINDIR)/guard_svc.app		\
		$(BINDIR)/guard_demo.app	\
		$(BINDIR)/guard_fstest.app	\
		$(BINDIR)/proofchecker.app	\
	        $(BINDIR)/nfs.app 		\
		$(BINDIR)/ownership.app		\
	        $(BINDIR)/daemon.app 		\
						\
		$(BUILDROOT)/LICENSE		\
		$(BUILDROOT)/README		

#						\
		## stuff we need to fix		\
		$(BINDIR)/audio-i810.drv 	\
		$(BINDIR)/lwip_sntp.app		\
	        $(BINDIR)/nslookup.app		\
		$(BINDIR)/nc			\
						\
		## stuff that's basically OK	\
	        $(BINDIR)/helloworld.app 	\
	        $(BINDIR)/helloworld-posix.app 	\

ifdef CONFIG_BUSYBOX
INITRD_FILES +=	$(BINDIR)/busybox
endif

ifdef CONFIG_MPLAYER
INITRD_FILES +=	$(BINDIR)/mplayer		\
		$(BINDIR)/demo.mpg		\
		$(BINDIR)/demo.mpg.README
endif

$(INITRD): $(INITRD_DIR) $(INITRD_FILES)
	$(call cmd_info,Creating initrd)
	@-rm $(INITRD_DIR)/* 2>/dev/null
	@cp -alf $(INITRD_FILES) $(INITRD_DIR)
	@date > $(INITRD_DIR)/version
	@(cd $(INITRD_DIR) && tar $(TAROPTS) $@ *)

initrd:$(INITRD)

initrd_clean:
	@-rm $(INITRD)

reinitrd: initrd_clean initrd

## kernel top-level
kernel: setup kcore kdriver $(ISOROOT)/vmnexuz $(INITRD)

## kernel cleaning
kernel_clean:
	@-rm -f $(KINITROOT)/boot/bbootsec $(KINITROOT)/boot/bbootsect.lko \
	     $(KINITROOT)/boot/bbootsect.s $(KINITROOT)/boot/bsetup \
	     $(KINITROOT)/boot/bsetup.lko $(KINITROOT)/boot/bsetup.s \
	     $(KINITROOT)/tools/build $(KINITROOT)/bvmnexus \
	     $(KINITROOT)/vmnexus.a $(KINITROOT)/vmnexus.la $(VMNEXUS_OBJ) \
	     $(KINITROOT)/boot/compressed/head.kern.o \
	     $(KINITROOT)/boot/compressed/misc.kern.o 2>/dev/null \
	     $(KINITROOT)/kernel/asm-offsets.h $(IOREDIR)

## automatic dependencies using gcc -MD
#  see e.g., http://make.paulandlesley.org/autodep.html
include $(shell find $(BUILDROOT) -name *.d)

#### create a minimal iso image of the kernel and initrd
##   expects isolinux.bin to be in /usr/lib/syslinux, where Ubuntu puts it
$(BUILDROOT)/boot/stage1/nexus.iso: $(ISOROOT)/vmnexuz $(INITRD)
	cp -al $(BUILDROOT)/tools/isolinux/isolinux.bin $(ISOROOT)
	cp -al $(BUILDROOT)/tools/isolinux/isolinux.cfg $(ISOROOT)
	cp -al $(BUILDROOT)/tools/isolinux/menu.c32 $(ISOROOT)
	mkisofs -no-emul-boot -boot-load-size 4 -boot-info-table \
		-b isolinux.bin -c boot.catalog \
		-o $(BUILDROOT)/boot/stage1/nexus.iso $(ISOROOT)
	rm $(ISOROOT)/isolinux.bin $(ISOROOT)/isolinux.cfg $(ISOROOT)/menu.c32

iso: $(BUILDROOT)/boot/stage1/nexus.iso

