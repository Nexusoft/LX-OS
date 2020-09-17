# Make trousers (a TPM library) for Nexus

# source information: version and filepath to archive
APP_NAME	:= tpm-emulator
APP_VERSION	:= svn20100224
APP_BASE	:= $(APP_NAME)
APP_SRC		:= $(APP_BASE)-$(APP_VERSION).tgz

ifeq ($(BUILD_VERBOSE),)
REDIR		:= >/dev/null
endif

# target information: 
TARGET 		:= $(APP_BASE)/tpmd/tpmd

# library and header includes 
# RELATIVE to .../packages/lighttpd. This build will FAIL from other locations
NXBUILDDIR	:= $(PWD)/../../..
NXLIBDIR	:= $(NXBUILDDIR)/user/lib

GCC_MAJOR       := $(shell gcc -dumpversion | cut -d'.' -f1)
GCC_MINOR       := $(shell gcc -dumpversion | cut -d'.' -f2)
GCC_HOME	:= /usr/lib/gcc/$(shell gcc -dumpmachine)/$(shell gcc -dumpversion)

# configuration options
NX_CFLAGS	:= -fno-stack-protector \
		   -I . \
		   -I $(APP_BASE) \
		   -I $(APP_BASE)/build \
		   -I $(NXBUILDDIR)/user/include \
		   -I $(NXBUILDDIR)/common/include \
		   -I $(GCC_HOME)/include \
		   -I $(GCC_HOME)/include-fixed \
		   -nostdinc -Wall -Wno-unused-parameter -Wsign-compare

NX_LDFLAGS	:= -Bstatic -e compatmain -nostdlib

NX_LIBS		:= -Wl,--start-group,$(NXLIBDIR)/liblwip.a,$(NXLIBDIR)/libc.a,$(NXLIBDIR)/libnexus.a,$(NXLIBDIR)/libnexus-sec.a,$(NXLIBDIR)/libnexus-sys.a,$(NXLIBDIR)/libgmp.a,$(NXLIBDIR)/libcrypto.a,$(NXLIBDIR)/libssl.a,$(NXLIBDIR)/libz.a,$(GCC_HOME)/libgcc.a,$(NXLIBDIR)/crti.o,$(NXLIBDIR)/crt1.o,$(NXLIBDIR)/crtn.o,--end-group

.PHONY: all install clean distclean sources

all: binary

%.nexus.o: %.c
	$(CC) $(NX_CFLAGS) -c -o $@ $^

TPM_SRCS	 = $(wildcard $(APP_BASE)/crypto/*.c) \
		   $(wildcard $(APP_BASE)/tpm/*.c) \
		   $(APP_BASE)/tpmd/nexus/tpmd.c

TPM_OBJ		 = $(patsubst %.c,%.nexus.o,$(TPM_SRCS))

$(APP_BASE)/config.h:
	@echo "Unpacking sources"
	@tar -xf $(APP_SRC)
	@(cd $(APP_BASE); patch -p1 < ../$(APP_BASE).nexus.patch)

# recursive make to find generated (extracted from tgz) files
binary: $(APP_BASE)/config.h
	make $(TARGET)

$(TARGET): $(APP_BASE)/config.h $(TPM_OBJ)
	@gcc -o $@ $(NX_LDFLAGS) $(TPM_OBJ) $(NX_LIBS)

install: $(TARGET)
	@cp -alf $(TARGET) $(NXBUILDDIR)/boot/bin
	@echo "OK. installed"

clean:
	@make -C $(APP_BASE) $(NX_MAKE_OPTS) clean

distclean: 
	rm -rf $(APP_BASE)

