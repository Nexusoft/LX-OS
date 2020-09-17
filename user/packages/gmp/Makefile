# Make libgmp for Nexus

# source information: version and filepath to archive
APP_NAME	:= gmp
APP_VERSION	:= 4.3.2
APP_BASE	:= $(APP_NAME)-$(APP_VERSION)
APP_SRC		:= $(APP_BASE).tar.bz2

ifeq ($(BUILD_VERBOSE),)
REDIR		:= >/dev/null
endif

# target information: 
TARGET 	:= $(APP_BASE)/.libs/libgmp.a

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
		   -I $(NXBUILDDIR)/user/packages/trousers/$(APP_BASE)/src/include \
		   -I $(NXBUILDDIR)/user/include \
		   -I $(NXBUILDDIR)/common/include \
		   -I $(GCC_HOME)/include \
		   -I $(GCC_HOME)/include-fixed \
		   -nostdinc \
		   -W -Wall -Wno-unused-parameter -Wsign-compare

NX_LDFLAGS	:= -Bstatic -e compatmain -nostdlib

NX_LIBS		:= -Wl,--start-group,$(NXLIBDIR)/liblwip.a,$(NXLIBDIR)/libc.a,$(NXLIBDIR)/libnexus.a,$(NXLIBDIR)/libnexus-sec.a,$(NXLIBDIR)/libnexus-sys.a,$(NXLIBDIR)/libcrypto.a,$(NXLIBDIR)/libssl.a,$(NXLIBDIR)/libz.a,$(GCC_HOME)/libgcc.a,$(NXLIBDIR)/crti.o,$(NXLIBDIR)/crt1.o,$(NXLIBDIR)/crtn.o,--end-group

NX_MAKE_OPTS 	:= CC=gcc LD=GCC CFLAGS="$(NX_CFLAGS)" LDFLAGS="$(NX_LDFLAGS)" LIBS="$(NX_LIBS)"

CONFIG_OPTS	:= --disable-shared --enable-static --with-gnu-ld \
		   --with-openssl=$(NXBUILDDIR)/user CC=gcc 

.PHONY: all install clean distclean

all: $(TARGET)

# unpack and patch
$(APP_BASE)/config.h:
	@echo "Unpacking sources"
	@tar -xf $(APP_SRC)
	@(cd $(APP_BASE); patch -p1 < ../$(APP_BASE).nexus.patch)

# to get past issues with my hacky cross compiling in configure, 
# we configure for the local system (fragile)
$(TARGET): $(APP_BASE)/config.h
	@(cd $(APP_BASE); ./configure $(CONFIG_OPTS))
	@(cd $(APP_BASE); make $(NX_MAKE_OPTS))

# build the gmp check applications
check: $(TARGET)
	@(cd $(APP_BASE)/tests; make check-apps $(NX_MAKE_OPTS))

install: $(TARGET)
	@(cd $(NXBUILDDIR)/user/lib; ln -sf ../packages/gmp/$(TARGET) .)
	@cp $(APP_BASE)/mp.h $(APP_BASE)/gmp*h $(NXBUILDDIR)/user/include

clean:
	@make -C $(APP_BASE) $(NX_MAKE_OPTS) clean

distclean: 
	rm -rf $(APP_BASE)

