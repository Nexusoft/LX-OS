# Make trousers (a TPM library) for Nexus

# source information: version and filepath to archive
APP_NAME	:= trousers
APP_VERSION	:= 0.3.4
APP_BASE	:= $(APP_NAME)-$(APP_VERSION)
APP_SRC		:= $(APP_BASE).tar.gz

ifeq ($(BUILD_VERBOSE),)
REDIR		:= >/dev/null
endif

# target information: 
TARGETS 	:= $(APP_BASE)/src/tspi/.libs/libtspi.a \
		   $(APP_BASE)/src/tcsd/tcsd 

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
		   -DTCSD_DEFAULT_PORT=30003 -DBI_OPENSSL -DTSS_NO_GUI \
		   -W -Wall -Werror -Wno-unused-parameter -Wsign-compare \
		   -DTSS_VER_MAJOR=0 -DTSS_VER_MINOR=3 \
		   -DTSS_SPEC_MAJOR=1 -DTSS_SPEC_MINOR=2

NX_LDFLAGS	:= -Bstatic -e compatmain -nostdlib

NX_LIBS		:= -Wl,--start-group,$(NXLIBDIR)/liblwip.a,$(NXLIBDIR)/libc.a,$(NXLIBDIR)/libnexus.a,$(NXLIBDIR)/libnexus-sec.a,$(NXLIBDIR)/libnexus-sys.a,$(NXLIBDIR)/libcrypto.a,$(NXLIBDIR)/libssl.a,$(NXLIBDIR)/libz.a,$(GCC_HOME)/libgcc.a,$(NXLIBDIR)/crti.o,$(NXLIBDIR)/crt1.o,$(NXLIBDIR)/crtn.o,--end-group

NX_MAKE_OPTS 	:= CC=gcc LD=GCC CFLAGS="$(NX_CFLAGS)" LDFLAGS="$(NX_LDFLAGS)" LIBS="$(NX_LIBS)"

CONFIG_OPTS	:= --disable-shared --enable-static --with-gui=none \
		   --with-gnu-ld
#		   --with-openssl=$(NXBUILDDIR)/user --with-gnu-ld

.PHONY: all install clean distclean

all: $(TARGETS)

# unpack and patch
$(APP_BASE)/Makefile.am:
	@echo "Unpacking sources"
	@tar -xf $(APP_SRC)
	@(cd $(APP_BASE); patch -p1 < ../$(APP_BASE).nexus.patch)
	@(cd $(APP_BASE); ./configure $(CONFIG_OPTS))

# NB: configure runs for local host, too fool it into passing a compilation test
# NB: make will fail. but if all went well, after we are done
$(TARGETS): $(APP_BASE)/Makefile.am
	@echo "Building $(APP_BASE)"
	-@(cd $(APP_BASE); make $(NX_MAKE_OPTS))

install: $(TARGETS)
	@(cd $(NXBUILDDIR)/user/lib; ln -sf ../packages/trousers/$(APP_BASE)/src/tspi/.libs/libtspi.a .)
	@cp -alf $(APP_BASE)/src/tcsd/tcsd $(NXBUILDDIR)/boot/bin

clean:
	@make -C $(APP_BASE) $(NX_MAKE_OPTS) clean

distclean: 
	rm -rf $(APP_BASE)

