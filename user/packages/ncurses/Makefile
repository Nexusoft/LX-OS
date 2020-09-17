# Make sqlite for Nexus

# source information: version and filepath to archive
APP_NAME	:= ncurses
APP_VERSION	:= 5.7
APP_BASE	:= $(APP_NAME)-$(APP_VERSION)
APP_SRC		:= $(APP_BASE).tar.gz

ifeq ($(BUILD_VERBOSE),)
REDIR		:= >/dev/null
endif

# target information: 
TARGET	 	:= $(APP_BASE)/lib/libncurses.a

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
		   -I $(NXBUILDDIR)/user/include \
		   -I $(NXBUILDDIR)/common/include \
		   -I $(GCC_HOME)/include \
		   -I $(GCC_HOME)/include-fixed \
		   -nostdinc

NX_LIBS		:= -Wl,--start-group,$(NXLIBDIR)/liblwip.a,$(NXLIBDIR)/libc.a,$(NXLIBDIR)/libnexus.a,$(NXLIBDIR)/libnexus-sec.a,$(NXLIBDIR)/libnexus-sys.a,$(NXLIBDIR)/libcrypto.a,$(NXLIBDIR)/libssl.a,$(NXLIBDIR)/libz.a,$(GCC_HOME)/libgcc.a,$(NXLIBDIR)/crti.o,$(NXLIBDIR)/crt1.o,$(NXLIBDIR)/crtn.o,--end-group -nostdlib

NX_MAKE_OPTS 	:= CC=gcc LD=GCC CFLAGS="$(NX_CFLAGS)" LIBS="$(NX_LIBS)"
NX_CONFIG_OPTS	:= --without-shared --with-normal --disable-largefile --without-progs

.PHONY: all install clean distclean

all: $(TARGET)

# unpack and patch
$(APP_BASE):
	@echo "Unpacking sources"
	@tar -xf $(APP_SRC)

# Build:
# first make the host parts used during second stage build
# then build for the nexus
#
# The second part fails, but not until after we get our library, so no biggie.
$(TARGET): $(APP_BASE)
	@echo "Building $(APP_BASE)"
	@(cd $(APP_BASE); ./configure $(NX_CONFIG_OPTS))
	@make -C $(APP_BASE) sources
	@-make -C $(APP_BASE) $(NX_MAKE_OPTS) 
	@echo "Nexus: don't mind the ctypes error. We have our library by now"

# manually install, because we cannot use install with the failed make
# this is NOT a full install. A lot is missing. XXX fix
install: $(TARGET)
	@(cd $(NXBUILDDIR)/user/lib; ln -sf ../packages/ncurses/$(TARGET) .)
	@-mkdir $(NXBUILDDIR)/user/include/ncurses
	@cp -f $(APP_BASE)/include/*.h $(NXBUILDDIR)/user/include/ncurses
	@cp -f $(APP_BASE)/include/*.h $(NXBUILDDIR)/user/include
	@(cd $(NXBUILDDIR)/user/include/ncurses; ln -sf curses.h ncurses.h)
	@echo "Installed $(APP_BASE)"

clean:
	@make -C $(APP_BASE) $(NX_MAKE_OPTS) clean

distclean: 
	rm -rf $(APP_BASE)

