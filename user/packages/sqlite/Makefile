# Make sqlite for Nexus

# source information: version and filepath to archive
APP_NAME	:= sqlite
APP_VERSION	:= 3.6.22
APP_BASE	:= $(APP_NAME)-$(APP_VERSION)
APP_SRC		:= $(APP_NAME)-amalgamation-$(APP_VERSION).tar.gz

ifeq ($(BUILD_VERBOSE),)
REDIR		:= >/dev/null
endif

# target information: 
TARGET	 	:= $(APP_BASE)/.libs/libsqlite3.a

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
		   -nostdinc \
		   -DSQLITE_DISABLE_LFS

NX_LIBS		:= -Wl,--start-group,$(NXLIBDIR)/liblwip.a,$(NXLIBDIR)/libc.a,$(NXLIBDIR)/libnexus.a,$(NXLIBDIR)/libnexus-sec.a,$(NXLIBDIR)/libnexus-sys.a,$(NXLIBDIR)/libcrypto.a,$(NXLIBDIR)/libssl.a,$(NXLIBDIR)/libz.a,$(GCC_HOME)/libgcc.a,$(NXLIBDIR)/crti.o,$(NXLIBDIR)/crt1.o,$(NXLIBDIR)/crtn.o,--end-group -nostdlib

NX_CONFIG_OPTS	:= --disable-shared --enable-static --disable-dynamic-extensions --disable-readline --disable-largefile
NX_MAKE_OPTS 	:= CC=gcc LD=GCC CFLAGS="$(NX_CFLAGS)" LIBS="$(NX_LIBS)"

.PHONY: all install clean distclean

all: $(TARGET)

# unpack 
$(APP_BASE):
	@echo "Unpacking sources"
	@tar -xf $(APP_SRC)

# configure and make 
# don't care if make fails at building the .la file. the .a will already have been built
$(TARGET): $(APP_BASE)
	@echo "Building $(APP_BASE)"
	@(cd $(APP_BASE); ./configure $(NX_CONFIG_OPTS))
	@-make -C $(APP_BASE) $(NX_MAKE_OPTS) 

install: $(TARGET)
	@(cd $(NXBUILDDIR)/user/lib; ln -sf ../packages/sqlite/$(TARGET) .)
	@cp -alf $(APP_BASE)/sqlite3.h $(NXBUILDDIR)/user/include
	@echo "Installed $(APP_BASE)"

clean:
	@make -C $(APP_BASE) $(NX_MAKE_OPTS) clean

distclean: 
	rm -rf $(APP_BASE)

