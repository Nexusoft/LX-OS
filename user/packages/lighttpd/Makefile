# Make Lighthttpd for Nexus
#
# Lighthttp has a two-stage build. We build the lemon parser for the 
# development system (Linux) and then build the server for nexus

# source information: version and filepath to archive
APP_BASE	:= lighttpd-1.4.25
APP_HOSTBASE	:= $(APP_BASE)-host
APP_SRC		:= $(APP_BASE).tar.gz

ifeq ($(BUILD_VERBOSE),)
REDIR		:= >/dev/null
endif

# target information: 
TARGETS	 	:= $(APP_BASE)/src/lighttpd

# library and header includes 
# RELATIVE to .../packages/lighttpd. This build will FAIL from other locations
NXBUILDDIR	:= $(PWD)/../../..
NXLIBDIR	:= $(NXBUILDDIR)/user/lib

GCC_MAJOR       := $(shell gcc -dumpversion | cut -d'.' -f1)
GCC_MINOR       := $(shell gcc -dumpversion | cut -d'.' -f2)
GCC_HOME	:= /usr/lib/gcc/$(shell gcc -dumpmachine)/$(shell gcc -dumpversion)

# configuration options
NX_CFLAGS	:= -fno-stack-protector \
		   -I $(NXBUILDDIR)/user/include \
		   -I $(NXBUILDDIR)/common/include \
		   -I $(GCC_HOME)/include \
		   -I $(GCC_HOME)/include-fixed \
		   -nostdinc -std=c99 -O2 \
		   -DLIGHTTPD_STATIC

NX_LDFLAGS	:= -Bstatic -e compatmain

# ldflags are very sensitive, because lighttpd uses libtool, and
# libtool tries to munge our --start-group .. --end-group
NX_LIBS		:= -Wl,--start-group,$(NXLIBDIR)/crti.o,$(NXLIBDIR)/crt1.o,$(NXLIBDIR)/crtn.o,$(NXLIBDIR)/liblwip.a,$(NXLIBDIR)/libc.a,$(NXLIBDIR)/libnexus.a,$(NXLIBDIR)/libnexus-sec.a,$(NXLIBDIR)/libnexus-sys.a,$(NXLIBDIR)/libcrypto.a,$(NXLIBDIR)/libssl.a,$(NXLIBDIR)/libz.a,$(GCC_HOME)/libgcc.a,--end-group -nostdlib

# configure options shared by host and target
NX_CONFIG_OPTS	:= --without-pcre \
		   --without-bzip2 \
		   --disable-ipv6 \
		   --disable-lfs \
		   --without-zlib \
		   --without-bzip2

NX_CONFIG_OPTS_HOST 	:= $(NX_CONFIG_OPTS)
NX_CONFIG_OPTS_TARGET 	:= $(NX_CONFIG_OPTS) \
		   	   --disable-shared \
		   	   --enable-static \
			   --with-openssl \
		   	   CC=gcc CFLAGS="$(NX_CFLAGS)" 

NX_MAKE_OPTS 	:= CC=gcc LD=GCC CFLAGS="$(NX_CFLAGS)" LDFLAGS="$(NX_LDFLAGS)" LIBS="$(NX_LIBS)"

.PHONY: all install clean distclean reinstall install

all: $(TARGETS)

# unpack for host
$(APP_HOSTBASE)/Makefile.am: 
	@echo "Unpacking sources for host build"
	@tar -xf $(APP_SRC)
	@mv $(APP_BASE) $(APP_HOSTBASE)

# configure and build host
$(APP_HOSTBASE)/src/lemon: $(APP_HOSTBASE)/Makefile.am
	@(cd $(APP_HOSTBASE); ./configure $(NX_CONFIG_OPTS_HOST))
	@make -C $(APP_HOSTBASE)

# unpack and patch
$(APP_BASE)/Makefile.am:
	@echo "Unpacking sources"
	@tar -xf $(APP_SRC)
	@(cd $(APP_BASE); patch -p1 < ../$(APP_BASE).nexus.patch-blocking)

# configure
$(APP_BASE)/Makefile: $(APP_BASE)/Makefile.am
	@echo "Configuring Lighthttpd"
	@(cd $(APP_BASE); ./configure $(NX_CONFIG_OPTS_TARGET))

# make 
# first round will fail at lemon. we copy over from ...-host and try again
$(APP_BASE)/src/lighttpd: $(APP_HOSTBASE)/src/lemon $(APP_BASE)/Makefile
	@echo "Building Lighthttpd"
	-@make -C $(APP_BASE) $(NX_MAKE_OPTS) 
	@cp -f $(APP_HOSTBASE)/src/lemon $(APP_BASE)/src
	@make -C $(APP_BASE) $(NX_MAKE_OPTS) 

install: $(TARGETS)
	cp -alf $(APP_BASE)/src/lighttpd $(NXBUILDDIR)/boot/bin
	@echo "Installed lighttpd"

reinstall:
	-@rm $(APP_BASE)/src/lighttpd 
	@make install

clean:
	-@make -C $(APP_HOSTBASE) clean
	-@make -C $(APP_BASE) clean

distclean: 
	rm -rf $(APP_HOSTBASE) $(APP_BASE)

