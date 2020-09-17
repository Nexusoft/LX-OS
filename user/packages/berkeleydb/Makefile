# Make $PACKAGE for Nexus
#
# to adapt to a particular software package, 
# replace all occurrences of __PLACEHOLDER__
# (and you'll probably need some additional changes

# source information: version and filepath to archive
APP_NAME	:= db
APP_VERSION	:= 4.7.25
APP_BASE	:= $(APP_NAME)-$(APP_VERSION)
APP_SRC		:= $(APP_BASE).tar.gz

ifeq ($(BUILD_VERBOSE),)
REDIR		:= >/dev/null
endif

# target of make -C $APP_BASE
# select whatever binary or library you require
TARGET 	:= $(APP_BASE)/build_unix/libdb-4.7.a

# library and header includes 
# RELATIVE to $NXSRC/build/user/packages/$PACKAGEDIR.
# This build will FAIL from other locations
NXBUILDDIR	:= $(PWD)/../../..
NXLIBDIR	:= $(NXBUILDDIR)/user/lib

GCC_MAJOR       := $(shell gcc -dumpversion | cut -d'.' -f1)
GCC_MINOR       := $(shell gcc -dumpversion | cut -d'.' -f2)
GCC_HOME	:= /usr/lib/gcc/$(shell gcc -dumpmachine)/$(shell gcc -dumpversion)

# configuration options
NX_CFLAGS	:= -c \
		   -O3 \
		   -fno-stack-protector \
		   -I . \
		   -I .. \
		   -I $(NXBUILDDIR)/user/include \
		   -I $(NXBUILDDIR)/common/include \
		   -I $(GCC_HOME)/include \
		   -I $(GCC_HOME)/include-fixed \
		   -nostdinc \
		   -W -Wall -Wno-unused-parameter -Wsign-compare

NX_LDFLAGS	:= -Bstatic -e compatmain -nostdlib

NX_LIBS		:= -Wl,--start-group,$(NXLIBDIR)/liblwip.a,$(NXLIBDIR)/libc.a,$(NXLIBDIR)/libnexus.a,$(NXLIBDIR)/libnexus-sec.a,$(NXLIBDIR)/libnexus-sys.a,$(NXLIBDIR)/libcrypto.a,$(NXLIBDIR)/libssl.a,$(NXLIBDIR)/libz.a,$(GCC_HOME)/libgcc.a,$(NXLIBDIR)/crti.o,$(NXLIBDIR)/crt1.o,$(NXLIBDIR)/crtn.o,--end-group

NX_MAKE_OPTS 	:= CC=gcc LD=gcc CFLAGS="$(NX_CFLAGS)" LDFLAGS="$(NX_LDFLAGS)" LIBS="$(NX_LIBS)"

# change to match your configure
CONFIG_OPTS	:= --disable-shared \
		   --enable-static \
		   --disable-largefile \
		   --disable-replication \
		   --with-gnu-ld \
		   --with-openssl=$(NXBUILDDIR)/user CC=gcc 

#		   --disable-cryptography \
		   --disable-mutexsupport \
		   --disable-queue \
		   --disable-statistics \
		   --disable-hash \
		   --disable-verify

.PHONY: all reinstall install clean distclean

all: $(TARGET)

# unpack and patch
$(APP_BASE)/README:
	@echo "Unpacking"
	@tar -xf $(APP_SRC)
	@echo "Patching"
#@(cd $(APP_BASE); patch -p1 < ../$(APP_BASE).nexus.patch)

# configure
$(APP_BASE)/build_unix/config.status: $(APP_BASE)/README
	@echo "Configuring"
	@(cd $(APP_BASE)/build_unix; ../dist/configure $(CONFIG_OPTS) )
	@sed -i 's/define.HAVE_BACKTRACE.1/undef HAVE_BACKTRACE/g' $(APP_BASE)/build_unix/db_config.h
# make	
$(TARGET): $(APP_BASE)/build_unix/config.status
	@echo "Building"
	@(cd $(APP_BASE)/build_unix; make $(NX_MAKE_OPTS) libdb.a)

install: $(TARGET)
	@echo "Installing"
	@cp -alf $(TARGET) $(NXLIBDIR)/libdb.a
	@cp -alf $(APP_BASE)/build_unix/*.h $(NXBUILDDIR)/user/include

reinstall: $(TARGET)
	-@rm $(TARGET)
	make $(TARGET)
	make install

clean:
	@make -C $(APP_BASE)/build_unix $(NX_MAKE_OPTS) clean

distclean: 
	@rm -rf $(APP_BASE)

