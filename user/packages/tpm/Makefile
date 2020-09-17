# Make libtpm 3.2.0 for Nexus

# source information: version and filepath to archive
APP_BASE	:= tpm-3.2.0
APP_SRC		:= $(APP_BASE).tar.gz

ifeq ($(BUILD_VERBOSE),)
REDIR		:= >/dev/null
endif

# target information: 
TARGET	 	:= $(APP_BASE)/tpm_utils/tpm_demo

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
		   -I ../libtpm \
		   -I $(NXBUILDDIR)/user/include \
		   -I $(NXBUILDDIR)/common/include \
		   -I $(GCC_HOME)/include \
		   -I $(GCC_HOME)/include-fixed \
		   -nostdinc

NX_LIBS		:= -ltpm -Wl,--start-group,$(NXLIBDIR)/crti.o,$(NXLIBDIR)/crt1.o,$(NXLIBDIR)/crtn.o,$(NXLIBDIR)/liblwip.a,$(NXLIBDIR)/libc.a,$(NXLIBDIR)/libnexus.a,$(NXLIBDIR)/libnexus-sec.a,$(NXLIBDIR)/libnexus-sys.a,$(NXLIBDIR)/libcrypto.a,$(NXLIBDIR)/libssl.a,$(NXLIBDIR)/libz.a,$(GCC_HOME)/libgcc.a,--end-group

NX_LDFLAGS	:= -Bstatic -e compatmain -L$(NXLIBDIR) -L../libtpm -nostdlib

# configure options shared by host and target
NX_MAKE_OPTS 	:= CC=gcc LD=GCC CFLAGS="$(NX_CFLAGS)" LDFLAGS="$(NX_LDFLAGS)" LDLIBS="$(NX_LIBS)"

.PHONY: all install clean distclean

all: $(TARGET) 

# unpack 
$(APP_BASE):
	@echo "Unpacking sources"
	@tar -xf $(APP_SRC)
	@(cd $(APP_BASE); patch -p1 < ../$(APP_BASE).nexus.patch)

# make libtpm
$(APP_BASE)/libtpm/libtpm.a: $(APP_BASE)
	@echo "Building $(APP_BASE)"
	@make -C $(APP_BASE)/libtpm $(NX_MAKE_OPTS) 

$(APP_BASE)/tpm_utils/tpm_demo: $(APP_BASE)/libtpm/libtpm.a
	@make -C $(APP_BASE)/tpm_utils $(NX_MAKE_OPTS) $(NX_LIBS)

install: $(TARGET) 
	@(cd $(NXBUILDDIR)/user/lib; ln -sf ../packages/tpm/$(APP_BASE)/libtpm/libtpm.a .)
	@cp -alf $(APP_BASE)/libtpm/tpm*.h $(NXBUILDDIR)/user/include
	-@mkdir $(NXBUILDDIR)/boot/bin/tpm
	@cp -alf $(APP_BASE)/tpm_utils/* $(NXBUILDDIR)/boot/bin/tpm
	-@rm $(NXBUILDDIR)/boot/bin/tpm/*.c
	@echo "Installed $(APP_BASE)"

clean:
	@make -C $(APP_BASE)/libtpm $(NX_MAKE_OPTS) clean

distclean: 
	rm -rf $(APP_BASE)

