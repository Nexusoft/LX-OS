# Make zlib for Nexus

include ../Makefile.shared

# source information: version and filepath to archive
APP_BASE:= zlib-1.2.3
APP_SRC	:= $(APP_BASE).tar.gz

ifeq ($(BUILD_VERBOSE),)
REDIR	:= >/dev/null
endif

# target information: 
TARGETS	     := $(APP_BASE)/libz.a

.PHONY: all install clean distclean

all: $(TARGETS)

# setup the sources and import the prepared configuration file
$(APP_BASE):
	@echo "Unpacking sources"
	@tar -xf $(APP_SRC)

# build the library
$(TARGETS): $(APP_BASE)
	@(cd $(APP_BASE); ./configure)
	@echo "Calling make"
	make -C $(APP_BASE) CFLAGS="$(NX_CFLAGS)" LDFLAGS="$(NX_LDFLAGS)" libz.a

install: $(TARGETS)
	@(cd $(APP_BASE)/$(NXLIBDIR); ln -sf ../packages/zlib/$(TARGETS) . )
	@(cd $(APP_BASE)/$(NXLIBDIR)/../include; ln -sf ../packages/zlib/$(APP_BASE)/zlib.h . )
	@(cd $(APP_BASE)/$(NXLIBDIR)/../include; ln -sf ../packages/zlib/$(APP_BASE)/zconf.h . )

clean:
	make -C $(APP_BASE) clean

distclean: 
	-@rm -r $(APP_BASE)

