# Make openssl for Nexus

# source information: version and filepath to archive
APP_BASE:= openssl-0.9.8k
APP_SRC	:= $(APP_BASE).tar.gz

ifeq ($(BUILD_VERBOSE),)
REDIR	:= >/dev/null
endif

# target information: 
TARGETS	     := install/lib/libcrypto.a
NEXUS        := ../../../..

.PHONY: all install clean distclean

all: install

# setup the sources and import the prepared configuration file
$(APP_BASE):
	@echo "Unpacking sources"
	@tar -xvf $(APP_SRC)
	@echo "Patching sources"
	@(cd $(APP_BASE); patch -p1 < ../$(APP_BASE).nexus.patch $(REDIR))

# build the library
$(TARGETS): $(APP_BASE)
	make -C $(APP_BASE) 

install: $(TARGETS)
	make -C $(APP_BASE) install

clean:
	make -C $(APP_BASE) clean

distclean: 
	-@rm -r $(APP_BASE)

