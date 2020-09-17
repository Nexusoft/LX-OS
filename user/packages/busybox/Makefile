# Make busybox for Nexus

# source information: version and filepath to archive
APP_BASE:= busybox-1.15.2
APP_SRC	:= $(APP_BASE).tar.bz2

ifeq ($(BUILD_VERBOSE),)
REDIR	:= >/dev/null
endif

# target information: 
TARGETS	     := $(APP_BASE)/busybox
NEXUS        := ../../../..

.PHONY: all install clean distclean reinstall

all: $(TARGETS)

# setup the sources and import the prepared configuration file
$(APP_BASE):
	@echo "Unpacking sources"
	@tar -xvf $(APP_SRC)
	@rm -rf $(APP_BASE)/examples	# a directory here mucks up the main makefile
	@echo "Patching sources"
	@(cd $(APP_BASE); patch -p1 < ../$(APP_BASE).nexus.patch $(REDIR))
	@echo "Copying config"
	@cp $(APP_BASE).nexus.config $(APP_BASE)/.config
	@echo "Calling make oldconfig"
	make -C $(APP_BASE) oldconfig

# build the library
$(TARGETS): $(APP_BASE)
	@echo "Calling make"
	make -C $(APP_BASE) 

install: $(TARGETS)
	-@rm $(NEXUS)/build/boot/bin/busybox 2>/dev/null
	cp -al $(APP_BASE)/busybox $(NEXUS)/build/boot/bin
	@echo "Installed busybox"

# relink and reinstall. for when the called libraries (libc, libnexus) change
reinstall:
	-@rm busybox-1.15.2/busybox busybox-1.15.2/busybox_unstripped
	make -C . install

clean:
	make -C $(APP_BASE) clean

distclean: 
	-@rm -r $(APP_BASE)

