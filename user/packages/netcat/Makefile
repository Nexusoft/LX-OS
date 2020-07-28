# Make openssl for Nexus

# source information: version and filepath to archive
APP_BASE	:= netcat-openbsd_1.89.orig
APP_SRC		:= $(APP_BASE).tar.gz

ifeq ($(BUILD_VERBOSE),)
REDIR  := >/dev/null
endif

# target information: 
TARGETS		:= $(APP_BASE)/nc
NEXUS		:= ../../../..

.PHONY: all install clean distclean

all: $(TARGETS)

# setup the sources and import the prepared configuration file
$(APP_BASE):
	@echo "Unpacking sources"
	@tar -xvf $(APP_SRC)
	@mv netcat-openbsd-1.89.orig netcat-openbsd_1.89.orig
	@echo "Patching sources"
	@(cd $(APP_BASE); patch -p1 < ../$(APP_BASE).posix.patch $(REDIR))

# build the tool
$(TARGETS): $(APP_BASE)
	@echo "Calling make"
	make -C $(APP_BASE) 

install: $(TARGETS)
	cp -alf $(APP_BASE)/nc $(NEXUS)/build/boot/bin
	@echo "Installed netcat"

# relink and reinstall. for when the called libraries (libc, libnexus) change
reinstall:
	-@rm $(TARGETS)
	make -C . install

clean:

distclean: 
	-@rm -r $(APP_BASE)


