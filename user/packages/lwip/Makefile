# Make lwip for Nexus

# source information: version and filepath to archive
APP_BASE:= lwip-1.3.2.rc1
APP_SRC	:= $(APP_BASE).tgz

ifeq ($(BUILD_VERBOSE),)
REDIR	:= >/dev/null
endif

# target information: 
TARGETS	:= $(APP_BASE)/liblwip.a
NEXUS	:= ../../../..

CFLAGS	:= -fno-stack-protector

.PHONY: all install rebuild clean distclean

all: $(TARGETS)

# setup the sources and import the prepared configuration file
$(APP_BASE)/Makefile:
	@echo "Unpacking sources"
	@tar -xvf $(APP_SRC)
	@echo "Patching sources for Unix"
	@(cd $(APP_BASE); patch -p1 < ../$(APP_BASE).unix.patch $(REDIR))
	@echo "Patching sources for Nexus"
	@(cd $(APP_BASE); patch -p1 < ../$(APP_BASE).nexus.nofastdev.patch $(REDIR))

$(APP_BASE)/src/include/lwip/arch/cc.h: $(APP_BASE)/Makefile
	@echo "Preparing for IPv4"
	@(cd $(APP_BASE)/src/include/lwip; ln -s . lwip)
	@cp -al $(APP_BASE)/src/include/ipv4/lwip/*.h $(APP_BASE)/src/include/lwip
	@cp -r $(APP_BASE)/src/include/arch $(APP_BASE)/src/include/lwip
	@touch $@

# build the library
$(TARGETS): $(APP_BASE)/src/include/lwip/arch/cc.h
	@echo "Calling make"
	make -C $(APP_BASE) CFLAGS="$(CFLAGS)"

rebuild:
	-@rm $(TARGETS)
	make $(TARGETS)

install: $(TARGETS)
	@echo "Linking lwIP library into distribution"
	@(cd ../../lib; ln -sf ../packages/lwip/$(APP_BASE)/liblwip.a .)
	@(cd ../../include; ln -sf ../packages/lwip/$(APP_BASE)/src/include/lwip .)

# relink and reinstall. for when the called libraries (libc, libnexus) change
reinstall: clean $(TARGETS)
	make rebuild

clean:
	-@make -C $(APP_BASE) clean

distclean: 
	-@rm -r $(APP_BASE)

