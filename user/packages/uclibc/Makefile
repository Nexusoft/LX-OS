# Make uclibc for Nexus

# source information: version and filepath to archive
APP_BASE   := uClibc-0.9.30.1
APP_SRC    := $(APP_BASE).tar.bz2
APP_DST    := install

# target information: 
TARGETS	   := install/lib/libc.a 
NXBUILD	   := ../../../..

.PHONY: all install clean distclean

all: install

# setup the sources and import the prepared configuration file
$(APP_BASE):
	tar -xvjf $(APP_SRC)
	cp config.nexus $(APP_BASE)/.config
	@(cd $(APP_BASE); patch -p1 < ../$(APP_BASE).nexus.patch $(REDIR))
	@(cd $(APP_BASE); sed -i 's/getline/parseline/g' extra/scripts/unifdef.c) 
	@ln -sv $(NXBUILD)/../../../../user/include/nexus/linuxcalls.h $(APP_BASE)/libc/sysdeps/linux/i386 
	@ln -sv $(NXBUILD)/../../../../user/include/nexus/linuxcalls_io.h $(APP_BASE)/libc/sysdeps/linux/i386 

# build the library
$(TARGETS): $(APP_BASE)
	make -C $(APP_BASE) oldconfig
	make -C $(APP_BASE) 
	make -C $(APP_BASE) install

# install the uclibc headers and libs 
install: $(TARGETS)
	cp -alf $(APP_DST)/lib/* $(NXBUILD)/build/user/lib
	cp -alfr $(APP_DST)/include/* $(NXBUILD)/build/user/include

clean:
	-@rm -r $(APP_BASE) 

distclean: clean
	-@rm -r $(APP_DST)

