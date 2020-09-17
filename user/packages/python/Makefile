# Make Python for Nexus
#
# See README for explanation

# source information: version and filepath to archive
APP_BASE	:= Python-2.6.4
APP_HOSTBASE	:= $(APP_BASE)-host
APP_SRC		:= $(APP_BASE).tgz
APP_URL 	:= http://www.python.org/ftp/python/2.6.4/Python-2.6.4.tgz

ifeq ($(BUILD_VERBOSE),)
REDIR		:= >/dev/null
endif

# target information: 
TARGETS	 	:= install/bin/python
NEXUS   	:= ../../../../..
NXBUILDDIR	:= $(NEXUS)/build
NXLIBDIR	:= $(NXBUILDDIR)/user/lib

# fragile: --prefix requires an absolute address (why?)
INSTPREFIX	:= $(PWD)/install

GCC_MAJOR       := $(shell gcc -dumpversion | cut -d'.' -f1)
GCC_MINOR       := $(shell gcc -dumpversion | cut -d'.' -f2)
GCC_HOME	:= /usr/lib/gcc/$(shell gcc -dumpmachine)/$(shell gcc -dumpversion)

# configuration options
NX_CFLAGS	:= -fno-stack-protector \
		   -I $(NXBUILDDIR)/user/include \
		   -I $(NXBUILDDIR)/common/include \
		   -I $(GCC_HOME)/include \
		   -I $(GCC_HOME)/include-fixed \
		   -nostdinc
NX_LDFLAGS	:= -L $(NXLIBDIR) -L $(GCC_HOME) -nostdlib -Bstatic -e compatmain
NX_LIBS		:= -Wl,--start-group \
 		   $(NXLIBDIR)/libsqlite3.a \
 		   $(NXLIBDIR)/libz.a \
 		   $(NXLIBDIR)/libdb.a \
		   $(NXLIBDIR)/liblwip.a \
		   $(NXLIBDIR)/libcrypto.a \
		   $(NXLIBDIR)/libssl.a \
		   $(NXLIBDIR)/libnexus.a \
		   $(NXLIBDIR)/libnexus-sec.a \
		   $(NXLIBDIR)/libnexus-sys.a \
		   $(NXLIBDIR)/libc.a \
		   $(NXLIBDIR)/crti.o \
		   $(NXLIBDIR)/crt1.o \
		   $(NXLIBDIR)/crtn.o \
		   $(GCC_HOME)/libgcc.a \
		   -Wl,--end-group
NX_CONFIG_OPTS	:= --prefix=$(INSTPREFIX) \
		   --disable-shared \
		   --disable-ipv6 \
		   -with-libc=$(NXLIBDIR)/libc.a \
		   -with-libm=$(NXLIBDIR)/libm.a \
		   CXX=g++ CC=gcc CFLAGS="$(NX_CFLAGS)" 
NX_MAKE_OPTS 	:= CC=gcc CROSS_COMPILE=yes CFLAGS="$(NX_CFLAGS)" LDFLAGS="$(NX_LDFLAGS)" LIBS="$(NX_LIBS)"

.PHONY: all install clean distclean prepatch patched reinstall

all: $(TARGETS) 

prepatch:
	@echo "try 'make patched' instead"

# use to manually apply (and modify) the patch
patched: $(APP_BASE)/Modules/Setup
	@cp -r $(APP_BASE) $(APP_BASE)-orig
	@rm $(APP_BASE)/pyconfig.h
	@rm $(APP_BASE)-orig/pyconfig.h
	@(cd $(APP_BASE); patch -p1 < ../$(APP_BASE).nexus.patch)
	@echo "Created patch sources. "
	@echo "Use this version to generate a diff. It will NOT compile cleanly"
	@echo "Issue ``diff -Nur Python-2.6.4-orig Python-2.6.4 > $$PATCHFILE''"
# download the source if it's not in the tree
$(APP_SRC):
	@wget $(APP_URL)

$(APP_HOSTBASE): $(APP_SRC)
	@echo "Unpacking sources"
	@tar -xf $(APP_SRC)
	@mv -f $(APP_BASE) $(APP_HOSTBASE)

# build the host interpreter (see README)
hostpython: $(APP_HOSTBASE)
	@echo "Configuring Host Python"
	@(cd $(APP_HOSTBASE); ./configure)
	@echo "Building Host Python"
	@make -C $(APP_HOSTBASE) python Parser/pgen
	@echo "Copying items to host location"
	-@cp -f $(APP_HOSTBASE)/python hostpython
	-@cp -f $(APP_HOSTBASE)/Parser/pgen hostpgen

# configure for the installation interpreter
# cleanly untar each time so that we don't double patch when rebuilding
$(APP_BASE)/Modules/Setup: hostpython
	-@rm -rf $(APP_BASE) 2>/dev/null
	@tar -xzf $(APP_SRC)
	@echo "Configuring Nexus Python"
	-@(cd $(APP_BASE); ./configure $(NX_CONFIG_OPTS))

# instead of patching, we remove pyconfig and write a whole new file
# because on at least one machine Configure generated a different pyconfig.h
$(APP_BASE)/nexus.patched: $(APP_BASE)/Modules/Setup
	@echo "Patching sources"
	@rm $(APP_BASE)/pyconfig.h
	@(cd $(APP_BASE); patch -N -p1 < ../$(APP_BASE).nexus.patch)
	@cp -alf nexusmodule.c $(APP_BASE)/Modules

# build the installation interpreter
$(APP_BASE)/python: $(APP_BASE)/nexus.patched
	@echo "Building Nexus Python"
	-@(cd $(APP_BASE); make $(NX_MAKE_OPTS) python)
	@touch $(APP_BASE)/Makefile.pre
	@(cd $(APP_BASE); make $(NX_MAKE_OPTS) python)

# install to local sub
# NB: this will have an error, but not an important one
$(TARGETS): $(APP_BASE)/python nexusmodule.c
	@echo "Calling Install"
	-@make -C $(APP_BASE) $(NX_MAKE_OPTS) libinstall
	-@make -C $(APP_BASE) $(NX_MAKE_OPTS) inclinstall
	-@make -C $(APP_BASE) $(NX_MAKE_OPTS) libainstall
	-@make -C $(APP_BASE) $(NX_MAKE_OPTS) bininstall

# nb: the .pyc files are deleted because the HOSTPYTHON generated files
# cannot be used by the target interpreter
install: $(TARGETS)
	@echo "Installing"
	@cp -alf $(TARGETS) ../../../boot/bin
	@(cd ../../../boot/lib; cp -alf ../../user/packages/python/install/lib/* . )
	-@rm ../../../boot/lib/python2.6/*.pyc
	@echo "Installing FastCGI for Python"
	@cp -alf fcgi.py ../../../boot/lib/python2.6
	@cp -alf fingerprint.py ../../../boot/lib/python2.6
	-@(cd ../../../boot/lib; chmod -R a+rw python2.6)

reinstall:
	-@rm ../../../boot/bin/python $(APP_BASE)/python $(APP_BASE)/Modules/nexusmodule.o
	@(cd $(APP_BASE); make $(NX_MAKE_OPTS) python)
	@cp -alf $(APP_BASE)/python ../../../boot/bin
	@echo "Copied python interpreter"
	
clean:
	make -C $(APP_BASE) clean

distclean: 
	-@rm -rf $(APP_BASE) $(APP_HOSTBASE) install hostpgen hostpython

