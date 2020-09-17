# Make mplayer for Nexus

# source information: version and filepath to archive
APP_BASE:= MPlayer-1.0rc2
APP_SRC	:= $(APP_BASE).tar.bz2

ifeq ($(BUILD_VERBOSE),)
REDIR	:= >/dev/null
endif

# target information: 
TARGETS	     := $(APP_BASE)/mplayer $(APP_BASE)/mencoder
NEXUS        := ../../../..

.PHONY: all install clean distclean

all: $(TARGETS)

# setup the sources and import the prepared configuration file
$(APP_BASE):
	@echo "Unpacking sources"
	@tar -xvf $(APP_SRC)
	@echo "Patching sources"
	@(cd $(APP_BASE); patch -p1 < ../$(APP_BASE).nexus.patch $(REDIR))
	@(cd $(APP_BASE) && chmod +x configure.nexus && ./configure.nexus)

# build the library
$(TARGETS): $(APP_BASE)
	@make -C $(APP_BASE) 

install: $(TARGETS)
	@strip $(TARGETS) 
	@cp $(TARGETS) demo.mpg $(NEXUS)/build/boot/bin
	@cp $(TARGETS) demo.mpg.README $(NEXUS)/build/boot/bin

# redo link and install steps. Needed when called libraries change
reinstall:
	rm $(TARGETS)
	make -C . install

clean:
	make -C $(APP_BASE) clean

distclean: 
	-@rm -r $(APP_BASE)

