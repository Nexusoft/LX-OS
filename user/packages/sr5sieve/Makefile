# Make sr2sieve for Nexus

include ../Makefile.shared

# source information: version and filepath to archive
APP_BASE:= sr5sieve-1.8.10-src
APP_SRC	:= $(APP_BASE).zip

TARGETS	:= $(APP_BASE)/sr2sieve sr2data.txt

.PHONY: all install reinstall clean distclean

all: $(TARGETS)

# setup the sources and import the prepared configuration file
$(APP_BASE):
	@echo "Unpacking sources"
	@(mkdir $(APP_BASE) && cd $(APP_BASE) && unzip -q ../$(APP_SRC))
	@echo "Applying patch"
	@(cd $(APP_BASE) && patch -p1 < ../$(APP_BASE).nexus.patch)

$(APP_BASE)/sr5sieve: $(APP_BASE)
	@echo "Calling make"
	@make -C $(APP_BASE) CFLAGS="$(NX_CFLAGS)" LDFLAGS="$(NX_LDFLAGS)" sr5sieve LDLIBS="$(NX_LIBS)" $(REDIR)

$(TARGETS): $(APP_BASE)/sr5sieve
	@cp $< $@

reinstall:
	make distclean	$(REDIR)
	make install	$(REDIR)

install: $(TARGETS)
	@echo "Copying application"
	@cp $(TARGETS) $(APP_BASE)/$(NXBUILDDIR)/boot/bin

clean:
	make -C $(APP_BASE) clean

distclean: 
	-@rm -r $(APP_BASE)

