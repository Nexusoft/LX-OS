# Makefile for toplevel elsa distribution

# don't rebuild nexus-idlgen if we can help it, it is very slow
ifeq ($(wildcard nexus-idl/nexus-idlgen),)
all: again
else
all:
		@echo "warning: not rebuilding nexus-idlgen, it takes too long..."
		@echo "         but try saying please if you really really want to"
endif

# if no config, just spit out an error
ifneq ($(words $(wildcard */Makefile)),4)

please again check doc:
	@echo "error: You must run ./configure first"
	@exit 1

clean distclean:

else

# just do the obvious recursive thing

please again: 
	$(MAKE) -C smbase
	$(MAKE) -C ast
	$(MAKE) -C elkhound
	$(MAKE) -C nexus-idl


check:
	$(MAKE) -C smbase check
	$(MAKE) -C ast check
	$(MAKE) -C elkhound check
	$(MAKE) -C nexus-idl check

clean:
	@if [ -f smbase/Makefile ]; then $(MAKE) -C smbase clean; fi
	@if [ -f ast/Makefile ]; then $(MAKE) -C ast clean; fi
	@if [ -f elkhound/Makefile ]; then $(MAKE) -C elkhound clean; fi
	@if [ -f nexus-idl/Makefile ]; then $(MAKE) -C nexus-idl clean; fi

distclean:
	@if [ -f smbase/Makefile ]; then $(MAKE) -C smbase distclean; fi
	@if [ -f ast/Makefile ]; then $(MAKE) -C ast distclean; fi
	@if [ -f elkhound/Makefile ]; then $(MAKE) -C elkhound distclean; fi
	@if [ -f nexus-idl/Makefile ]; then $(MAKE) -C nexus-idl distclean; fi

doc:
	$(MAKE) -C smbase doc
	$(MAKE) -C ast doc
	$(MAKE) -C elkhound doc
	$(MAKE) -C nexus-idl doc

endif
