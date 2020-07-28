#
# Makefile for nexus tools.
#

.PHONY: all clean mrproper distclean dep depends install
.PHONY: idlgen gpxe

all: idlgen gpxe

idlgen:
	$(MAKE) -C idlgen

gpxe:
	$(MAKE) -C gpxe

dep depends:
	@# nothing here

clean mrproper:
	@-$(MAKE) -C idlgen clean
	@-$(MAKE) -C gpxe clean

distclean:
	@-$(MAKE) -C nexus-idlgen distclean
	@-$(MAKE) -C gpxe distclean

install:
	@# nothing here

