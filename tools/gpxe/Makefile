# Make GPXE with our initscript embedded into the image

# source information: version and filepath to archive
GPXE_BASE   := gpxe-0.9.7
GPXE_SRC    := $(GPXE_BASE).tar.gz

# target information: name and script
GPXE_TARGET := nexus-gpxe
GPXE_BOOT   := $(GPXE_TARGET).boot
TARGETS	    := $(GPXE_TARGET).bzimage $(GPXE_TARGET).iso $(GPXE_TARGET).usb

ifndef GPXE_SERVER
GPXE_SERVER := $(shell hostname -i)
endif
ifndef GPXE_NIC
GPXE_NIC    := net0
endif

.PHONY: all clean distclean

all: $(TARGETS)

$(GPXE_BASE):
	tar -xvzf $(GPXE_SRC)

# adapt the default script to the current environment:
# the server address is changed to that of the development host
$(GPXE_TARGET).boot: $(GPXE_TARGET).boot.default
	@echo "Configuring Nexus to contact TFTP server $(GPXE_SERVER) over NIC $(GPXE_NIC)"
	@sed 's/athens\.systems\.cs\.cornell\.edu/$(GPXE_SERVER)/g' < $+ > $@.tmp
	@sed 's/net0/$(GPXE_NIC)/' < $@.tmp > $@
	@rm $@.tmp

$(GPXE_TARGET).bzimage $(GPXE_TARGET).iso $(GPXE_TARGET).usb : $(GPXE_TARGET).boot $(GPXE_BASE)
	make -C $(GPXE_BASE)/src bin/gpxe.lkrn bin/gpxe.iso bin/gpxe.usb EMBEDDED_IMAGE=../../$(GPXE_BOOT)
	cp $(GPXE_BASE)/src/bin/gpxe.lkrn $(GPXE_TARGET).bzimage
	cp $(GPXE_BASE)/src/bin/gpxe.iso  $(GPXE_TARGET).iso
	cp $(GPXE_BASE)/src/bin/gpxe.usb  $(GPXE_TARGET).usb

clean:
	-@rm -r $(GPXE_BASE) *.boot

distclean: clean
	-@rm *.bzimage *.iso *.usb 2>/dev/null

install: $(TARGETS)

