# Make trusted boot binaries

TBOOT_BASE   := tboot-20100427
TBOOT_SRC    := $(TBOOT_BASE).tar.gz

# Nexus files
NXBOOT       := ../../boot/stage1
NXIMAGE      := $(NXBOOT)/nexus.multiboot
NXINITRD     := $(NXBOOT)/initrd.tar

.PHONY: all clean install lcpv1 lcpv2 

all: $(TBOOT_BASE) tboot

$(TBOOT_BASE):
	@tar -xvzf $(TBOOT_SRC)
	@(cd $(TBOOT_BASE); patch -p1 < ../$(TBOOT_BASE).nexus.patch)

tboot:
	@make -C $(TBOOT_BASE)

clean:
	-@rm -rf $(TBOOT_BASE) tboot.gz

# Don't push to /boot just put under currency directory
install:
	@cp $(TBOOT_BASE)/tboot/tboot.gz .

lcpv1:
	@$(TBOOT_BASE)/lcptools/lcp_mlehash -c "tboot logging=vga" $(NXBOOT)/tboot.gz > mle_hash
	@$(TBOOT_BASE)/lcptools/lcp_crtpol -t hashonly -m mle_hash -o $(NXBOOT)/lcp.pol
	-@rm -rf mle_hash
	@$(TBOOT_BASE)/tb_polgen/tb_polgen --create --type nonfatal $(NXBOOT)/vl.pol
	@$(TBOOT_BASE)/tb_polgen/tb_polgen --add --num 0 --pcr 19 --hash image --cmdline "" --image $(NXBOOT)/nexus.multiboot $(NXBOOT)/vl.pol
	@$(TBOOT_BASE)/tb_polgen/tb_polgen --add --num 1 --pcr 19 --hash image --cmdline "initrd" --image $(NXBOOT)/initrd.tar $(NXBOOT)/vl.pol

lcpv2:
	@echo "Launch Control Policy v2 is currently unsupported"


