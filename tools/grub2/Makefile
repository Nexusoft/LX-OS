# Make grub2 binaries

GRUB_BASE   	:= grub-1.98
GRUB_SRC    	:= $(GRUB_BASE).tar.gz

REDIR		:= >/dev/null 2>&1

.PHONY: all clean distclean install 

all: $(GRUB_BASE) grub

$(GRUB_BASE):
	@tar -xvzf $(GRUB_SRC)

grub:
	@(cd $(GRUB_BASE); ./configure --prefix=$(CURDIR))
	@(cd $(GRUB_BASE); make $(REDIR))

clean:
	-@rm -rf $(GRUB_BASE) etc >/dev/null $(REDIR)

distclean:
	-@rm -rf $(GRUB_BASE) bin etc lib sbin share $(REDIR)

install:
	-@make -C $(GRUB_BASE) install $(REDIR) 

