# Make sample multiboot kernel binary

MBKERN_BASE   := mbkern
MBKERN_SRC    := $(MBKERN_BASE).tar.gz

.PHONY: all clean 

all: $(MBKERN_BASE) 

$(MBKERN_BASE): 
	@tar -xvzf $(MBKERN_SRC)

video: 
	@make -C $(MBKERN_BASE) video

initrd:
	@make -C $(MBKERN_BASE) initrd

clean:
	-@rm -rf $(MBKERN_BASE)

