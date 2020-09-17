## Nexus bootloader

Nexus is a multiboot compliant OS. It requires a bootloader that not only is
capable of booting multiboot OSes, but also supports some of the probing
functionality in the multiboot specification (specifically, memory region
and VESA video discovery).

# local image

Boot Nexus with Grub 1.98 or higher. A local image can be added to your 
grub.cfg as follows (obviously, change parameters to match your system):

menuentry "Nexus" {
	set root=(hd0,1)
	insmod vbe
	insmod ext2
	echo "Loading Nexus.."
	multiboot /nexussrc/build/boot/stage1/nexus.multiboot
	echo "Loading Initial Ramdisk.."
	module /nexussrc/build/boot/stage1/initrd.tar initrd
}


# booting over PXE

To boot a pxeboot image, compile the network boot images and add the
following entry:

menuentry "Nexus GPXE" {
	set root=(hd0,1)
	insmod ext2
	echo "Loading Nexus GPXE.."
	linux16 /nexussrc/build/boot/nexus-gpxe.bzimage
}

# known issues

1. Multiboot (in general) with Grub2 is known to be broken on the older IBM
   ThinkCentre with an Intel Pentium 4 CPU and an Intel 865G chipset. Similar
   configurations may not work either. Most newer machines should be fine
   when multibooting Nexus.

2. Nexus PCI drivers do not work with the nVidia MCP55 chipset. Currently
   there is no known solution and it is advised to switch to a more
   mainstream board.

