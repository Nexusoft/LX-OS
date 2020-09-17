Nexus boot process

## CDRom

By issuing a `make iso`, the build system creates a bootable cdrom image of
the Nexus. It is also the default config option.

## Virtual Disk

You can make either a QEMU or VMware-format virtual disk with Grub2 and Nexus
kernel image preloaded. Nexus source code is also there under /src.

Due to Grub2's current limitation that bars loopback device installation,
there is a small, persistent .vmdk bootable image with Grub 1.98 installed
and compressed as tools/vmware/disk.vmdk.tgz. Each Nexus recompilation 
decompresses the file, and copies the latest Nexus boot files onto the image.
We use qemu-img to convert the image to the desired virtual disk type.

Using `make menuconfig`, the "Boot Options"/"Boot Image" option toggles among
a Nexus livecd, a QEMU virtual disk and a VMware virtual disk. Below it is
an option to make a sparse initrd package,
"Boot Options"/"Build sparse initrd image (for virtual disk)",
enabling faster booting. LiveCD and virtual disk images are all under 
build/boot/stage1/.

If you wish to build files individually, `make qemuimg` and `make vmdkimg` 
are the respective commands.

## GPXE

A regular `make` generates network boot images using the tool GPXE
(formerly known as etherboot). Instead of booting from the ISO, you can
have your machine boot this 'mini OS', which initializes the network
card, performs a DHCP lookup and downloads the real Nexus kernel from
your machine.

# Serving Files
For network boot, you need to serve the vmnexuz and initrd.tar files
over tftp. HOWTO.tftpd explains how to do this.

# Troubleshooting Network Boot
Note that GPXE expects your vmnexuz and initrd.tar files to be hosted
in a known location. It tries to autoconfigure this location during
compilation, by reading your /etc/hostname, but that may be off. During
boot, verify that the IP address GPXE is trying to read from matches
the host serving the files.

If it is, check that your tftp server is configured correctly by trying to
download the files manually using a tftp client. 

# Q: What do I do when my server address changes?
Unfortunately, you'll have to rebuild GPXE with the new information in
build/tools/gpxe/nexus-gpxe.boot and will have to overwrite the existing
bootimage with the new one. This can be tedious, I know.

You may consider switching from TFTP to HTTP and using a persistent URL. 
I think GPXE can issue DNS lookups.

#Q: What do I do when my client NIC changes?
Nothing. While etherboot builds images for specific NICs, GPXE has many
drivers included.

