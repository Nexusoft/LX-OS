Nexus boot process

## CDRom

By issuing a `make iso`, the build system creates a bootable cdrom image of
the Nexus.

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

