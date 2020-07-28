#!/usr/bin/perl -w

use strict;

for(my $i=0; $i < 30; $i++) {
	my $dir = "router$i/";
	my $ofname = "$dir/router.vmx";

	system("mkdir -p $dir");
	open(VMX,">$ofname") or die "could not open vmx file\n";

	my $addr = 50 + $i;

	print VMX << "EOF"
#!/usr/bin/vmplayer
config.version = "8"
virtualHW.version = "4"
ide0:0.present = "TRUE"
ide0:0.filename = "/redhat/fc8/Fedora-8-x86_64-DVD.iso"
#ide0:0.present = "TRUE"
#ide0:0.filename = "dev.vmdk"

memsize = "512"
MemAllowAutoScaleDown = "FALSE"
ide1:0.present = "FALSE"
ide1:0.autodetect = "TRUE"
ide1:0.fileName = "/root/trickles.iso"
ide1:0.deviceType = "cdrom-image"
floppy0.present = "FALSE"
ethernet0.present = "TRUE"
#ethernet0.virtualDev = "e1000"
ethernet0.virtualDev = "vlance"

ethernet1.present = "FALSE"
#ethernet1.virtualDev = "e1000"
#ethernet1.virtualDev = "e1000"
ethernet1.virtualDev = "vlance"

usb.present = "FALSE"
sound.present = "FALSE"
displayName = "Testbed router $i"
guestOS = "other26xlinux"
nvram = "fc4.nvram"
MemTrimRate = "-1"
ide0:0.redo = ""
#ethernet0.addressType = "generated"
uuid.location = "56 4d f7 ef f7 7b d0 de-1f d4 38 4d 47 87 2c 58"
uuid.bios = "56 4d f7 ef f7 7b d0 de-1f d4 38 4d 47 87 2c 58"
uuid.action = "create"
#ethernet0.generatedAddress = "00:0c:29:d1:fd:ef"
#ethernet0.generatedAddressOffset = "0"
tools.syncTime = "TRUE"
ide1:0.startConnected = "FALSE"
checkpoint.vmState = ""

sound.virtualDev = "es1371"

tools.remindInstall = "TRUE"

ide0:1.redo = ""

priority.grabbed = "normal"
priority.ungrabbed = "normal"

Ethernet0.connectionType = "bridged"
Ethernet0.vnet = "/dev/vmnet0"

ethernet0.addressType = "generated"
ethernet0.generatedAddress = "00:0c:29:8b:5a:$addr"
ethernet0.generatedAddressOffset = "0"

scsi0.present = "TRUE"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "/root/router-0/tnode.vmdk"

scsi0:0.redo = ""

ide0:0.deviceType = "cdrom-image"

ide0:0.startConnected = "FALSE"

scsi0:0.mode = "independent-nonpersistent"
disk.locking = "FALSE"

EOF
;
	close(VMX);
	system("chmod a+x $ofname");
}
