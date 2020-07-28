#!/usr/bin/perl -w

use strict;

use SetupCommon;

die unless @ARGV == 2;

my $NODE_PREFIX = "router";
my ($TOPO_FNAME,$NODE_ID) = @ARGV;
my $NODENAME = "$NODE_PREFIX$NODE_ID";
my $CONFDIR = "./$NODENAME/";

my $ZEBCONF = "$CONFDIR/zebra.conf";
my $RIPCONF = "$CONFDIR/rip.conf";

#print "FNAME = $TOPO_FNAME\n";
load_topo_file($TOPO_FNAME);

system("mkdir -p $CONFDIR");

open(ZEBRA,">$ZEBCONF") or die "could not create zebra conf\n";
open(RIP,">$RIPCONF") or die "could not create rip conf\n";

my $interfaces = "";
my $networks = "";

my %did_vlan;

sub add_interface($$$$) {
	my ($vname, $ip, $other_ip, $prefix) = @_;
	#my $mask = prefix_to_mask($prefix);

	$interfaces .= <<"EOF"
interface $vname
ip address $ip/$prefix
no shutdown

EOF
;
	if(!exists($did_vlan{$vname})) {
		my $neighbor = "";
		if($other_ip ne 0) {
			$neighbor = "neighbor $other_ip";
		}
		$networks .= <<"EOF"
network $vname
$neighbor

EOF
;
		$did_vlan{$vname} = 1;
	}
}

$interfaces .= " !!! Neighbors\n\n";
$networks .= " !!! Networks\n\n";

for my $e (edges($NODE_ID)) {
	my ($t,$delay) = @$e;
	print "Neighbor $t $delay\n";
	my ($host,$other_host);
	if($NODE_ID < $t) {
		$host = 1;
		$other_host = 2;
	} elsif($NODE_ID > $t) {
		$host = 2;
		$other_host = 1;
	} else {
		die;
	}
	my ($low,$high) = sort_nodes($NODE_ID,$t);
	add_interface(link_to_vname($NODE_ID,$t), "10.$low.$high.$host", "10.$low.$high.$other_host", 30);
}

my $role = node_info($NODE_ID);

$interfaces .= " !!! Router local address\n\n";
add_interface(vname($NODEID), "10.0.2.$NODE_ID", 0, 32);

$interfaces .= " !!! Attached subnets\n\n";

if($role eq "LEFT") {
	# add interface for source
	add_interface(vname($LEFT_VLAN), '10.255.1.1', 0, 24);
} elsif($role eq "RIGHT") {
	# add interface for destination
	add_interface(vname($RIGHT_VLAN), '10.255.2.1', 0, 24);
} elsif($role eq "MIDDLE") {
	# do nothing
} elsif($role eq "NQSERVER") {
  print ZEBRA "! NQ SERVER\n";
  print RIP "! NQ SERVER\n";
  exit(0);
} elsif($role eq 'NQCLIENT') {
  print ZEBRA "! NQ CLIENT\n";
  print RIP "! NQ CLIENT\n";
  exit(0);
} else {
	die "Unknown role $role\n";
}
print ZEBRA << "EOF"
!!! Node $NODE_ID, role is $role

hostname $NODENAME
password zebra
enable password zebra

$interfaces

log file $CONFDIR/zebra.log

EOF
;

close(ZEBRA);

print RIP << "EOF"
hostname $NODENAME-rip
password zebra
!
!
router rip
$networks

log file $CONFDIR/ripd.log

! timers basic update timeout garbage

debug rip events
debug rip packet

EOF
;
close(RIP);

