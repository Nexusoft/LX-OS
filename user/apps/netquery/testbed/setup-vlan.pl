#!/usr/bin/perl -w

use strict;
my $TOPO_FNAME = "test.topo";

# Node assignments
# 6 bit space
# 1-20 = Routers
# 21-40 = NQ servers
# 41-60 = NQ clients

## IP assignments
# 10.low.high.{1,2} - internal { 1 = low, 2 = high }
# 10.0.0.name - externally routable, w/o delay
# 10.0.1.name - externally routable, w/ delay
# 10.0.2.name - internally routed, w/ delay (TESTING ONLY)

# There are only 12 bits of vlan

## Vlan assignments
# 4095 = globally accessible, assigned to 10.0.0.xxx
## (low,high) = point to point, w/ delay
## name = local interface, assigned to 10.0.2.name
## (1,low,high) = emulated multihop delay # don't need this ; it can coexist with the other

use SetupCommon;

load_topo_file($TOPO_FNAME);

my @all_commands;

sub cmd(@) {
	push @all_commands, [@_];
}

sub clear_all_vlan() {
	open(VLAN, "/proc/net/dev") or die "could not start ifconfig";
	while(my $line = <VLAN>) {
		#print "$line\n";
		if($line =~ /^($ETH\.\d+):/) {
			cmd("vconfig rem $1");
		}
	}
}

my %added_vlans;
sub add_vlan($) {
	my ($vlan_num) = @_;
	if(!exists $added_vlans{$vlan_num}) {
		cmd("vconfig add $ETH $vlan_num");
		$added_vlans{$vlan_num} = 1;
	}
}

sub add_ip($$$) {
	my ($dev,$ip,$prefix_len) = @_;
	my $mask = prefix_to_mask($prefix_len);
	$mask = inet_ntoa($mask);
	cmd("ifconfig $dev $ip netmask $mask");
}

my $hostname = "testbed-$NODEID";
cmd("hostname $hostname");

cmd("echo 1 > /proc/sys/net/ipv4/conf/all/arp_filter");
clear_all_vlan();

add_vlan($GLOBAL_VLAN);
add_vlan($NODE_VLAN);

my $role = node_info($NODEID);
if($role eq 'LEFT') {
  add_vlan($LEFT_VLAN);
} elsif($role eq 'RIGHT') {
  add_vlan($RIGHT_VLAN);
}

# Configure VLAN for all links
for(my $s=$NODEID; $s <= $NODEID; $s++) {
	for(my $t=1; $t <= $MAX_NODEID; $t++) {
		add_vlan(link_to_vlan($s,$t));
	}
}

# Configure externally routable addresses. All others are configured via zebra.conf
for(my $s=$NODEID; $s <= $NODEID; $s++) {
	add_ip($GLOBAL_VNAME, "10.0.0.$s", 24);
	for(my $t=1; $t <= $MAX_NODEID; $t++) {
		my $point_to_point = link_to_vname($s,$t);
		my $src_ip = ext_routable($s);
		my $dst_ip = ext_routable($t);
		add_ip($point_to_point, $src_ip, 32);
		cmd("/sbin/route add -host $dst_ip dev $point_to_point");
	}
}

# Master NIC might lose connectivity
cmd("killall dhclient ");
cmd("sleep 1 ");
cmd("dhclient $ETH");

if(0) {
	print "## Would execute: \n" . join("\n", map { join(" ", @$_) } @all_commands);
} else {
	for my $cmd (@all_commands) {
		system(@$cmd);
	}
}

