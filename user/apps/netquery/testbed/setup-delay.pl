#!/usr/bin/perl -w

use strict;

use SetupCommon;

my $TOPO_FNAME = "test.topo";
load_topo_file($TOPO_FNAME);

sub find_all_vlan() {
  my @vlans = ();
  open(VLAN, "/proc/net/dev") or die "could not start ifconfig";
  while (my $line = <VLAN>) {
    #print "$line\n";
    if ($line =~ /^($ETH\.(\d+)):/) {
      push @vlans, $1;
    }
  }
  close(VLAN);
  return @vlans;
}

my @all_nodes = nodes();

for my $node (@all_nodes) {
}
