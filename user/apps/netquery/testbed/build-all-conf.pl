#!/usr/bin/perl -w

use strict;

use SetupCommon;

die unless @ARGV == 1;
my ($TOPO_FNAME) = @ARGV;

load_topo_file($TOPO_FNAME);

my @nodes = sort { $a <=> $b } nodes();
print "All Nodes: " . join(", ", @nodes) ."\n===================================\n";

for my $node ( @nodes ) {
	print "===== Building configuration for $node\n";
	my $shell_conf = "router$node/config";
	if(! -e "router$node" ) {
	  system("mkdir router$node");
	}
	if(! -e $shell_conf) {
		open(CONFIG,">$shell_conf") or die "could not open config file\n";
		print CONFIG <<"EOF"
export NODEID=$node
export ETH=eth6

NQ_NAME=router$node
NQ_FLAGS="-n 10.0.1.21:4001"
EOF
		;
		close(CONFIG);
	}
	system(". $shell_conf ; ./build-router-conf.pl $TOPO_FNAME $node");
}

