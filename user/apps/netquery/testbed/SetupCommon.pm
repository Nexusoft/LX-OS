package SetupCommon;

use strict;
use Exporter;

our @ISA = qw(Exporter);
our @EXPORT = qw($NODEID $ETH $LEFT_VLAN $RIGHT_VLAN $GLOBAL_VLAN $NODE_VLAN $GLOBAL_VNAME $MAX_NODEID inet_ntoa check_limit link_to_vlan link_to_vname vname prefix_to_mask load_topo_file edges node_info sort_nodes nodes node_is_present ext_routable is_nqserverid is_nqclientid is_routerid);

our $NODEID = $ENV{NODEID};
our $ETH = $ENV{ETH};
our $NODE_VLAN = $NODEID;
our $MAX_NODEID = 35;

sub vname($) {
	my ($vlan) = @_;
	return "$ETH.$vlan";
}
sub sort_nodes {
	return sort { $a <=> $b } @_;
}

our $GLOBAL_VLAN = 4094;
our $GLOBAL_VNAME = vname($GLOBAL_VLAN);
our $LEFT_VLAN = 4092;
our $RIGHT_VLAN = 4093;

die unless($NODEID ne "" && $ETH ne "");

sub prefix_to_mask($) {
	my ($prefix_len) = @_;
	return (0xffffffff << (32 - $prefix_len)) & 0xffffffff;
}

sub inet_ntoa($) {
	my ($v) = @_;
	my $accum = "";
	for my $i (0..2) {
		$accum = "." . ($v & 0xff) . $accum;
		$v >>= 8;
	}
	$accum = ($v & 0xff) . $accum;
	return $accum;
}

sub check_limit($) {
	my ($n) = @_;
	return (1 <= $n && $n <= 62);
}

sub link_to_vlan($$) {
	my ($n0,$n1) = sort_nodes(@_);
	die unless check_limit($n0) && check_limit($n1);
	return ($n0 << 6) | ($n1);
}

sub link_to_vname($$) {
	my ($n0,$n1) = @_;
	return vname(link_to_vlan($n0,$n1));
}

my %node_types;
my @EDGE_LIST; # Edge schema is [source, dest, one-way delay]
my %nodes;

sub load_topo_file($) {
	my ($fname) = @_;
	open(TOPO, "<$fname") or die "Could not open topo file $fname\n";
	while(my $line = <TOPO>) {
		$line =~ s/#.+$//;
		if($line =~ /^\s*(\d+)\s*--\s*(\d+)\s+(\d+)/) {
			my ($s,$t,$delay) = ($1,$2,$3);
			next unless(defined($delay));
			($s,$t) = sort_nodes($s,$t);

			if( (grep { ($s == $_->[0] && $t == $_->[0]) } @EDGE_LIST ) > 0) {
				die "Edge added multiple times to edge list\n";
			}
			push @EDGE_LIST, [$s,$t,$delay];
			$nodes{$s} = 1;
			$nodes{$t} = 1;
		} elsif($line =~ /^\s*(\d+)\s+(\S+)/) {
			my ($node, $type) = ($1,$2);
			die if(exists $node_types{$node});
			#print "Saving node type $node, $type\n";
			$node_types{$node} = $type;
			$nodes{$node} = 1;
		}
	}
	close(TOPO);
}

# Return incident edges on node, in [dest, delay] format
sub edges($) {
	my ($m) = @_;
	my @edges = map { 
		my @rv;
		my ($s,$t,$delay) = @$_;
		if($m == $s) {
			@rv = ([$t,$delay]);
		} elsif($m == $t) {
			@rv = ([$s,$delay]);
		} else {
			@rv = ();
		}
		@rv;
	} @EDGE_LIST;
	return @edges;
}

sub node_info($) {
	my ($n) = @_;
	if(exists($node_types{$n})) {
		return $node_types{$n};
	} else {
		return "MIDDLE";
	}
}

sub nodes() {
	return keys %nodes;
}

sub node_is_present($) {
  my ($n) = @_;
  return exists$nodes{$n};
}

sub ext_routable($) {
  my ($nodeid) = @_;
  return "10.0.1.$nodeid";
}

sub is_nqserverid($) {
  my ($id) = @_;
  return 21 <= $id && $id <= 30;
}

sub is_nqclientid($) {
  my ($id) = @_;
  return 31 <= $id
}
sub is_routerid($) {
  my ($id) = @_;
  return $id <= 20;
}

1;

