#!/usr/bin/perl -w

use strict;

my $latency = 1;

# argument is hopcount
die unless @ARGV >= 1;
my $hopcount = $ARGV[0];

my $diameter = $hopcount+1;

my $second = 3;

my @edges;

sub add_edge($$) {
  my ($a,$b) = @_;
  push @edges, [$a,$b];
}

if($hopcount > 1) {
  add_edge(1,$second);
  for (my $i=$second; $i < $diameter; $i ++) {
    add_edge($i, $i + 1);
  }
  add_edge($diameter, 2);
} else {
  add_edge(1,2);
}

my $edges = join ("\n", map { join(' -- ', @$_) . " $latency"; } @edges);

print << "EOF"
1 LEFT
2 RIGHT

$edges

21 NQSERVER
31 NQCLIENT

EOF
  ;
