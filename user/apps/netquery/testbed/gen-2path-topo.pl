#!/usr/bin/perl -w

use strict;

my $latency = 1;

die unless @ARGV >= 1;
my $diameter = $ARGV[0];

my $second = 3;
my $penultimate = $second + 2 * ($diameter - 2 - 1);
die unless($second <= $penultimate);

my @edges;

sub add_edge($$) {
  my ($a,$b) = @_;
  push @edges, [$a,$b];
}

add_edge(1,$second);
add_edge(1,$second+1);

for(my $i=0; $i < $diameter - 3; $i ++) {
  add_edge($second + (2 * $i), $second + 2 * ($i + 1));
  add_edge($second + (2 * $i) + 1, $second + 2 * ($i + 1) + 1);
}

add_edge($penultimate, 2);
add_edge($penultimate+1, 2);

my $edges = join ("\n", map { join(' -- ', @$_) . " $latency"; } @edges);

print << "EOF"
1 LEFT
2 RIGHT

$edges

21 NQSERVER
31 NQCLIENT

EOF
  ;
