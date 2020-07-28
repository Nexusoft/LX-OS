#!/usr/bin/perl -w

use strict;

my $FLOW_PAT = 'flow=Flow (\d+)';

# Extract the completion time of a set of flows

my $fname = shift @ARGV;
open(IN, "<$fname") or die "could not open $fname\n";

#0: CheckIPSuccess(=>64992)Reliable(size=16)CreateFlowReturn() Flow 470 created (latest converged latency=3)[ 64992
#issued at 0 RPCIssue 177=>177 Send(=> 177@177)

my %stats;
while (my $line = <IN>) {
  next unless $line =~ /^(\d+(\.\d+)?):/;
  my $curr_time = $1;
  while ($line =~ /CreateFlow\($FLOW_PAT/g) {
    my ($id, $issue_time) = ($1,$curr_time);
    $stats{$id} = [ $issue_time ];
    #print "\t$id at $issue_time\n";
  }
  while($line =~ /CreateFlowReturn\($FLOW_PAT.+?path=\[\s*(.+?)\s*\].+?\)/g ) {
    my ($id, $path_str) = ($1, $2);
    die unless exists($stats{$id});
    my @path = split('\s+', $path_str);
    $stats{$id}->[3] = [@path];
  }
  while($line =~ /Flow (\d+) created \(latest converged latency=(.+?)\)/g) {
    my ($id,$latency) = ($1,$2);
    my $completion_time = $curr_time;
    #print "Path = " . join (",", @path) . "\n";

    $stats{$id}->[1] = $completion_time;
    $stats{$id}->[2] = $latency;

    #print "$line =>\t $id " . join(" ", @{$stats{$id}}) . "\n";
  }
}

sub all_defined(@) {
  my @dat = @_;
  for my $d (@dat) {
    if(!defined($d)) {
      return 0;
    }
  }
  return 1;
}

my @res;
while (my ($k,$v) = each(%stats)) {
  my $c = [($k, @$v)];
  if(@$c == 5 && all_defined(@$c)) {
    push @res, $c;
  } else {
    print "# flow $k missing data points! " . join (" ", @$c) . "\n";
  }
}

#@res = sort { $a->[3] <=>  $b->[3] } @res;


sub int_filter($) {
  my ($s) = @_;
  return sprintf("%5d", $s);
}
for my $r (@res) {
  my @v = @$r;
  #print "Y: ". join(",", @v) . "\n";
  my ($path) =  splice(@v,-1);
  my ($id) = splice(@v, 0, 1);
  my $path_len = scalar @$path;
  print join(" ", int_filter($id), (map { sprintf("%8.3f", $_) } @v), int_filter($path_len) ) . " # " . join(",", map { sprintf("%6d", $_) } @$path) . "\n";
}
