#!/usr/bin/perl -w

use strict;

use lib '/home/ashieh/perllib';

use Util qw(max);

use Statistics::OLS;

my $PATH_PAT = '\s*(.+?)\s*';

# xxx

# We assume that the cost of sending the accumulated path to the
# recursive query is the roughly the same as that of the "write path"
# operation.

sub regress(@) {
  my @data = @_;
  my @xydata;
  my $x = 2;
  for my $d (@data) {
    push @xydata, ($x, $d);
    $x++;
  }
  my $ls = Statistics::OLS->new;
  if(!$ls->setData( \@xydata )) {
    print "Error: " . $ls->error() . "\n";
    print "Data: " . join (" ", @xydata) . "\n";
    die;
  }
  if(!$ls->regress()) {
    print $ls->error();
    die;
  }

  my ($intercept, $slope) = $ls->coefficients();
  #print "Regressed to $intercept, $slope\n";
  return ($intercept, $slope);
}

sub extrapolate($$) {
  my ($params, $count) = @_;
  my ($intercept,$slope) = @$params;
  return int($intercept + $slope * $count);
}

my $SETUP_COST = 903 + 7214;
sub HOP_SIM_COST($) {
  my ($num_hops) = @_;
  die unless($num_hops >= 2);
  return 27679 + ($num_hops - 2) * 28530 + 42661;
}

sub WRITE_COST($) {
  my ($hop_count) = @_;
  my @costs = qw(
		 2521
		 3361
		 4201
		 5041
		 5881
		 6721
		 7561
		 8401
		 9241
		);
  return extrapolate([regress(@costs)], $hop_count);
}

sub TRIGGER_COST($) {
  my ($hop_count) = @_;
  my @costs = qw(
		 50633
		 78290
		 106039
		 133604
		 161353
		 188964
		 216575
		 244232
		 271521
		);
  return extrapolate([regress(@costs)], $hop_count);
}

sub COMMIT_COST($) {
  my ($hop_count) = @_;
  my @costs = qw(
		 436
		 644
		 852
		 1044
		 1268
		 1476
		 1684
		 1892
		 1996
		);
  return extrapolate([regress(@costs)], $hop_count);
}

sub sum(@) {
  my @data = @_;
  my $total = 0;
  while(@data) {
    my ($name,$cost) = splice(@data, 0, 2);
    $total += $cost;
  }
  return $total;
}

sub vec_sum($$) {
  my ($d0,$d1) = @_;
  my @output =();
  while(@$d0 && @$d1 ) {
    my ($n0,$c0) = splice(@$d0, 0, 2);
    my ($n1,$c1) = splice(@$d1, 0, 2);
    die unless ($n0 eq $n1);
    push @output, ($n0, $c0 + $c1);
  }
  die unless @$d0 == 0 && @$d1 == 0;
  return @output;
}

sub breakdown_as_str(@) {
  my @data = @_;
  my $str = "";
  while(@data) {
    my ($name, $cost) = splice(@data, 0, 2);
    $str .= "$name:\t$cost\n"
  }
  return $str;
}

# Test the regression parameters
if(0) {
  print "TESTING REGRESSION\n";
  for my $hop_count (2..10) {
    my @test = (
		SETUP_COST=>$SETUP_COST,
		HOP_SIM_COST=>HOP_SIM_COST($hop_count),
		WRITE_COST=>WRITE_COST($hop_count),
		TRIGGER_COST=>TRIGGER_COST($hop_count),
		COMMIT_COST=>COMMIT_COST($hop_count),
	       );
    print "Hop Count: $hop_count\n";
    print "Total: " . sum(@test) . "\n";
    print breakdown_as_str(@test) . "\n";
  }
}

my $total_bw = 0;
my %flow_info; # id => [recursive queries]

my $total = 0;
my @accum = ();
my $num_flows = 0;
while(my $line = <>) {
  if($line =~ /RecursiveQuery\(flow=Flow (\d+).+?path=\[$PATH_PAT\]/) {
    my ($flow_id, $path_str) = ($1, $2);
    my @path_elements = split('\s+', $path_str);
    if(!exists($flow_info{$flow_id})) {
      $flow_info{$flow_id} = [];
    }
    push @{$flow_info{$flow_id}}, [@path_elements];
  } elsif($line =~/CreateFlowReturn\(flow=Flow (\d+).+path=\[$PATH_PAT\]/) {
    my ($flow_id, $path_str) = ($1, $2);
    my @elements = split('\s+', $path_str);
    my $hop_count = @elements;

    my @cost_components =
      (
       SETUP_COST=>$SETUP_COST,
       HOP_SIM_COST=>HOP_SIM_COST($hop_count),
       WRITE_COST=>WRITE_COST($hop_count),
       TRIGGER_COST=>TRIGGER_COST($hop_count),
       COMMIT_COST=>COMMIT_COST($hop_count),
      );

    if(exists($flow_info{$flow_id})) {
      my $rec_cost = 0;
      for my $f (@{$flow_info{$flow_id}}) {
	my $len = @$f;
	$rec_cost += WRITE_COST($len);
      }
      push @cost_components, (RECURSIVE_COST=>$rec_cost);
    }
    my $cost = sum(@cost_components);
    print "Cost for $flow_id = $cost (hopcount = $hop_count)\n";
    print breakdown_as_str(@cost_components);
    print "-----------------\n";
    if(@accum == 0) {
      @accum = @cost_components;
    } else {
      @accum = vec_sum(\@accum, \@cost_components);
    }
    $num_flows++;
  }
}

print "Accumulated $num_flows flows:\n";
print "Total: " . sum(@accum) . "\n";
print "Breakdown:\n" . breakdown_as_str(@accum) . "\n";
