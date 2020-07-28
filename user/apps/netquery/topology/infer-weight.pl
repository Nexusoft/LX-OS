#!/usr/bin/perl -w

use strict;

my $dotfile = "foo.dot";
my $weights = shift @ARGV;
my $file = shift @ARGV;

open(W,"<$weights") or die "could not open weights file\n";

open(F,"<$file") or die "could not open $file\n";
my $unknown_fixfile = "$file.unknown";

#string _prefix("(\d+)\s+@(\S+)(?:\s+(\+))?(?:\s+(bb))?\s+\((\d+)\)(?: &(\d+))?");
#string _internal("<(\d+)>");
#string _external("\{(-\d+)\}");

sub known_loc($) {
  my ($l) = @_;
  return ($l ne 'T') && ($l ne '?') && ($l ne 'EXTERNAL');
}

sub round($) {
  my ($number) = @_;
  return int($number + .5 * ($number <=> 0));
}

sub make_key {
  my @locs = sort { $a cmp $b } @_;
  return join("-", @locs);
}

# Built-in latency db entries
my %latency_db =
# Computed from
# http://gc.kls2.com/
  (
   'Anaheim,+CA-Chicago,+IL'=>	14,
   'Anaheim,+CA-Tacoma,+WA'=>	7.9,
   'Atlanta,+GA-Kansas+City,+MO'=>	5.7,
   'Cheyenne,+WY-New+York,+NY' =>	13,
   'Chicago,+IL-Relay,+MD'=>	5.1,
   'New+York,+NY-Stockton,+CA'=> 20.9,
  );

while(my $line = <W>) {
  my $LOC = '([^\s\d]+)(\d+)';
  if($line =~ /$LOC\s+$LOC\s+(\d+)/) {
    my $k = make_key($1,$3);
    if(exists $latency_db{$k}) {
      #print "Mismatch at $k unless $latency_db{$k} == $5\n";
      die unless $latency_db{$k} == $5;
    }
    $latency_db{$k} = $5;
  }
}

open(FIXES, "<loc-fixfile.txt") or die "FIX!\n";
while(my $line = <FIXES>) {
  my @input = split(" ", $line);
  my $loc = shift @input;
  my $distance = pop @input;
  my ($l,$r) = split("-", $loc);
  $latency_db{make_key($l,$r)} = round($distance);
}

sub add_self($) {
  my ($s) = @_;
  my $k = make_key($s,$s);
  unless(exists($latency_db{$k})) {
    $latency_db{$k} = 1;
  }
}

# Insert self-links
for my $k (keys %latency_db) {
  my @ls = split('-', $k);
  die unless (@ls == 2);
  my ($l0, $l1) = @ls;
  add_self($l0);
  add_self($l1);
}

if(0) {
  print "Latency db:\n";
  for my $k (keys %latency_db) {
    print "$k: $latency_db{$k}\n";
  }
}
print "latency done\n";

my %routers;

my $NUM = 0;

while(my $line = <F>) {
  if ($line =~ /(\d+)\s+@(\S+)(?:\s+(\+))?(?:\s+(bb))?\s+\((\d+)\)(?: &(\d+))?/) {
    my $router_id = $1;
    my $location = $2;
    my $int_count = $5;
    my $ext_count = $6;
    my @internal_links = ();
    my @external_links = ();
    # print "ID = $router_id, location = $location\n";
    while ($line =~ m/<(\d+)>/g) {
      push @internal_links, $1;
    }
    while ($line =~ m/\{(-\d+)\}/g) {
      push @external_links, $1;
    }
    die unless(@internal_links == $int_count);
    #die unless(@external_links == $ext_count);
    $routers{$router_id} = [$location, [@internal_links, @external_links], $NUM++, $router_id];
  }
}

my @known;
my @unknown;
my $progress = 0;
my %possible_errs;
my %possible_err_pairs;
for my $r (keys %routers) {
  $progress++;
  my ($location, $links, $num, $id) = @{$routers{$r}};
  my $comment = "";

  for my $l (@$links) {
    my $target_num = -1;
    my $edgelist;
    if($l >= 0) {
      die unless exists($routers{$l});
      my ($target_loc, $target_links, $t_num, $id) = @{$routers{$l}};
      $target_num = $t_num;
      if (known_loc($location) && known_loc($target_loc)) {
	my $k = make_key($location, $target_loc);
	unless(exists $latency_db{$k}) {
	  # $errs{"Prob: $k not in latency db ($r, $l)"} = 1;
	  $possible_errs{$location} = 1;
	  $possible_errs{$target_loc} = 1;
	  $possible_err_pairs{$k} = 1;

	    #print STDERR "Prob: $k not in latency db ($r, $l)\n";
	  # print STDERR "Progress: $progress / " . scalar(keys(%routers)) . "\n";
	  next;
	  die ;
	}
	$comment = " $latency_db{$k}";
	$edgelist = \@known;
      } else {
	$edgelist = \@unknown;
      }
    } else {
      unless(exists($routers{$l})) {
	$routers{$l} = ["EXTERNAL", [], $NUM++, $l];
      }
      $target_num = $routers{$l}->[2];
      push @{$routers{$l}->[1]}, $r;
      # print STDERR "Target num = $target_num\n";
      $edgelist = \@unknown;
    }
    #print STDERR "n$num -- n$target_num $comment\n";
    push @$edgelist, "n$num -- n$target_num; /* $comment */";
  }
}

if(keys(%possible_errs) > 0) {
  for my $k (sort { $a cmp $b } keys %possible_errs) {
    if(!exists($latency_db{make_key($k,$k)})) {
      print STDERR "$k not in db\n";
    }
  }
  print STDERR "Pairs:\n";
  print STDERR join("\n", sort {$a cmp $b} keys(%possible_err_pairs) );
  die;
}

open(DOT, ">$dotfile\n");

sub print_edges {
  my @edges = @_;
  for my $e (@edges) {
    print DOT "$e\n";
  }
}

sub uniq(@) {
  my @elems = @_;
  my $last = shift @elems;;
  my @result = ();
  my $run = 1;
  for my $e (@elems) {
    #print "<$e>";
    if(defined($last) && $last eq $e) {
      $run++;
      next;
    }
    push @result, [$last, $run];
    $last = $e;
    $run = 1;
  }
  push @result, [$last, $run];
  return @result;
}

sub compress_to_counts($) {
  my ($h) = @_;
  return uniq(sort { $a cmp $b } (map { $routers{$_}->[0] } keys(%$h)));
}

print DOT "strict graph foo {\n";
print DOT "node [color=black];\n";
print DOT "edge [color=black];\n";

my %surfaces;
for my $v (sort { $a->[2] <=> $b->[2] } values %routers) {
  my ($loc, $edges, $num, $id) = @$v;
  if(known_loc($loc)) {
    print DOT "n$num; // $loc\n";
  } else {
    my $deg = @$edges;
    print "Unknown location $id at $loc, out degree $deg\n";
    if(0) {
      print "Peers: ";
      for my $e (@$edges) {
	print "[$e: $routers{$e}->[0]] ";
      }
    }
    print "	Surface : ";

    sub set_hash($@) {
      my ($h, @edges) = @_;
      #print STDERR "[" . join(",", @edges) . "]";
      for my $e (@edges) {
	$h->{$e} = 1;
      }
    }
    my %frontier;
    #set_hash(\%frontier, @$edges);
    set_hash(\%frontier, $id);

    my %visited = ();
my $MEMOIZE = 1;
    if($MEMOIZE && exists($surfaces{$id})) {
      # memoization
      # Sanity check
      for my $f (keys %frontier) {
	#print STDERR "<$f>";
	if(!known_loc($routers{$f}->[0])) {
	  die unless exists($surfaces{$f});
	}
      }
      my $h = $surfaces{$id};
      %visited = %{$h};
    } else {
      while (keys %frontier) {
	my @k = keys(%frontier);
	my $n = shift @k;
	delete $frontier{$n};
	if (!exists($visited{$n})) {
	  if (!known_loc($routers{$n}->[0])) {
	    $visited{$n} = 1;
	    #print STDERR "F: <$n $routers{$n}->[0]>";
	    set_hash(\%frontier, @{$routers{$n}->[1]});
	  } else {
	    $visited{$n} = 0;
	  }
	}
      }
      if($MEMOIZE) {
	my $new_surface = { %visited };
	for my $v1 (sort {$a <=> $b} keys(%visited)) {
	  next if($visited{$v1} == 0);
	  #print STDERR "===> ADD $v1 $routers{$v1}->[0] <===\n";
	  if (exists($surfaces{$v1})) {
	    print STDERR "ERR AT $v1 , from $id\n";
	    print STDERR "S0: " . scalar(keys %visited) . "\n S1: " . join(",", scalar(keys %{$surfaces{$v1}})) . "\n";
	    die;
	  }
	  $surfaces{$v1} = $new_surface;
	}
      }
    }
    my @uniq = compress_to_counts(\%visited);
    print "[" . scalar(keys(%visited)) . "," . scalar(@uniq) . "] ";
    print join(" ; ", map { "$_->[0]" . ( ($_->[1] > 1) ? "($_->[1])" : "" ) } @uniq ) . "\n";
  }
}

# , $METADATA, [1, undef]
my %rename;
my $next_id = 0;
my %surface_id;
for my $n (sort { $a <=> $b } keys(%surfaces)) {
  #print "surface($n)\n";
  unless(exists($surface_id{$surfaces{$n}})) {
    $surface_id{$surfaces{$n}} = $next_id++;
  }
  my $component = $surface_id{$surfaces{$n}};
  my @loc_count = compress_to_counts($surfaces{$n});
  my @sorted_filtered = sort { -($a->[1] <=> $b->[1]) }
    ( map { known_loc($_->[0]) ? ($_) : () } @loc_count );
  die if(@sorted_filtered == 0);
  my $loc = $sorted_filtered[0]->[0];
  $rename{$n} = "$loc $component"; # * = inferred location
}

open(FIXUPS, ">$unknown_fixfile");
for my $r (sort { $a <=> $b } keys %rename) {
  print FIXUPS "$r $rename{$r} $routers{$r}->[0]\n";
}

print "Fixups at $unknown_fixfile\n";

print_edges(@known);
print DOT "edge [color=red];\n";
print DOT "node [color=red];\n";
print_edges(@unknown);
print DOT "}\n";
# Append latencies at end
# Append unknown node types
