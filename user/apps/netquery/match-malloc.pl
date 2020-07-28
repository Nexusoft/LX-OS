#!/usr/bin/perl -w

use strict;

sub gdb_resolve($$) {
  my ($fname,$addr) = @_;
  my $cmd = "/tmp/gdb.cmd";
  open(DISAS, ">$cmd");
  my $fname_clean = $fname;
  $fname_clean =~ s/\(.+\)$//;
  print DISAS "file $fname_clean\nb *$addr\n";
  close(DISAS);
  my $result = `gdb -batch -x $cmd`;
  if($result =~ /Breakpoint.+file (\S+), line (\d+)/) {
    return ($1,$2);
  }
  return ($fname,$addr);
}

my $DEFAULT_FNAME = shift(@ARGV);
#gdb_resolve('/local/ashieh/trunk/nexus/user/apps/netquery/obj-test','0x8099f8c');
#exit;

my $mode = 0;
my %malloc_entries;
my @trace;
my $num_mallocs = 0;
my ($size, $loc);
my $pending_line;
while(my $line = <STDIN>) {
  if($line =~ /^M sz=(\d+) loc=(\S+)/) {
    $num_mallocs++;
    ($size,$loc) = ($1, $2);
    $mode = 1;
    @trace = ();
  } elsif($line =~/^F loc=(\S+)/) {
    $pending_line = $line;
    last;
  } elsif($mode == 1) {
    if($line =~ /^\s*$/) {
      push @{$malloc_entries{$loc}}, [$size, $loc, [@trace]];
      $mode = 0;
    } else {
      push @trace, $line;
    }
  }
}

my $match_count = 0;
my $unmatch_count = 0;

sub process_free($) {
  my ($line) = @_;
  $line =~ /^F loc=(\S+)/;
  my $loc = $1;
  if(exists($malloc_entries{$loc})) {
    shift @{$malloc_entries{$loc}};
    $match_count++;
    if(@{$malloc_entries{$loc}} == 0) {
      delete $malloc_entries{$loc};
    }
  } else {
  unmatch:
    print "No matching malloc at $loc!\n";
    $unmatch_count++;
  }
}

if (defined($pending_line)) {
  process_free($pending_line);
}

while(my $line = <STDIN>) {
  if($line =~/^F loc=(\S+)/) {
    process_free($line);
  }
}

my $num_leaks = $num_mallocs - $match_count;
print "$num_mallocs total malloc(), $num_leaks leaks\n";
my $cnt = 0;
my %trace_loc;
my $leak_total = 0;
for my $v (values(%malloc_entries)) {
  for my $e (@$v) {
    my ($size,$loc,$trace) = @$e;
    print "Leaked $size (0x$loc):\n" .
      join("", @$trace) . "\n";
    $leak_total += $size;

    my ($fname,$addr);
    if($trace->[2] =~ /^(.+)\[(.+)\]$/) {
      ($fname,$addr) = ($1, $2);
    } elsif($trace->[2] =~ /^\t(\S+)$/) {
      ($fname,$addr) = ($DEFAULT_FNAME, $1);
    } else {
      die "invalid trace format\n";
    }

    my $key = "$fname-$addr";
    push @{$trace_loc{$key}}, [$fname, $addr, $size];

    $cnt++;
  }
}

print "$num_leaks == $cnt?\n";
if($num_leaks != $cnt) {
  print "ERROR!!!\n";
}

sub total_size(@) {
  my $size = 0;
  for my $a (@_) {
    $size += $a->[2];
  }
  return $size;
}

#print join("\n", keys(%trace_loc)) . "\n";
my @trace_histo = sort { -(total_size(@$a) <=> total_size(@$b)) } (values %trace_loc);

for my $e (@trace_histo) {
  my ($fname, $addr, undef) = @{$e->[0]};
  ($fname,$addr) = gdb_resolve($fname,$addr);
  my  $samp_cnt = scalar(@$e);
  print "$fname\[$addr\]: Tot($samp_cnt) = " . total_size(@$e) . "\n";
}

print "LEAK TOTAL: $leak_total\n";
