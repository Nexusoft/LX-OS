#!/usr/bin/perl -w

my %files;
open(FILES, "/home/ashieh/nexus-files/zebra-files.txt") or die "could not open filelist\n";

while(my $line = <FILES>) {
  chomp($line);
  $files{$line} = 0;
}

my %orig_files = %files;

open(DIFF, "/tmp/delta.txt") or die "could not open difflist\n";
my $state = 0;
my $curr_fname;
while(my $line = <DIFF>) {
  if($line =~/Index: (.+)/) {
    if($state == 0) {
      # nothing special
    } elsif($state == 1) {
      $state = 0;
      $curr_fname = "";
    }
    my $fname = $1;
    if($fname =~ /\.(c|cc|h)$/) {
      unless (exists($files{$fname})) {
	$files{$fname} = 0;
      }
      #print "Start scan for $fname\n";
      $curr_fname = $fname;
      $state = 1;
      die unless($files{$curr_fname} == 0);
    }
  } else {
    if ($state == 1) {
      next if($line =~ /^\*\*\*|===|---/);
      my @l = split('',$line);
      die unless exists($files{$curr_fname});
      if ($l[0] =~ /^-|\+|!$/) {
	#print $line;
	$files{$curr_fname}++;
      }
      elsif($l[0] ne ' ') {
	print "unknown char $l[0] ($line)\n";
      }
    }
  }
}

my $total = 0;
my $in_total = 0;
while(my ($k,$v) = each(%files)) {
  my $in;
  if(exists($orig_files{$k})) {
    $in = " # in";
    $in_total += $v;
  } else {
    $in = " # other";
  }
  print "$k: $v$in\n";
  $total += $v;
}

print "Total is $total\nInTotal is $in_total\n";
