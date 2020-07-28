#!/usr/bin/perl -w

use strict;

my $C = 186.282397; # in mi/ms
#sub to_dms($) {
#  my ($v) = @_;
#  # negative = east/south
#
#}

my ($wanted) = shift @ARGV;
open(WANTED, "<$wanted") or die "could not open wanted\n";
#open(LATLONG, "<$latlong") or die "could not open latlong\n";

my %city;
while(my $line = <>) {
  my ($loc, $lat, $long) = split(" ", $line);
  my $long_suffix = ($long < 0) ? "W" : "E";
  my $lat_suffix = ($lat < 0) ? "S" : "N";
  if(!exists($city{$loc})) {
    $city{$loc} = abs($lat) . "d$lat_suffix " . abs($long) . "d$long_suffix";
  }
}

sub fix_name($) {
  my ($v) = @_;
  $v =~ s/\+//g;
  return $v;
}
sub find_latlong($) {
  my ($loc) = @_;
  if(!exists($city{$loc})) {
    return undef;
  } else {
    return $city{$loc};
  }
}

my %errs;
while(my $line = <WANTED>) {
  chomp $line;
  my ($s,$d) = split("-", $line);
  next unless defined($s) && defined($d);
  #print "$s => $d\n";
  my $l0 = find_latlong(fix_name($s));
  my $l1 = find_latlong(fix_name($d));
  if(defined($l0) && defined($l1)) {
    my $tmpfile = "foo.tmp";
    open(TMP, ">$tmpfile") or die "no tmp file\n";
    print TMP "$l0 $l1\n";
    my $val = `geod +ellps=clrk66 -I +units=us-mi $tmpfile`;
    $val =~ /(\S+)$/;
    my $mi = $1;
    my $ms = $mi/$C;
    print "$s-$d $l0 $l1 $mi $ms\n";
  } else {
    if(!defined($l0)) {
      $errs{$s} = 1;
    }
    if(!defined($l1)) {
      $errs{$d} = 1;
    }
  }
}

if(%errs > 0) {
	print "Not found!\n";
	for my $e (keys %errs) {
	print "$e\n";
	}
}
