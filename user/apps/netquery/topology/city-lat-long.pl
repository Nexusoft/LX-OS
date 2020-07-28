#!/usr/bin/perl -w

use strict;

open(IPLOC, "<dns_based_loc_mapping.txt") or die "could not open dns mapping\n";
open(LATLONG, "<ip_to_pop_mapping_with_latlons.txt") or die "could not open latlong src\n";

# Pick an IP per city
my %city;
my %map;
{
  my %need_city;
  while (my $line = <IPLOC>) {
    if ($line =~ /^(\S+) (\S+)$/) {
#      if (!exists($city{$2})) {
#	$city{$2} = 1;
	$map{$1} = [$2];
#      }
    }
  }
}

#print join("\n", sort { $a cmp $b } keys(%city));
#69.5.160.252 8302 1902737997 1953535826

my $limit = 0;
while(my $line = <LATLONG>) {
  if($line =~ /^(\S+) (\S+) (\S+) (\S+)/) {
    my $ip = $1;
    my $lat = $3;
    my $long = $4;
    next unless(abs($lat) <= 180 && abs($long) <= 180);
    if( exists($map{$ip}) && @{$map{$ip}} == 1 ) {
      my $loc = $map{$ip}->[0];
      next if exists($city{$loc});
      $city{$loc} = 1;
      push @{$map{$ip}}, ($lat, $long);
      #last if($limit++ > 10);
    }
  }
}

for my $v ( sort { $a->[0] cmp $b->[0] } values(%map) ) {
  my ($loc, $lat, $long) = @$v;
  if( defined($lat) && defined($long) ) {
    print "$loc $lat $long\n";
  }
}
