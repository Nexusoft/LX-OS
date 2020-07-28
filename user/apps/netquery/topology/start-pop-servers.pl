#!/usr/bin/perl -w

use strict;

#my $PROGDIR = "./";
my $PROGDIR = $ENV{RF};
my $RPC = '';

system("killall -9 netqueryd");
my %started;
while(my $line = <>) {
  my ($popname,$hostname,$portnum) = split(" ", $line);
  $portnum =~ s/\s//g;
  if(!exists($started{$portnum})) {
	  $started{$portnum} = 1;
	  print "Forking $portnum\n";
	  system("$PROGDIR/netqueryd $RPC -p $portnum" . " > logs/$portnum.log 2> logs/$portnum.err " . " &");
  }
}

system("$PROGDIR/netqueryd " . " > logs/local.log 2>&1 " . "&" );

