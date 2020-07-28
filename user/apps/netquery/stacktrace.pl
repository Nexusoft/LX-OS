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

my $input_file = shift@ARGV;
while(my $line = <>) {
  if($line =~ /(0x[a-fA-F0-9]+)/) {
    my $str = join(":", gdb_resolve($input_file, $1));
    $line =~ s/(0x[a-fA-F0-9]+)/$str/;
  }
  print $line;
}
