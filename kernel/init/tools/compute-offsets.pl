#!/usr/bin/perl -w

use strict;

my %structs = (
	       InterruptState =>
	       [ qw( gs fs es ds ebx ecx edx esi edi ebp eax errorcode entry_vector eip cs eflags esp ss) ],
	       UThread => [ qw(ipd) ],
	       IPD => [ qw(type) ],
	      );

sub clean_field_name($) {
  # Get rid of .'s
  my ($n) = @_;
  $n =~ s/\./__/g;
  return $n;
}

print <<EOF
#include <nexus/asm-offsets-deps.h>
#include <stdio.h>

//static inline Map *nexusthread_current_map(void) { return 0; } // keep linker happy

int main(int argc, char **argv) {
EOF
  ;

for my $struct (keys %structs) {
  my @fields = @{$structs{$struct}};
  for my $field (@fields) {
    my $cleanname = clean_field_name($field);
# We used to use macros, but that was not as flexible as defining constants
#printf("#define ${struct}__$cleanname(X) %d(X)\\n", (int)&((struct $struct *)0)->$field);
    print <<"EOF"
printf("#define ${struct}__$cleanname %d\\n", (int)&((struct $struct *)0)->$field);
EOF
      ;
  }
  print <<"EOF"
printf("#define ${struct}__sizeof %d\\n", sizeof(struct $struct));
EOF
    ;
}

print <<EOF
   return 0;
}

EOF
  ;
