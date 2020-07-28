#!/usr/bin/perl -w

use strict;

my %structs = (
	       vcpu_guest_context=>
	       [ qw( fpu_ctxt.x user_regs ) ],
	       cpu_user_regs =>
	       [ qw(
		   ebx
		   ecx
		   edx
		   esi
		   edi
		   ebp
		   eax
		   error_code
		   entry_vector
		   eip
		   cs
		   saved_upcall_mask
		   eflags
		   esp
		   ss
		   es
		   ds
		   fs
		   gs) ]);

sub clean_field_name($) {
  # Get rid of .'s
  my ($n) = @_;
  $n =~ s/\./__/g;
  return $n;
}

print <<EOF
#include <stdio.h>
#include "offsets-deps.h"

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
