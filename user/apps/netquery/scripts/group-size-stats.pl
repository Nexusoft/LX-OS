#!/usr/bin/perl -w

my $dir = shift @ARGV;
my $SCRIPTDIR = "/home/ashieh/netquery/code/scripts/";

my $TIME_PAT = '\d+\.\d+';
# 1202711680.000000: Send request id=0 type=NQ_REQUEST_TRIGGER_CREATE(req) len=676 199447680:9001
# 1202711680.000000: -----> Writing 676 bytes 199447680:9001 <----------
# Client got id=151 type=NQ_REQUEST_TRIGGER_CREATE(response) len=46

#===> "SET TRIGGERS" DONE <===
#===> "COMMIT" START <===

use constant UNDEFINED => 'UNDEFINED';

use constant SEND => 'SEND';
use constant SERVER_GET => 'SERVER_GET';
use constant CLIENT_GET => 'CLIENT_GET';
use constant WRITE => 'WRITE';

sub parse($) {
# return hash of grouped
  my ($fname) = @_;
  open(F, "cat $dir/$fname | $SCRIPTDIR/extract-size-stats.pl|") or die "could not open $fname\n";
  my $section_name = UNDEFINED;

  my @results;

  my @section_stats = ();
  my $section_num = 0;
  my $end_section = sub {
    if(@section_stats > 0) {
      push @results, [ "$section_name-$section_num", [@section_stats] ];
      @section_stats = ();
      $section_num++;
    }
  };

  while(my $line = <F>) {
    if($line =~ /===> "(.+)" START <===/) {
      $end_section->();
      $section_name = $1;
    } elsif($line =~ /===> "(.+)" DONE <===/) {
      die unless($section_name eq $1);
      $end_section->();
      $section_name = UNDEFINED;
    } elsif($line =~ /($TIME_PAT): Send request id=(\d+) type=(\S+) len=(\d+) (\d+:\d+)/) {
      my ($time,$id,$type,$len,$dest) = ($1,$2,$3,$4,$5);
      push @section_stats, [ SEND,$id,$type,$len, $time, $dest ];
    } elsif($line =~ /($TIME_PAT): Server got id=(\d+) type=(\S+) len=(\d+)/) {
      my ($time, $id, $type, $len) = ($1,$2,$3, $4);
      push @section_stats, [ SERVER_GET, $id, $type, $len, $time ];
    } elsif($line =~ /($TIME_PAT): Client got id=(\d+) type=(\S+) len=(\d+)/) {
      my ($time, $id, $type, $len) = ($1,$2,$3, $4);
      push @section_stats, [ CLIENT_GET, $id, $type, $len, $time ];
    } elsif($line =~ /($TIME_PAT): .+Writing (\d+) bytes (\d+:\d+)/) {
      my ($time, $len, $dest) = ($1,$2,$3);
      push @section_stats, [ WRITE, -1, -1, $len, $time, $dest ];
    }
  }
  $end_section->();
  close(F);
  return \@results;
}

sub get_client_stats($) {
  my ($fname) = @_;
  open(F, "<$dir/$fname") or die "could not open $fname\n";
  my $triggers;
  my $hopcount = 0;
  while(my $line = <F>) {
    if($line =~ /Set (\d+) triggers/) {
      die if(defined($triggers));
      $triggers = $1;
    } elsif($line =~ /\[\d+\].+CompositeElement tid/) {
      $hopcount++;
    }
  }
  die unless defined($triggers);
  die unless $hopcount > 0;
  close(F);
  return ($triggers, $hopcount);
}

sub summarize($$) {
  my ($section_stats, $filter) = @_;
  my $client_get_total = 0;
  my $server_get_total = 0;
  my $send_total = 0;
  my $write_total = 0;
  map {
    my ($d) = $_;
    if($filter->($d)) {
      if ($d->[0] eq CLIENT_GET) {
	$client_get_total += $d->[3];
      } elsif ($d->[0] eq SERVER_GET) {
	$server_get_total += $d->[3];
      } elsif ($d->[0] eq SEND) {
	$send_total += $d->[3];
      } elsif ($d->[0] eq WRITE) {
	$write_total += $d->[3];
      }
    }
  } @$section_stats;
  return ($client_get_total, $server_get_total, $send_total, $write_total);
}

sub add_vec($$) {
  my ($a,$b) = @_;
  die unless(@$a == @$b);
  for(my $i=0; $i < @$a; $i++) {
    $a->[$i] += $b->[$i];
  }
}

sub print_data_helper($$$$) {
  my ($results,$filter,$prefix,$do_print_related) = @_;
  my @totals = (0,0,0,0);
  for my $r (@$results) {
    my @section_totals = (0,0,0,0);
    print "${prefix}Section $r->[0]:\n";
    my ($client_got, $server_got, $sent, $wrote) = summarize($r->[1], $filter);
    print "\tGot $client_got, $server_got ; sent $sent ; wrote $wrote\n";
    add_vec(\@totals, [$client_got, $server_got, $sent, $wrote]);
    add_vec(\@section_totals, [$client_got, $server_got, $sent, $wrote]);

    if (0) {
      for my $s (@{$r->[1]}) {
	if(1) {
	  if($filter->($s)) {
	    print "\t" . join(" ", @$s) . "\n";
	  }
	} else {
	  my $p = $filter->($s) ? "" : "N ";
	  print "\t$p" . join(" ", @$s) . "\n";
	}
      }
    }
    if($do_print_related) {
      my @child_total = print_related_sections($r);
      print "Child total " . join (",", @child_total) . "\n";
      add_vec(\@totals, \@child_total);
      add_vec(\@section_totals, \@child_total);
      print "Section totals " . join(",", @section_totals) . "\n";
    }
  }
  return @totals;
}

sub print_related_sections($) {
  my ($section) = @_;

  # Find the first send and last receive
  my $first_send = undef;
  my $last_client_get = undef;
  for my $s (@{$section->[1]}) {
    if($s->[0] eq SEND &&
       !defined($first_send)) {
      $first_send = $s;
    } elsif($s->[0] eq 'CLIENT_GET') {
      $last_client_get = $s;
    }
  }
  die unless(defined($first_send) && defined($last_client_get));

  # Merge data from other sources
  my $start = $first_send->[4];
  my $end = $last_client_get->[4];
  print "[$start-$end]\n";
  my @total = (0,0,0,0);
  for my $f (glob("$dir/*.log")) {
    print "==== $f ====\n";
    $f =~ m{([^/]+)$};
    $f = $1;
    my $results = parse($f);
    #->[4];
    add_vec(\@total, [
    print_data_helper($results,
	      sub {
		my ($a) = @_;
		return
		  $start <= $a->[4] &&
		    $a->[4] <= $end;
	      }, "Other ", 0)
		     ]);
  }
  return @total;
}

sub print_data($) {
  my ($results) = @_;
  my @total = print_data_helper($results, sub { return 1}, "Top ", 1);
  print "Grand total " . join(",", @total) . "\n";
}

my $results = parse("client");
print_data($results);
my ($trigger_count, $hop_count) = get_client_stats("client");
print "Trigger count = $trigger_count, Hop count = $hop_count\n";

#print "==== Local server ====\n";
#$results = parse("local.log");
#print_data($results);

