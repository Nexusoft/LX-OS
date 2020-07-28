#!/usr/bin/perl -w

use strict;

use File::Temp qw/ :mktemp /;
use Getopt::Std;

# Test script API
our $FIRST_NQ_SERVER_PORT = 4001;

# Test script can add more nq server options, and add commands to run
# after setup
our $nq_server_opts = "";
our @post_setup = ();
our $first_nq_server_ip;
our $first_nq_server_ip_external;
our @machines;

my $mode = 0;
my $skip_fast_setup = 0;
my %options = ();

getopts("St", \%options);

if(defined($options{S})) {
  $mode = 1;
}
if(defined($options{t})) {
  # Skip setup steps to make it easier to test driver scripts
  $skip_fast_setup = 2;
}


my @test_scripts = @ARGV;

for my $script (@test_scripts) {
  require $script;
}

use SetupCommon;

load_topo_file("test.topo");

my $topdir = "/local/ashieh/nq-linux/user/apps/netquery/testbed/";

sub build_hostfile(@) {
  my @machines = @_;
  my $host_fname = mktemp("/tmp/tmphostXXXXX");

  my @ips = map { $_->[1] } @machines;

  open(HOSTS,">$host_fname") or die "could not open host file\n";
  print HOSTS join("\n", @ips);
  close(HOSTS);
  return $host_fname;
}

@machines = (
#		[1, '128.84.223.159'],
#		[2, '128.84.223.163'],
#		[3,'128.84.223.160'],
#		[4,'128.84.223.162'],

# NQ servers
		[21,'128.84.223.148'], # dualla
# NQ clients
		[31,'128.84.223.150'], # falcon
	);

{
  # Routers are all VMs
  open(VMIP, "<vm-ips.txt") or die "could not open VM ip file\n";
  my $router_id = 1;
  while(my $line = <VMIP>) {
    $line =~ s/\s//g;
    $line =~ s/#+$//;
    chomp $line;
    if($line ne '') {
      die unless is_routerid($router_id);
      if(node_is_present($router_id)) {
	push @machines, [$router_id, $line];
      } else {
	print "Node $router_id not in use\n";
      }
    }
    $router_id++;
  }
  close(VMIP);
}

for my $m (@machines) {
  die "invalid node id\n" if($m->[0] <= 0 || $m->[0] > $MAX_NODEID);
}

my $i = 1;

my $log_count = 0;

sub start_all {
	my ($hosts,$cmd,$extra_args) = @_;
	if(!defined($extra_args)) {
	  $extra_args = "";
	}
	my $host_fname = build_hostfile(@$hosts);
	if(! -e $log_count) {
		system("mkdir $log_count");
	}
	system("pssh $extra_args -h $host_fname -l root -o $log_count/stdout -e $log_count/stderr cd $topdir \\; . /root/testbed-config \\; $cmd");
	$log_count++;
}

sub start_one($$) {
	my ($host,$cmd) = @_;
	system("ssh root\@$host cd $topdir \\; $cmd");
}

if($mode) {
	print "Doing expensive startup\n";

	print "Creating symlinks to config files\n";
	for my $m (@machines) {
	  my ($n,$ip) = @$m;
	  start_one($ip, "rm /root/testbed-config \\; rm /tmp/fib-log.txt \\; ln -s $topdir/router$n/config /root/testbed-config");
	}
	print "Initializing VLAN configuration (takes a long time, might wedge networking. Reboot all nodes if somethig bad happens)\n";
	start_all(\@machines, "./setup-vlan.pl", "-p 20 -t 120");
	print "Done with expensive steps, exiting\n";
	exit(0);
}

for my $m ( grep { is_nqserverid($_->[0]) } @machines) {
  my $nq_server_addr = $m->[1];
  if (!defined($first_nq_server_ip)) {
    $first_nq_server_ip = ext_routable($m->[0]);
    $first_nq_server_ip_external = $nq_server_addr;
  }
}

unless($skip_fast_setup) {
  print "Cleaning up old daemons\n";

  start_all(\@machines, "./cleanup-processes.sh");

  print "Starting NQ processes\n";
  {
    my $nq_server_port = $FIRST_NQ_SERVER_PORT;
    for my $m ( grep { is_nqserverid($_->[0]) } @machines) {
      my $nq_server_addr = $m->[1];
      print "Starting NQ at $nq_server_addr:$nq_server_port\n";
      #start_one($nq_server_addr, "nohup ../netqueryd $nq_server_opts -g -p $nq_server_port \\> /tmp/netqueryd.out '2>&1' &");
      my $core = ""; # "ulimit -c 1000000 \\; "
      start_one($nq_server_addr, " $core nohup ../netqueryd $nq_server_opts -g -p $nq_server_port > /tmp/nq.log 2>&1 &");
      $nq_server_port++;
    }
  }
  sleep(2);

  if (defined($first_nq_server_ip)) {
    my $cmd = "../site-init $first_nq_server_ip $FIRST_NQ_SERVER_PORT";
    print "Running site-init\n";
    print "CMD = $cmd => $first_nq_server_ip\n";
    start_one($first_nq_server_ip_external, $cmd);
  }

  print "Starting up routers\n";
  start_all([grep { is_routerid($_->[0]) } @machines], "nohup ./start-router.sh");
} else {
  print "Skipping fast setup\n";
}

for my $post_setup_cmd (@post_setup) {
  $post_setup_cmd->();
}
