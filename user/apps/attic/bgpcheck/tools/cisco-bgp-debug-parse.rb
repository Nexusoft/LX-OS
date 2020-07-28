#!/usr/bin/ruby -w

class Route
	def initialize(prefix)
		@prefix = prefix
		(@nexthop, @path) = nil
	end
	def ready
		@prefix && @nexthop && @path
	end
	attr_reader :prefix, :nexthop, :path
	attr_writer :nexthop, :path
end

def handle_line(line)
	$line_no += 1
	line =~ /(\d+):(\d+):(\d+)/
	$ts = 3600*$1.to_i + 60*$2.to_i + $3.to_i
	if $ts > $old_ts + 2
		($sender, $routeset, $nexthop, $prefix) = nil
	end
	$old_ts = $ts
	if line =~ /\[upd\].*Updates replicated to neighbor ([0-9.]+)/
		$routesclosed = 1;
		if $routeset && $routeset.last.ready
			print "SENT_TO: #$1\n",
				$routeset.map{|p|
					#if !p.ready
						#STDERR.print "UPDATE for #{p.prefix} not ready to send!\n"
						#nil
					#else
						"AS_PATH: #{p.path}\nSTATUS: 0\nANNOUNCE: #{p.prefix}\n"
					#end
				}.join
			#($path, $nexthop, $prefix) = nil
		elsif $withdrawal
			print "SENT_TO: #$1\n#$withdrawal"
			#$withdrawal = nil
		else
			STDERR.print "[#$line_no] no update to send\n"
		end
	elsif line =~ /\[rtr\].*UPDATE from ([0-9.]+), prefix ([0-9.\/]+) withdrawn/
		#print "received from #$1: withdraw #$2\n"
		print "RECEIVED_FROM: #$1\nSTATUS: 0\nWITHDRAWN: #$2\n";
	elsif line =~ /\[upd\].*Sending UPDATE.*with ([0-9.\/]+) unreachable/
		#$withdrawal = "withdraw #$1"
		$withdrawal = "STATUS: 0\nWITHDRAWN: #$1\n"
	elsif line =~ /\[rtr\].*Received UPDATE from ([0-9.]+) with attr/
		$sender = $1
	elsif $sender && line =~ /\[rtr\].*nexthop ([0-9.]+),.* path ([0-9 ]+)/
		($nexthop, $path) = [$1,$2]
	elsif $sender && line =~ /\[rtr\].*Received ([0-9.\/]+) from ([0-9.]+)/
		if $sender != $2 then
			STDERR.print "[#$line_no] UPDATE sender mismatch! #$sender != #$2\n"
		elsif !$path then
			STDERR.print "[#$line_no] PATH not set!\n"
		else
			#print "received from #$sender: #$1 #$path\n"
			print "RECEIVED_FROM: #$sender\nAS_PATH: #$path\nSTATUS: 0\nANNOUNCE: #$1\n"
		end
	elsif $routeset && line =~ /\[upd\].*path ([0-9 ]+).*nexthop ([^ ,]+)[ ,]/
		#$sending_update = "#{$prefix.join(' ')} #$1"
		$routeset.last.path = $1;
		$routeset.last.nexthop = $2;
	elsif ($routesclosed == 0) && $routeset && line =~ /\[upd\].*Sending UPDATE message .* for ([0-9.\/]+)/
		$routeset.push(Route.new($1))
	elsif line =~ /\[upd\].*Sending UPDATE message .* for ([0-9.\/]+)/
		$routesclosed = 0;
		$routeset = [Route.new($1)]
	else
		junk(line)
	end
end

def junk(line)
	if line =~ /\[rtr\].*Received unreachables/
	elsif line =~ /\[upd\].*Computing updates/
	elsif line =~ /\[upd\].*table-attr walk for table TBL/
	elsif line =~ /\[upd\].*No unreachable sent to/
	elsif line =~ /\[upd\].*Update generation run for IPv4/
	elsif line =~ /\[upd\].*Generated \d+ updates for update/
	elsif line =~ /\[rtr\].*Next hop received.*is a local address/
	elsif line =~ /\[ioct\].*Active open to/
	elsif line =~ /\[ioct\].*Could not open active connection/
	elsif line =~ /\[ioct\].*Using local address/
	elsif line =~ /\[ioct\].*Setting TTL Rx filter/
	elsif line =~ /\[ioct\].*Set precedence for/
	elsif line =~ /\[ioct\].*Connect attempt to/
	elsif line =~ /\[upd\].*Formatting MP_UNREACH attribute/
	elsif line =~ /\[rtr\].*duplicate path .* ignored/
	else
		STDERR.print "[#$line_no] REJECTED: #{line}\n"
	end
end


$routesclosed = 0;
$line_no = 0
$old_ts = 0
ARGF.each {|line| handle_line(line) }
