#!/usr/local/bin/perl

# $rcs$

#
# This tries to implement RFC 3091: The Pi Digit Generation Protocol
#
# We listen on Ports 314159 and 20007 TCP and UDP.

require 5.002;

#use strict;
use Socket;

sub logmsg;
sub dummy_sig_handler;
sub tcp_listen;
sub udp;

$SIG{'PIPE'}='sig_handler';


$pi="3.1415926535897932384626433832795028841971693993751058209749445923078".
"16406286208998628034825342117084";	# Fallback Approximation.

if (-f pi){
	chomp($pi=`cat pi`);
};

$client=0; # global name for client handle.

sub tcp_listen {
	my $port=shift;
	my $new = "CLIENT".$client++;
	socket($new, PF_INET, SOCK_STREAM, getprotobyname("tcp"))
														|| die "socket: $!";
	bind  ($new, sockaddr_in($port, INADDR_ANY))        || die "bind: $!" ;
	listen($new, SOMAXCONN)                             || die "listen: $!";
	$listen[fileno($new)]=$new;
	$port[fileno($new)]=$port;
	vec($rin,fileno($new),1) = 1;
};

$rin = $win = $ein = '';
&tcp_listen(314159);
&tcp_listen(220007);

sub udp_listen {
	my $port=shift;
	my $new = "CLIENT".$client++;
	socket($new, PF_INET, SOCK_DGRAM, getprotobyname("udp"))
														|| die "socket: $!";
	bind  ($new, sockaddr_in($port, INADDR_ANY))        || die "bind: $!" ;

	$port[fileno($new)]=$port;
	$udp[fileno($new)]=$new;
	vec($rin,fileno($new),1) = 1;
};
&udp_listen(314159);
&udp_listen(220007);

print "Running.\n";

sub pb {
	print unpack("b*",shift),"->",unpack("b*",shift)," ";
}

while(1){
	my $timeout=undef;

	$ein = $rin | $win;

	($nfound,$timeleft) = select($rout=$rin, $wout=$win, $eout=$ein, $timeout);

	pb($rin,$rout); pb($win,$wout); pb($ein,$eout);
	print "$nfound , $timeleft\n";

	die "nfound < 0: $!" if ($nfound < 0);

	$maxfd=1024;
	for (0..$maxfd){
		if (vec($eout,$_,1)==1){
			print "execpt: $_\n";
			die "Unhandled except on fd $_";
			$nfound--;
		};
		if (vec($wout,$_,1)==1){
			print "write: $_\n";
			if ($conn[$_]){
				&send($conn[$_]);
			}else{
				die "Unhandled write on fd $_";
			};
			$nfound--;
		};
		if (vec($rout,$_,1)==1){
			print "read: $_\n";
			if ($listen[$_]){
				&newconn($listen[$_])
			} elsif ($udp[$_]) {
				&udp_packet($udp[$_]);
			} elsif ($conn[$_]) {
				&junk($conn[$_]);
			} else {
				die "Unhandled read on fd $_";
			};
			$nfound--;
		};
		last if ($nfound == 0);
	};

	die "$nfound != 0" if ($nfound != 0);
};

exit;

sub logmsg {
	print @_,"\n";
};

sub newconn{
	my $sock=shift;
	my $new = "CLIENT".$client++;

	$paddr = accept($new,$sock);
	$conn[fileno($new)]=$new;
	$port[fileno($new)]=$port[fileno($sock)];
	vec($rin,fileno($new),1) = 1;
	vec($win,fileno($new),1) = 1;

	my($port,$iaddr) = sockaddr_in($paddr);
	my $name = gethostbyaddr($iaddr,AF_INET);
	logmsg "connection from $name [". inet_ntoa($iaddr). "] port $port";
};

sub send{
	my $sock=shift;
	my $off=$offset[fileno($sock)];
	my $data;

	if($port[fileno($sock)] eq 314159 ){
        # The method chosen SHOULD provide a precise value for the digits of Pi.
		if($off<length($pi)){
			$data=syswrite($sock,$pi,1,$off);
		}else{ # If we can't, fall back to Zeros.
			$data=syswrite($sock,"0",1);
		};
	} elsif ($port[fileno($sock)] eq 220007 ){
		# Approximation service repeats itself.
		$data=syswrite($sock,"142857",1,$off%6);
	}else{
		die "Unknown port number $port[fileno($sock)]";
	};

	$off+=$data;

	select(undef, undef, undef, 0.25);

	$offset[fileno($sock)]=$off;
};

sub udp_packet{
	my $sock=shift;
	my $off;
	my $hispaddr;
	my $data;
	
	$hispaddr= recv($sock, $off, 512, 0);

	$off+=0; # Get numeric value

	my($port,$iaddr) = sockaddr_in($hispaddr);
	my $name = gethostbyaddr($iaddr,AF_INET);
	logmsg "udp from $name [". inet_ntoa($iaddr). "] port $port";
		
	if($off==0){
		print "Junked $off\n";
		return;
	};
	
	$off--;

	if($port[fileno($sock)] eq 314159 ){
        # The method chosen SHOULD provide a precise value for the digits of Pi.
		if($off<length($pi)){
			$data=substr($pi,$off,1);
		}else{ # If we can't, fall back to Zeros.
			$data="0";
		};
	} elsif ($port[fileno($sock)] eq 220007 ){
		# Approximation service repeats itself.
		$data=substr("142857",$off%6,1);
	}else{
		die "Unknown port number $port[fileno($sock)]";
	};

	defined(send($sock, $off.":".$data."\r\n", 0, $hispaddr)) || die "send $host: $!";

	select(undef, undef, undef, 0.25);
};

sub junk{
	my $sock=shift;
	my $data;
	my $read;
	
	$data=sysread($sock,$read,1024);
	
	if ($data > 0){
		print "Junked: $data bytes -$read- $!\n";
	}elsif ($data==0){
		if ($! =~ /reset by peer/){ # XXX This is not nice.
			vec($rin,fileno($sock),1) = 0;
			vec($win,fileno($sock),1) = 0;
			close($sock);
			print "reset it\n";
		};
	}else{
		die "Read returned undef, i think: $!";
	};
};

sub dummy_sig_handler {
        my($sig) = @_;
        logmsg "Caught a SIG$sig.";
};

