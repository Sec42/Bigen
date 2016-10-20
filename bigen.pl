#!/usr/local/bin/perl
# vim:set ai ts=4 sw=4 si:
#
# This implements RFC 3091: The Pi Digit Generation Protocol
#
# Written by Stefan `Sec` Zehl <sec@42.org>, 
# first released under BSD Copyright 2001-5-1
#
# It implements the pigen and pigem (approximate pi) service via TCP
# and UDP. The pigen service is done with a precalculated value of PI
# read from the file "pi". If digits beyond the ones available are
# requested, we violate the "SHOULD" provide an accurate value, and
# return an approximation consisting of zeros.
#
# The service is deliberately slowed down to 4 Answers per second
# shared among all requestors. Via TCP this results in max 4
# characters/sec. Via UDP this may be as high as
# (max_size_of_udp_packet)*4. I don't deem this a flooding risk,
# because you get the same effect with icmp echo's. Nontheless this
# may be switched off by commenting the two &udp_listen() lines below.
#
# It does dns lookups by default which will hang all replies while
# looking up a hostname. This may be switched off, by setting $dns=0
# below.
#
# $Id$

require 5.002;

$|=1;

use strict;
use Socket;
use Symbol qw(gensym);

sub dummy_sig_handler;
sub tcp_listen;
sub udp_listen;
sub newconn;
sub send;
sub udp_packet;
sub junk;
sub logmsg;
sub logconn;

open(LOG,">>bigen.log") || die "Can't open logfile: $!";
select LOG;$|=1; # Write everything into our LOG

$SIG{'PIPE'}='dummy_sig_handler';

my $pi="141592653589793238462643383279502884197169399375105820974944".
       "592307816406286208998628034825342117084"; # Fallback Approximation.

if (-f "pi"){
	chomp($pi=`cat pi`);
	logmsg length($pi)," digits of PI loaded";
};

my $dns=1;						# Do DNS lookups (may cause delays).
my (@listen,@conn,@port,@udp);	# Arrays for Socket handling.
my (@offset);					# Array for Offset in tcp stream.
my ($rin,$win,$ein);			# For select().
my $client=0; 					# Global name for Socket handle.

# We listen on Ports 314159 and 220007 TCP and UDP.
&tcp_listen(314159);
&tcp_listen(220007);
&udp_listen(314159);			# Remove these, if you don't want UDP.
&udp_listen(220007);

logmsg "Started.";

#sub pb { print unpack("b*",shift)." "; }

while(1){
	my $timeout=undef;
	my $maxfd=1024;		# max FDs.

	my ($nfound,$timeleft);
	my ($rout,$wout,$eout);

	$ein = $rin | $win;

	($nfound,$timeleft) = select($rout=$rin, $wout=$win, $eout=$ein, $timeout);
	
#	pb($rin); pb($win); pb($ein);print"\n";
#	pb($rout); pb($wout); pb($eout);print"$nfound\n";

	die "nfound < 0: $!" if ($nfound < 0);

	for (0..$maxfd){ # Do what select deems necessary.
		if (vec($eout,$_,1)==1){
			die "Unhandled except on fd $_";
			$nfound--;
		};
		if (vec($wout,$_,1)==1){
			if ($conn[$_]){
				&send($conn[$_]);
			}else{
				die "Unhandled write on fd $_";
			};
			$nfound--;
		};
		if (vec($rout,$_,1)==1){
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

sub newconn{
	my $sock=shift;
#	my $new = "CLIENT".$client++;
	my $new = gensym;
	my $paddr = accept($new,$sock);

	$conn[fileno($new)]=$new;
	$port[fileno($new)]=$port[fileno($sock)];
	$offset[fileno($new)]=0;
	vec($rin,fileno($new),1) = 1;
	vec($win,fileno($new),1) = 1;

	logconn $paddr,"Connection from %s port %d for $port[fileno($sock)]";
};

sub send{
	my $sock=shift;
	my $off=$offset[fileno($sock)];
	my $data;

	$data=&digit($port[fileno($sock)],$off);
	$off+=syswrite($sock,$data,1,0);
	$offset[fileno($sock)]=$off;

	select(undef, undef, undef, 0.25);
};

sub udp_packet{
	my $sock=shift;
	my $off;
	my $hispaddr;
	my $data;
	
	$hispaddr= recv($sock, $data, 512, 0);
	
	$off=$data+0;

	logconn $hispaddr,"Udp $off from %s port %d";
		
	if($off==0){
		chomp($data);
		logmsg "UDPjunk: $data";
		return;
	};

	$data=&digit($port[fileno($sock)],$off-1);

	defined(send($sock, $off.":".$data."\r\n", 0, $hispaddr))
												|| die "send: $!";
	select(undef, undef, undef, 0.25);
};

sub junk{
	my $sock=shift;
	my $data;
	my $read;
	
	$data=sysread($sock,$read,1024);
	
	if ($data > 0){
		# If someone hits ^c in his Telnet, we get ff f4 ff fd 06
		# We probably should do somthing about this, because telnet 
		# then stops displaying the incoming data.
		chomp($read);
		logmsg "TCPjunk: $read";
	}elsif ($data==0){
		if ($! =~ /reset by peer/){ # XXX This is not nice.
			vec($rin,fileno($sock),1) = 0;
			vec($win,fileno($sock),1) = 0;
			close($sock);
			logmsg "TCPClose";
		};
	}else{
		die "Somewhat bizarre problem, i think: $!";
	};
};

sub dummy_sig_handler {
        my($sig) = @_;
        logmsg "Caught a SIG$sig.";
};

sub tcp_listen {
	my $port=shift;
#	my $new = "CLIENT".$client++;
	my $new = gensym;
	socket($new, PF_INET, SOCK_STREAM, getprotobyname("tcp"))
														|| die "socket: $!";
	bind  ($new, sockaddr_in($port, INADDR_ANY))        || die "bind: $!" ;
	listen($new, SOMAXCONN)                             || die "listen: $!";
	$listen[fileno($new)]=$new;
	$port[fileno($new)]=$port;
	vec($rin,fileno($new),1) = 1;
};

sub udp_listen {
	my $port=shift;
#	my $new = "CLIENT".$client++;
	my $new = gensym;

	socket($new, PF_INET, SOCK_DGRAM, getprotobyname("udp"))
														|| die "socket: $!";
	bind  ($new, sockaddr_in($port, INADDR_ANY))        || die "bind: $!" ;

	$port[fileno($new)]=$port;
	$udp[fileno($new)]=$new;
	vec($rin,fileno($new),1) = 1;
};

sub logconn {
	my($port,$iaddr) = sockaddr_in(shift);
	my $name;
	if ($dns) {
		$name = gethostbyaddr($iaddr,AF_INET)." [".inet_ntoa($iaddr)."]";
	}else{
		$name=inet_ntoa($iaddr);
	};
	logmsg scalar localtime;
	logmsg sprintf shift,$name,$port;
};

sub digit{
	my $port=shift;
	my $off=shift;

	if($port eq 314159 ){
		# The method chosen SHOULD provide a precise value for the digits of Pi.
		if($off<length($pi)){
			return substr($pi,$off,1);
		}else{ # If we can't, fall back to Zeros.
			return "0";
		};
	} elsif ($port eq 220007 ){
		# Approximation service repeats itself.
		return substr("142857",$off%6,1);
	}else{
		die "Unknown port number $port";
	};
};

sub logmsg {
	print @_,"\n";
};

