#!/usr/bin/perl

# ---------------------------------------------------------------------
# Author: Logan Peterson
# Date: April 3rd, 2015
# Description: This script is to translate a XML file created from the 
#	-oX command used in nmap scans to a CSV file. The input is the xml
#	file that and the output will be placed in the same place the script
#	is ran called "ScanResults.csv"
# Usage: nmapConvert.pl <nmap xml file.xml> 
#
# This script used the below script as a base:
# http://eelsivart.blogspot.com/2012/03/converting-nmap-xml-output-to-csv-excel.html
# ---------------------------------------------------------------------

# Libraries and Basics
use strict;
use warnings;
use Nmap::Parser;

# Globals:
my $scan = new Nmap::Parser;

# Check for usage
if (!$ARGV[0])
{
	print "Usage: nmapConvert.pl <nmap xml file.xml>";
	exit;
}

# Scan file for nmap XML
my $scan_file = $ARGV[0];

# Create Results file:
open (my $results, ">ScanResults.csv") or die "Can't open file: $!";

# Prototype:
sub main();

# Main Call
main();

# ---------------------------------------------------------------------
#  Function: main()
#  Inputs: N/A
#  Description: This is the only function of this script. Its primary
#	function is what the description of this document describes.
#	
#	A few things to note:
#		This script only concerns itself with open TCP ports found in
#		the xml file. It can be modified to have UDP included in scope
#		as well.
#
#	The format of the output in CSV will be the below:	
#	||IP|Hostname|OS|Port|Service|Application|Version|Extra Info||
#
# ---------------------------------------------------------------------

sub main(){
	
	my $svc;
	my $hostobj;
	my $count = 0;
	open (my $debug, " >debug.txt") or die "can't open file: $!";
	
	# Put xml into parser
	$scan->parsefile($scan_file);
	
	print $results "IP,Hostname,OS,Port,Service,Application,Version,Extra Info\n";

	#loop through all the IPs in the current scan file
	for my $ip ($scan->get_ips) 
	{
		# Get Host Obj
		$hostobj = $scan->get_host($ip);

		# Get Ports
		my @tcpports = $hostobj->tcp_ports;
		
		# Loop through ports to establish 1 port & IP per line
		foreach my $port (@tcpports){
			# Only care about ports that are open, skip all others
			if ($hostobj->tcp_port_state($port) ne "open"){
				next;
			}
			
			# Get OS and Service information:
			my $os = $hostobj->os_sig;
			$svc = $hostobj->tcp_service($port);
			
			# Handle special case(s) where OS name has , in it
			my $osname = $os->names;
			$osname =~ s/,//g;
			
			# Output results
			print $results $hostobj->ipv4_addr . ",";
			print $results $hostobj->hostname . ",";		
			print $results $osname . ",";				
			print $results $port . ",";
			print $results $svc->name . ",";
			print $results $svc->product . ",";
			print $results $svc->version . ",";
			print $results $svc->extrainfo . "\n";
		}	
	} 
	close ($results);
}
