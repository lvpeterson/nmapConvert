# nmapConvert
This script is used to translate a XML file created from the -oX option within nmap to a CSV file.

The format of the CSV is 1 port per row, so if multiple ports are open then there will be multiple rows for the same IP. By default this script only parses TCP and open ports. If your requirements are different it should be easy enough to figure out where to make the necessary modifications.

Columns of CSV:
||IP|Hostname|OS|Port|Service|Application|Version|Extra Info||

Usage: Usage: nmapConvert.pl <nmap xml file.xml> 

Dependancies:
Nmap::Parser
XML::Twig
