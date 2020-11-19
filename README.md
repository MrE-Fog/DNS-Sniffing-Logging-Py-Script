# DNS-Sniffing-Logging-Py-Script
Script that uses NPCAP and pcap-ct modules to sniff DNS traffic and log to a file

Still in a fairly rough state. Building on the good work of others, namely : https://github.com/jeffsilverm/dpkt_doc/blob/master/decode_dns.py ., the goal here was to create something that might be able to run on DNS servers and structure the DNS question\answer data such that it could be used to feed a SIEM.

It took some scavenging to get a useable "pcap" module. I have no idea why but on Windows installing "pcap-ct" effectivley gives you "pcap". The other necessary ingredient is NPCAP, which fully replaces legacy WINPCAP.
