# pcap-parser
### Analyze a pcap (or pcapng) file and return a table of the highest layer protocols with a count of occurrences.

Large pcap(ng) files will process slowly, so YMMV.  For example, a 12 MB file with 38642 packets and 70+ protocols takes about 3 minutes.
