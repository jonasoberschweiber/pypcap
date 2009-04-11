# PyPcap
## Simple pcap file format reader for Python

PyPcap is a very simple reader for the pcap file format used by tcpdump, Wiershark and others. It also contains classes that make Ethernet, IP and TCP packets as well as whole TCP streams easy to work with. Using PyPcap you can quickly build analyzers for protocols captured in pcap files, without having to hack the Wireshark source.

A small usage example (using only PyPcap):

  import pypcap.pcap
  
  pcap_file = pypcap.PcapFile('path/to/your/pcap.file')
  p = pcap_file.next_packet()
  while p != None:
    print p.incl_len
    p = pcap_file.next_packet()
    
And one example using the tcp_streams_from_file helper:

  import pypcap.ethernet
  
  for stream in pypcap.ethernet.tcp_streams_from_file('path/to/your/pcap.file')
    print stream.sent_data()
    
