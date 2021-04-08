#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
	pkt.show()

	
pkt = sniff(iface=['br-82771e18ec80', 'enp0s3'], filter = 'ip host 10.0.2.4 and tcp dst port 23' , prn=print_pkt)
