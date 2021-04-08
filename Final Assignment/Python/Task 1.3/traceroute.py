#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import *

a = IP()
a.dst = '8.8.8.8'
a.ttl = 11
b = ICMP()
send(a / b)


