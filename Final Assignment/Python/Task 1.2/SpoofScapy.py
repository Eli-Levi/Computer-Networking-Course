from scapy.all import *
a = IP()
a.src = '10.9.0.5'
a.dst = '10.9.0.1'
b = ICMP()
p = a/b
send(p)
