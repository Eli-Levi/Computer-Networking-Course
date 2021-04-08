from scapy.all import *
from scapy.layers.inet import *


def spoof(pkt):

    # create new ICMP header inorder to fake a response
    spoofed = ICMP()
    spoofed.type = 0

    #create new IP header and swapping src and dest in spoofted packet
    changedIP = IP()
    changedIP.src = pkt[ARP].pdst
    changedIP.dst = pkt[ARP].psrc


    # putting together the entire spoofed packet to send back
    madePacket = changedIP/spoofed
    send(madePacket)


pkt = sniff(iface=['br-e2f0ea1b68d8'], filter='arp[6:2] = 1', prn=spoof)
