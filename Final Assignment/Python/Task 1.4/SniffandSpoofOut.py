from scapy.all import *
from scapy.layers.inet import *


def spoof(pkt):
    # create new ICMP header inorder to fake a response
    spoofed = ICMP()
    spoofed.type = 0
    spoofed.id = pkt[ICMP].id
    spoofed.seq = pkt[ICMP].seq

    #create new IP header and swapping src and dest in spoofted packet
    changedIP = IP()
    changedIP.src = pkt[IP].dst
    changedIP.dst = pkt[IP].src

    # copying message from original packet
    newRAW = Raw()
    newRAW.load = pkt[Raw].load

    # putting together the entire spoofed packet to send back
    madePacket = changedIP/spoofed/newRAW

    send(madePacket)


pkt = sniff(iface=['br-1ca35f87b2fa', 'enp0s3'], filter='icmp[icmptype] == icmp-echo', prn=spoof)
