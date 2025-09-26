#!/usr/bin/env python3

import sys
from scapy.all import *
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
print("Host ip addr : ", s.getsockname()[0])
ip_address = s.getsockname()[0]
s.close()

def handle_pkt(pkt):
    if pkt.haslayer(IPv6) or pkt.getlayer(IP).src == ip_address:
        return
    print("Got a packet")
    pkt.show2()
    sys.stdout.flush()


def main():
    iface = 'eth0'
    print("Sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface=iface, prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()
