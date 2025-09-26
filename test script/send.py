#!/usr/bin/env python3

import argparse
import socket
from time import sleep

from scapy.all import IP, TCP, UDP, Ether, get_if_hwaddr, get_if_list, sendp


def get_if():
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--p",   help="Protocol name To send TCP/UDP etc packets", type=str)
    parser.add_argument("--des", help="IP address of the destination", type=str)
    parser.add_argument("--sp",  help="Source port number", type=int)
    parser.add_argument("--dp",  help="Destination port number", type=int)
    parser.add_argument("--m",   help="Raw Message", type=str)
    args = parser.parse_args()

    if args.p and args.des and args.sp and args.dp and args.m:
        addr = socket.gethostbyname(args.des)
        iface = get_if()
        if args.p == 'UDP':
            pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=addr, tos=1) / UDP(dport=args.dp, sport=args.sp) / args.m
            pkt.show2()
            try:
                for i in range(3):
                    sendp(pkt, iface=iface)
                    sleep(1)
            except KeyboardInterrupt:
                raise
        elif args.p == 'TCP':
            pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=addr, tos=1) / TCP(dport=args.dp, sport=args.sp) / args.m
            pkt.show2()
            try:
                for i in range(3):
                    sendp(pkt, iface=iface)
                    sleep(1)
            except KeyboardInterrupt:
                raise


if __name__ == '__main__':
    main()
