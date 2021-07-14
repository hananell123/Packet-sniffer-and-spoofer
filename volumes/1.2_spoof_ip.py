from scapy.all import*
a=IP()
a.src = '1.2.3.4'
a.dst='8.8.8.8'
b=ICMP()
p=a/b
send(p)
