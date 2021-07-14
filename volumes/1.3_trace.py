from scapy.all import*
def print_pkt(pkt) :
	pkt.show()
	
a = IP()
a.dst = '34.96.118.58'
for num in range (1,11):
	a.ttl=num
	b=ICMP()
	send(a/b)
	a.show()


