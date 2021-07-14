from scapy.all import *

def show_pkt(pkt) :
	pkt.show()

pkt=sniff(iface='br-ef6bf2313a33', filter='icmp', prn=show_pkt)

