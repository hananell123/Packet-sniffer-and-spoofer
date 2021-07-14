from scapy.all import *

def print_pkt(pkt) :
	pkt.show()
	
pkt=sniff(iface=['br-ef6bf2313a33','enp0s3'], filter='net 128.230.0.0/16', prn=print_pkt)

