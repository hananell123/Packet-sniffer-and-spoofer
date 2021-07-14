CC=gcc
AR=ar
FLAGS=-Wall -g


all:2.1A 2.1B 2.2A 2.3


2.1A:
	 $(CC) $(FLAGS)  -o sniff_packet 2.1A_sniff_packets.c -lpcap
2.1B:  
	$(CC) $(FLAGS) -o sniff_packet_icmp 2.1B_sniff_icmp.c -lpcap
2.2A:
	$(CC) $(FLAGS)  -o sniff_and_spoof 2.2A_sniff_and_spoof.c -lpcap
2.3:
	$(CC) $(FLAGS)  -o sniff_and_spoof2.3 2.3sniff_and_spoof.c -lpcap


.PHONY:clean all
clean:
	rm -f *.o *.a *.so sniff_packet sniff_packet_icmp sniff_and_spoof sniff_and_spoof2.3
