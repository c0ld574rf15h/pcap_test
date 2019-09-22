all : pcap_test

pcap_test : main.o packet.o
	gcc -o pcap_test main.o packet.o -lpcap

packet.o : packet.c
	gcc -c -o packet.o packet.c

main.o : main.c
	gcc -c -o main.o main.c

clean :
	rm -f pcap_test *.o

