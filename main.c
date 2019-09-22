#include <pcap.h>
#include <stdio.h>
#include "packet.h"
#define	TRUE		1

int main(void) {
    // 0. Setting the Device (Interface)
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in searching network interfaces : %s\n", errbuf);
        return -1;
    }
    // Select first interface as default
    dev = alldevs;
    printf("[*] Dev : %s\n[*] Description : %s\n", dev->name, dev->description ? dev->description : "Not available");

    // 1. Opening the Device
    pcap_t * handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "Couldn't open device %s : %s\n", dev->name, errbuf);
        return -1;
    }

    // 2. Grab Packets & Print Information
    int grabbed = 0;
    while(TRUE) {
        struct sniff_ethernet *ethernet;
        struct pcap_pkthdr *header;
        const u_char* data;
        int res = pcap_next_ex(handle, &header, &data);

        printf("\n[Packet #%d]\n", grabbed);
        puts("------------------------------------------------------");
        // Ethernet Header
        ethernet = (struct sniff_ethernet*)(data);
        print_ether_hdr(ethernet);
        puts("------------------------------------------------------");

        grabbed += 1;
    }
    
    return 0;
}
