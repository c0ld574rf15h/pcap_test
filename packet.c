#include "packet.h"
#include <stdio.h>

void handle_pcap_next(int res, struct pcap_pkthdr *hdr) {
    switch(res) {
        case 0:
            fprintf(stderr, "[!] Timeout Expired\n");
            break;
        case PCAP_ERROR:
            fprintf(stderr, "[!] Error occured while reading packet\n");
            break;
        case PCAP_ERROR_BREAK:	// Not used from this project
            fprintf(stderr, "[!] No more packets to read from savefile\n");
            break;
        case 1:
            printf("%d Bytes Captured\n", hdr->caplen);
    }
}

void print_ether_hdr(struct sniff_ethernet* hdr) {
    printf("[Ethernet Header Scan]\n[*] Destination MAC address : ");
    for(int i=0;i<ETHER_ADDR_LEN;++i) {
        printf("%02x", hdr->ether_dhost[i]);
        i == ETHER_ADDR_LEN-1 ? fputc('\n', stdout) : fputc(':', stdout);
    }
    printf("[*] Source MAC address : ");
    for(int i=0;i<ETHER_ADDR_LEN;++i) {
        printf("%02x", hdr->ether_shost[i]);
        i == ETHER_ADDR_LEN-1 ? fputc('\n', stdout) : fputc(':', stdout);
    }
}

