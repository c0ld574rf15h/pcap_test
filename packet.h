#pragma once
#include <pcap.h>

#define ETHER_ADDR_LEN	6

// Network header structures
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

// Functions for printing information
void handle_pcap_next(int res, struct pcap_pkthdr *hdr);
void print_ether_hdr(struct sniff_ethernet* hdr);
