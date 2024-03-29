#include "packet.h"
#include <stdio.h>

u_short my_ntohs(u_short stream) {
    return (stream << 8) | (stream >> 8);
}

void print_addr(u_char *payload, int length, const char *fmt, char div, char end) {
    for(int i=0;i<length;++i) {
        printf(fmt, payload[i]);
        i == length - 1 ? fputc(end, stdout) : fputc(div, stdout);
    }
}

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
    printf("\n[ Ethernet Header Scan ]\n[*] Source MAC address : ");
    print_addr(hdr->ether_shost, ETHER_ADDR_LEN, "%02X", ':', '\n');
    printf("[*] Destination MAC address : ");
    print_addr(hdr->ether_dhost, ETHER_ADDR_LEN, "%02X", ':', '\n');
}

void print_ip_hdr(struct sniff_ip* hdr) {
    printf("\n[ IP Header Scan ]\n[*] Source IP address : ");
    print_addr(hdr->ip_src, IP_ADDR_LEN, "%d", '.', '\n');
    printf("[*] Destination IP address : ");
    print_addr(hdr->ip_dst, IP_ADDR_LEN, "%d", '.', '\n');
}

void print_tcp_hdr(struct sniff_tcp* hdr) {
    printf("\n[ TCP Header Scan ]\n");
    printf("[*] Source Port : %d\n", my_ntohs(hdr->tcp_sport));
    printf("[*] Destination Port : %d\n", my_ntohs(hdr->tcp_dport));
}

void print_payload(const u_char *payload, int sz) {
    if(sz == 0) return;
    printf("\n[ Payload ]\n");
    for(int i=0;i<(sz < 32 ? sz : 32);++i) {
        printf("%02X ", payload[i]);
        if((i%16)==15) fputc('\n', stdout);
    } if(sz<32 && sz%16!=0) fputc('\n', stdout);
}

int check_IP(struct sniff_ethernet* hdr) {
    return my_ntohs(hdr->ether_type) == 0x0800; // IPv4
}

int check_TCP(struct sniff_ip* hdr) {
    return hdr->ip_ptcl == 0x06;
}

void div_line(void) {
    puts("\n------------------------------------------------------");
}