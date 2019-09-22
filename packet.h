#pragma once
#include <pcap.h>

#define ETHER_ADDR_LEN	6
#define IP_ADDR_LEN     4

#define SIZE_ETHERNET   14

// Network header structures
struct sniff_ethernet {
    // Destination MAC | Source MAC | Ether Type
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

struct sniff_ip {
    // IP version | Header Length | Total Length |
    u_char ipv_hl;
    u_char ip_tos;
    u_short ip_len;
    // Identification | Fragment Offset Field
    u_short ip_id, ip_off;
    // Time To Live | Protocol | Checksum
    u_char ip_ttl, ip_ptcl;
    u_short ip_sum;
    // Source IP | Destination IP
    u_char ip_src[IP_ADDR_LEN], ip_dst[IP_ADDR_LEN];
};

struct sniff_tcp {
    // Source Port | Destination Port
    u_short tcp_sport, tcp_dport;
    // Sequence Number
    uint32_t tcp_seq;
    // Acknowledgement Number
    uint32_t tcp_ack;
    // Data Offset | Flags | Window
    u_char tcp_off, tcp_flags;
    u_short tcp_window;
    // Checksum | Urgent Pointer
    u_short tcp_sum, tcp_urg;
};

// Functions for type conversion
u_short my_ntohs(u_short stream);

// Functions for printing information
void print_addr(u_char *payload, int length, const char* fmt, char div, char end);
void handle_pcap_next(int res, struct pcap_pkthdr *hdr);
void print_ether_hdr(struct sniff_ethernet* hdr);
void print_ip_hdr(struct sniff_ip* hdr);
void print_tcp_hdr(struct sniff_tcp* hdr);
void div_line(void);

// Functions for checking protocol
int check_IP(struct sniff_ethernet* hdr);
int check_TCP(struct sniff_ip* hdr);