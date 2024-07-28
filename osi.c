#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800

// Ethernet header
struct ethernet_header {
    u_int8_t ether_dhost[ETHER_ADDR_LEN];  /* destination ethernet address */
    u_int8_t ether_shost[ETHER_ADDR_LEN];  /* source ethernet address */
    u_int16_t ether_type;                  /* protocol */
};

// IPv4 header
struct ipv4_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t ip_hl:4, ip_v:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t ip_v:4, ip_hl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
    u_int8_t ip_tos;          /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;         /* fragment offset field */
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

// TCP header
struct tcp_header {
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;         /* sequence number */
    u_int32_t th_ack;         /* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4, th_off:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4, th_x2:4;
#endif
    u_int8_t th_flags;
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_packet_info(const u_char *packet) {
    struct ethernet_header *eth_header = (struct ethernet_header *)packet;
    struct ipv4_header *ip_header = (struct ipv4_header *)(packet + sizeof(struct ethernet_header));
    struct tcp_header *tcp_header = (struct tcp_header *)(packet + sizeof(struct ethernet_header) + (ip_header->ip_hl * 4));
    const u_char *payload = packet + sizeof(struct ethernet_header) + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4);
    int payload_length = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4) - (tcp_header->th_off * 4);

    printf("\n---------------------------------------\n");  
    // Print Ethernet Header
    printf("Ethernet Header:\n");
    printf("\tSource MAC: ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", eth_header->ether_shost[i]);
        if (i < ETHER_ADDR_LEN - 1) printf(":");
    }
    printf("\n\tDestination MAC: ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", eth_header->ether_dhost[i]);
        if (i < ETHER_ADDR_LEN - 1) printf(":");
    }

    // Print IP Header
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);


    printf("\nIP Header:\n");
    printf("\tSource IP: %s\n", src_ip);
    printf("\tDestination IP: %s\n", dst_ip);

    // Print TCP Header
    printf("TCP Header:\n");
    printf("\tSource Port: %d\n", ntohs(tcp_header->th_sport));
    printf("\tDestination Port: %d\n", ntohs(tcp_header->th_dport));

    // Print Payload (Hexadecimal)
    printf("Payload (Hexadecimal):\n\t");
    for (int i = 0; i < payload_length && i < 20; i++) {
        printf("%02x ", payload[i]);
    }
    printf("\n");

    printf("\n---------------------------------------\n");
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethernet_header *eth_header = (struct ethernet_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ipv4_header *ip_header = (struct ipv4_header *)(packet + sizeof(struct ethernet_header));
        if (ip_header->ip_p == IPPROTO_TCP) {
            print_packet_info(packet);
        }
    }
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        packet_handler(NULL, header, packet);
    }

    pcap_close(pcap);
}
