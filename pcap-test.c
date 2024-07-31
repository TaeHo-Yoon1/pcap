#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

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

void print_info (const u_char* packet) {
    struct ether_header *eth_h = (struct ether_header *)packet;
    struct ip *ip_h =  (struct ip *)(packet + sizeof(struct ether_header));
    struct tcphdr *tcp_h = (struct tcphdr *)((u_char *)ip_h + (ip_h->ip_hl * 4));
    char *data_p = (char *)tcp_h + (tcp_h->th_off * 4);

    printf("SRC MAC : ");

    for (int i = 0; i < 6; i++) {
        printf("%02x ", eth_h->ether_shost[i]);
    }
    printf("\n");

    printf("SRC IP : %s\n", inet_ntoa(ip_h->ip_src));
    printf("DST IP : %s\n", inet_ntoa(ip_h->ip_dst));
    printf("SRC PORT: %d\n", ntohs(tcp_h->th_sport));
    printf("DST PORT: %d\n", ntohs(tcp_h->th_dport));

    printf("PAY ROAD : ");
    for (int k = 0; k < 20; k++) {
        printf("%02x ", (unsigned char)data_p[k]);
    }
    printf("\n");
}

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
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
        print_info(packet);
    }

    pcap_close(pcap);
}



