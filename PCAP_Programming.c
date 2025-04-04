#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/in.h> 
#include <ctype.h> // isprint() 사용을 위해 추가

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;        /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr     iph_sourceip;
    struct in_addr     iph_destip;
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

void packet_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ethheader *eth_header = (struct ethheader *)packet;
    struct ipheader *ip_header = (struct ipheader *)(packet + sizeof(struct ethheader));
    int ip_header_len = ip_header->iph_ihl * 4;
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;

    // Ethernet 헤더 정보 출력
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_shost));
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));

    // IP 정보 출력
    printf("Source IP = %s\n", inet_ntoa(ip_header->iph_sourceip));
    printf("Destination IP = %s\n", inet_ntoa(ip_header->iph_destip));

    // TCP 포트 정보 출력
    printf("Source Port = %d\n", ntohs(tcp->tcp_sport));
    printf("Destination Port = %d\n", ntohs(tcp->tcp_dport));

    // Message 출력
    unsigned char *payload = (unsigned char *)(packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len);
    int payload_size = ntohs(ip_header->iph_len) - (ip_header_len + tcp_header_len);

    if (payload_size > 0) {
        printf("Payload (%d bytes): ", payload_size);
        for (int i = 0; i < payload_size && i < 50; i++) {
            printf("%c", isprint(payload[i]) ? payload[i] : '.'); // 출력 가능 문자만 표시
        }
        printf("\n");
    } else {
        printf("No payload data.\n");
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // NIC카드로부터 패킷 캡처 세션 오픈
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        printf("Couldn't open device: %s\n", errbuf);
        return 2;
    } else {
        printf("Connect Success\n");
        pcap_loop(handle, 0, packet_capture, NULL);
        pcap_close(handle);
        return 0;
    }
}
