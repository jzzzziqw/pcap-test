#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <libnet.h>


typedef struct {
    char* dev_;
} V;

V values = {
    .dev_ = NULL // default value
};

bool parse(V* values, int argc, char* argv[]) {
    if (argc != 2) { 
        printf("입력값이 잘못되었습니다.\n./pcap-test <interface>\n");
        return false;
    }
    values->dev_ = argv[1]; // set network interface name
    return true;
}

// data -> hex
void print_hex(const u_char* data, int len) {
    for (int i = 0; i < len && i < 20; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&values, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(values.dev_, BUFSIZ, 1, 1000, errbuf); 
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", values.dev_, errbuf);
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

        // 이더넷 헤더
        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        // IPv4 헤더
        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));

        if (ip_hdr->ip_p != IPPROTO_TCP) {  // TCP 프로토콜이 아닌 경우
            continue;  // 무시
        }

        // TCP 헤더
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl * 4));
        // 페이로드 데이터
        const u_char* payload = packet + sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4);
        int payload_len = header->caplen - (payload - packet);  // 페이로드 길이

        printf("%u bytes captured\n", header->caplen);  // 캡처된 바이트 수 출력

        // 이더넷 헤더 정보 출력
        printf("Ethernet Header\n");
        printf("ㄴSource MAC Address      : %02X:%02X:%02X:%02X:%02X:%02X \n",
               eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
               eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
        printf("ㄴDestination MAC Address : %02X:%02X:%02X:%02X:%02X:%02X \n",
               eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
               eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

        // IP 헤더 정보 출력
        printf("IP Header\n");
        printf("ㄴsource IP Address       : %s\n", inet_ntoa(ip_hdr->ip_src));
        printf("ㄴDestination IP Address  : %s\n", inet_ntoa(ip_hdr->ip_dst));
        printf("ㄴProtocol                : %u\n", (unsigned int)ip_hdr->ip_p);

        // TCP 헤더 정보 출력
        printf("TCP Header\n");
        printf("ㄴSource Port             : %u\n", ntohs(tcp_hdr->th_sport));
        printf("ㄴDestination Port        : %u\n", ntohs(tcp_hdr->th_dport));

        
        printf("Payload (first 20 bytes):\n");
        print_hex(payload, payload_len);

        printf("\n");  // 줄 바꿈
    }

    pcap_close(pcap);  // pcap 세션 닫기
    return 0;  // 프로그램 종료
}

