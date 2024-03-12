#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct ether_header *eth_h;
struct tcphdr *tcp_h;
struct ip *ip_h;

uint16_t eth_t;

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
		printf("%u bytes captured\n", header->caplen);
		
		unsigned int packet_len = header->caplen;
		unsigned int ip_h_len;
		unsigned int tcp_h_len;
		unsigned int all_len;
		unsigned int payload_len;

		eth_h = (ether_header*)packet;
		eth_t = ntohs(eth_h->ether_type);

		printf("[+] Ethernet Header\n");
		printf("[+] Src Mac Addr : %s\n", ether_ntoa((ether_addr*)eth_h->ether_shost));
		printf("[+] Dst Mac Addr : %s\n", ether_ntoa((ether_addr*)eth_h->ether_dhost));
		printf("\n");

		if (eth_t == ETHERTYPE_IP){
			packet += sizeof(ether_header);
			ip_h = (ip*)packet;

			printf("[+] IP Header\n");
			printf("[+] Src IP : %s\n", inet_ntoa(ip_h->ip_src));
			printf("[+] Dst IP : %s\n", inet_ntoa(ip_h->ip_dst));
			printf("\n");

			if (ip_h->ip_p == IPPROTO_TCP){ 
				ip_h_len = ip_h->ip_hl;
				packet += ip_h_len;
				tcp_h = (tcphdr*)(packet);

				printf("[+] TCP Header\n");
				printf("[+] Src Port : %d\n", ntohs(tcp_h->source));
				printf("[+] Dst Port : %d\n", ntohs(tcp_h->dest));
				printf("\n");

				tcp_h_len = tcp_h->th_off * 4;
				all_len = 14 + ip_h_len + tcp_h_len;
				if (packet_len > all_len){
					packet += tcp_h_len;
					printf("[+] Payload : ");
					payload_len = packet_len - all_len;
					if (payload_len >= 16)
						payload_len = 16;
					while (payload_len--){
						printf("%02x ", *(packet++));
					}
					printf("\n");
				}
			}
		}
		printf("[-] End This Packet Captuer\n");
		printf("-----------------------------\n");
	}
	pcap_close(pcap);
}
