#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <cstring>
#include <arpa/inet.h>
#include <errno.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

constexpr uint8_t FLAG_RST_ACK = 0x14;
constexpr uint8_t FLAG_FIN_ACK = 0x11;

void usage() {
    printf("syntax: tcp-block <interface> <pattern>\n");
    printf("sample: tcp-block ens33 \"Host: test.gilgil.net\"\n");
}

bool get_my_mac(const char* iface, Mac& mac) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return false;
    }

    mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
    close(sock);
    return true;
}

uint16_t calc_checksum(uint16_t* ptr, int len){
    uint32_t sum = 0;
    uint16_t odd = 0;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        *(uint8_t *)(&odd) = *(uint8_t *)ptr;
        sum += odd;
    }
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

#pragma pack(push, 1)
struct PseudoHeader {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t zero = 0;
    uint8_t proto = 6;
    uint16_t tcp_len;
};
#pragma pack(pop)

void send_rst_packet(const IpHdr* ip_orig, const TcpHdr* tcp_orig, const char* iface, int payload_len) {
    IpHdr ip = *ip_orig;
    TcpHdr tcp = *tcp_orig;

    ip.total_length = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    ip.checksum = 0;
    ip.checksum = calc_checksum((uint16_t*)&ip, sizeof(IpHdr));

    tcp.tcp_flags = FLAG_RST_ACK;
    tcp.seq_number = htonl(ntohl(tcp_orig->seq_number) + payload_len);
    tcp.offset = sizeof(TcpHdr) / 4;
    tcp.window = htons(0);
    tcp.urgent_ptr = 0;
    tcp.checksum = 0;

    PseudoHeader pseudo = { ip.sip_, ip.dip_, 0, 6, htons(sizeof(TcpHdr)) };
    char buf[sizeof(PseudoHeader) + sizeof(TcpHdr)];
    memcpy(buf, &pseudo, sizeof(PseudoHeader));
    memcpy(buf + sizeof(PseudoHeader), &tcp, sizeof(TcpHdr));
    tcp.checksum = calc_checksum((uint16_t*)buf, sizeof(buf));

    char packet[sizeof(IpHdr) + sizeof(TcpHdr)];
    memcpy(packet, &ip, sizeof(IpHdr));
    memcpy(packet + sizeof(IpHdr), &tcp, sizeof(TcpHdr));

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("socket"); return; }

    int optval = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

    sockaddr_in sin = {};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip.dip_;

    sendto(sock, packet, sizeof(packet), 0, (sockaddr*)&sin, sizeof(sin));
    close(sock);
}

void send_fin_redirect(const IpHdr* ip_orig, const TcpHdr* tcp_orig, const char* iface, int payload_len) {
    const char* redirect_msg = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
    int redirect_len = strlen(redirect_msg);
    int ip_len = sizeof(IpHdr);
    int tcp_len = sizeof(TcpHdr);
    int total_len = ip_len + tcp_len + redirect_len;

    IpHdr ip{};
    ip.ihl = ip_len / 4;
    ip.version = 4;
    ip.ttl = 128;
    ip.protocol = 6;
    ip.total_length = htons(total_len);
    ip.sip_ = ip_orig->dip_; 
    ip.dip_ = ip_orig->sip_;

    ip.checksum = 0;
    ip.checksum = calc_checksum((uint16_t*)&ip, ip_len);

    TcpHdr tcp{};
    tcp.s_port = tcp_orig->d_port;
    tcp.d_port = tcp_orig->s_port;
    tcp.seq_number = tcp_orig->ack_number;
    tcp.ack_number = htonl(ntohl(tcp_orig->seq_number) + payload_len);
    tcp.offset = tcp_len / 4;
    tcp.tcp_flags = FLAG_FIN_ACK;
    tcp.window = htons(5840);
    tcp.urgent_ptr = 0;
    tcp.checksum = 0;

    // PseudoHeader + TCP + Payload
    PseudoHeader pseudo{};
    pseudo.src_ip = ip.sip_;
    pseudo.dst_ip = ip.dip_;
    pseudo.proto = 6;
    pseudo.tcp_len = htons(tcp_len + redirect_len);

    int pseudo_total = sizeof(PseudoHeader) + tcp_len + redirect_len;
    char* pseudo_packet = (char*)malloc(pseudo_total);
    memcpy(pseudo_packet, &pseudo, sizeof(PseudoHeader));
    memcpy(pseudo_packet + sizeof(PseudoHeader), &tcp, tcp_len);
    memcpy(pseudo_packet + sizeof(PseudoHeader) + tcp_len, redirect_msg, redirect_len);

    tcp.checksum = calc_checksum((uint16_t*)pseudo_packet, pseudo_total);
    free(pseudo_packet);

    // Full Packet = IP + TCP + Payload
    char* full_packet = (char*)malloc(total_len);
    memcpy(full_packet, &ip, ip_len);
    memcpy(full_packet + ip_len, &tcp, tcp_len);
    memcpy(full_packet + ip_len + tcp_len, redirect_msg, redirect_len);

    // Raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("socket"); free(full_packet); return; }

    int optval = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip.dip_;

    if (sendto(sock, full_packet, total_len, 0, (sockaddr*)&sin, sizeof(sin)) < 0) {
        perror("sendto");
    } else {
        printf("[+] FIN+302 packet sent successfully\n");
       // printf("[+] total packet length: %d\n", total_len);
    }

    close(sock);
    free(full_packet);
}


int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    const char* dev = argv[1];
    const char* pattern = argv[2];

    Mac my_mac;
    if (!get_my_mac(dev, my_mac)) {
        fprintf(stderr, "Failed to get source MAC address\n");
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res < 0) break;

	// filter
        EthHdr* eth = (EthHdr*)packet;
        if (eth->type() != EthHdr::Ip4) continue;

        IpHdr* ip = (IpHdr*)(packet + sizeof(EthHdr));
        if (ip->protocol != IpHdr::TCP) continue;

        TcpHdr* tcp = (TcpHdr*)((uint8_t*)ip + ip->header_len());
        int ip_len = ip->header_len();
        int tcp_len = tcp->header_len();
        int payload_len = ntohs(ip->total_length) - ip_len - tcp_len;
        const char* payload = (const char*)((uint8_t*)tcp + tcp_len);
	if (payload_len <= 0) continue;
	if ((size_t)payload_len < strlen(pattern)) continue;
        if (payload_len >= 4 && memcmp(payload, "GET ", 4) != 0) continue;

	if (memmem(payload, payload_len, pattern, strlen(pattern)) != nullptr) {
    		//forward
		send_rst_packet(ip, tcp, dev, payload_len);
   		//backward
		send_fin_redirect(ip, tcp, dev, payload_len);
	}
        
    }
    pcap_close(handle);
    return 0;
}

