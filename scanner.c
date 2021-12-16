#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "fill_packet.h"
#include "pcap.h"
#include "shared.h"

//#define BUFFER_SIZE 128

int main() {
	int sockfd;
	int on = 1;

	struct sockaddr_in dst;
	
	pid = getpid();

	bzero(&dst, sizeof(dst));
	dst.sin_family = AF_INET; // IPv4

	int count = DEFAULT_SEND_COUNT;
	int timeout = DEFAULT_TIMEOUT;
	
	pcap_init(timeout);

	printf("PID: %d\n", pid);
	printf("IP address: %s\n", net);
	printf("Mask: %s\n", mask);

	// char icmpRequestBuffer[BUFFER_SIZE], replyBuffer[BUFFER_SIZE];  // ICMP request 和 收到的IP封包
	
	/* create RAW socket */
	if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0)
	{
		perror("socket");
		exit(1);
	}

	/*
	* IP_HDRINCL must be set on the socket so that
	* the kernel does not attempt to automatically add
	* a default ip header to the packet
	*/
	if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt(IP_HDRINCL)");
		exit(1);
	}

	int val = 1;

	if (setsockopt(sd, IPPROTO_IP, IP_DONTFRAG, &val, sizeof(val)) < 0) {
		perror("setsockopt(IP_DONTFRAG)");
		exit(1);
	}

	struct in_addr net_addr, mask_addr;
	inet_aton(net, &(net_addr));
	inet_aton(mask, &(mask_addr));

	unsigned long x = mask_addr.s_addr;

	int numbits;
	for(numbits = 0; x != 0; x >>= 1) {
		if(x & 0x01) {
			numbits++;
		}
	}

	unsigned long hoststart = 1;
	unsigned long hostend = (1<<(32-numbits)) - 1;

	uint32_t network = htonl(net_addr.s_addr & mask_addr.s_addr);

	printf("Sending ICMP Echo Request to all the other subnet IP address...\n");

	/* Send ICMP Echo request to all the other subnet IP addresses */
	for(unsigned i = hoststart; i < hostend; i++) {
		// TODO: Reset timer before send the request

		uint32_t hostip = network + i;

		myicmp *packet = (myicmp*)malloc(PACKET_SIZE);

		// Fill in the IP packet
		struct ip ip_hdr;
		fill_iphdr(&ip_hdr, hostip);
		packet->ip_hdr = ip_hdr;

		// Fill in the ICMP packet
		struct icmphdr icmp_hdr;
		fill_icmphdr(&icmp_hdr);
		packet->icmp_hdr = icmp_hdr;

		// Fill the data
		char student_id[] = "M103040046";
		strncpy(packet->data, student_id, 10);
		
		// Send ICMP Echo request
		if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
		{
			perror("sendto");
			exit(1);
		}

		// Receive ICMP Echo replay
		if (pcap_get_reply() < 0) {
			free(packet);
			continue;
		}

		free(packet);
	}
	
	close(sockfd);

	return 0;
}

