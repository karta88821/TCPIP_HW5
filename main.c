#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "fill_packet.h"
#include "pcap.h"

#define ICMP_HEADER_LEN 8
#define BUFFER_SIZE 128

uint16_t in_cksum(uint16_t *addr, int len, int csum) {
    int sum = csum;

    while(len > 1)  {
        sum += *addr++;
        len -= 2;
    }

    if(len == 1) sum += htons(*(uint8_t *)addr << 8);

    sum = (sum >> 16) + (sum & 0xffff); 
    sum += (sum >> 16);        
    return ~sum; 
}

pid_t pid;

int main(int argc, char* argv[])
{
	int sockfd;
	int on = 1;
	
	pid = getpid();
	struct sockaddr_in dst;
	bzero(&dst, sizeof(dst));
	dst.sin_family = AF_INET;
	myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
	int count = DEFAULT_SEND_COUNT;
	int timeout = DEFAULT_TIMEOUT;
	
	/* 
	 * in pcap.c, initialize the pcap
	 */
	//pcap_init( target_ip , timeout);

	char icmpRequestBuffer[BUFFER_SIZE], replyBuffer[BUFFER_SIZE];  // ICMP request 和 收到的IP封包

	/* 建立ICMP Request(Echo message) */
    struct icmp *icmpRequest = (struct icmp *) icmpRequestBuffer;
    icmpRequest->icmp_type = ICMP_ECHO;
    icmpRequest->icmp_code = htons(0);  // htons(x) returns the value of x in TCP/IP network byte order(little endian -> big endian)
    icmpRequest->icmp_id = htons(pid);  // 用process id當作icmp_id
	
	
	if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0)
	{
		perror("socket");
		exit(1);
	}

	if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt");
		exit(1);
	}
	
	
	
	/*
	 *   Use "sendto" to send packets, and use "pcap_get_reply"(in pcap.c) 
		 or use the standard socket like the one in the ARP homework
 	 *   to get the "ICMP echo response" packets 
	 *	 You should reset the timer every time before you send a packet.
	 */
	 if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
	{
			perror("sendto");
			exit(1);
	}

	free(packet);

	return 0;
}

