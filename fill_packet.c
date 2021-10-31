#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include "shared.h"


#define ICMP_HEADER_LEN 8

uint16_t cksum(uint16_t *addr, int len, int csum) {
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

void fill_iphdr ( struct ip *ip_hdr , uint32_t dst_ip) {
    ip_hdr->ip_hl = sizeof(struct ip);                                         // header len
    ip_hdr->ip_len = PACKET_SIZE;  // htons(sizeof(struct ip) + sizeof(struct icmpheader))
	ip_hdr->ip_id = htons(0);                                                     // ID
    ip_hdr->ip_ttl = 1;                                                           // TTL
    ip_hdr->ip_p = IPPROTO_ICMP;                                               // protocol
    ip_hdr->ip_sum = cksum((uint16_t*) ip_hdr, ip_hdr->ip_hl, 0); 
    ip_hdr->ip_src.s_addr = inet_addr(net);
    ip_hdr->ip_dst.s_addr = dst_ip;            
}

void fill_icmphdr (struct icmphdr *icmp_hdr) {
    icmp_hdr->type = ICMP_ECHO;
	icmp_hdr->un.echo.id = htons(pid);
    icmp_hdr->un.echo.sequence = htons(seq++);
}

u16 fill_cksum(struct icmphdr *icmp_hdr) {
	icmp_hdr->checksum = cksum((uint16_t*) icmp_hdr, ICMP_HEADER_LEN, 0);
}