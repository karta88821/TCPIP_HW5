#include "pcap.h"
#include <sys/types.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>

#include "shared.h"


extern u16 icmp_req;

//static const char* dev = "enp0s3";

static char filter_string[FILTER_STRING_SIZE] = "icmp";

static pcap_t *p;
static struct pcap_pkthdr hdr;

/*
 * This function is almost completed.
 * But you still need to edit the filter string.
 */
void pcap_init(int timeout)
{	
	char *device;
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	bpf_u_int32 net_raw; // ip address as integer
	bpf_u_int32 mask_raw; // mask as integer
	
	struct in_addr addr; // used for both ip & subnet
	
	struct bpf_program fcode;

	device = pcap_lookupdev(errbuf);
	if (device == NULL) {
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	ret = pcap_lookupnet(device, &net_raw, &mask_raw, errbuf);
	if(ret == -1){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	addr.s_addr = net_raw;
	strcpy(net, inet_ntoa(addr));
	
	if(net == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	
	addr.s_addr = mask_raw;
	strcpy(mask, inet_ntoa(addr));
	
	if(mask == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	
	p = pcap_open_live(device, 8000, 1, timeout, errbuf);
	if(!p){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	if(pcap_compile(p, &fcode, filter_string, 0, mask_raw) == -1){
		pcap_perror(p,"pcap_compile");
		exit(1);
	}
	
	if(pcap_setfilter(p, &fcode) == -1){
		pcap_perror(p,"pcap_setfilter");
		exit(1);
	}
}

int pcap_get_reply(void) {

	const u_char *packet_content;
	packet_content = pcap_next(p, &hdr);

	if (packet_content == NULL) {
		printf("Didn't grab the packet\n");
	}
	
	printf("Grabbed packet of length %d\n", hdr.len);

	u_int eth_len = sizeof(struct ether_header);
	u_int ip_len = sizeof(struct ether_header);

	struct ip *ip_hdr;
	ip_hdr = (struct ip*)(packet_content + eth_len);

	if (ip_hdr->ip_dst.s_addr != inet_addr(net)) {
		return -1;
	}

	char src[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ip_hdr->ip_src.s_addr), src, INET_ADDRSTRLEN);

	if (ip_hdr->ip_p != IPPROTO_ICMP) {
		return -1;
	}

	struct icmphdr *icmp_hdr;
	icmp_hdr = (struct icmphdr*)(packet_content + eth_len + ip_len);

	if (icmp_hdr->type != ICMP_ECHOREPLY) {
		return -1;
	}

	if (icmp_hdr->un.echo.id != htons(pid)) {
		return -1;
	}

	if (icmp_hdr->un.echo.sequence != seq) {
		return -1;
	}

	printf("ICMP Echo replay, the source IP address is: %s", src);

	return 0;
}

