#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
// #include <netinet/ip6.h>
// #include <netinet/icmp6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <inttypes.h>

#define BUFSIZE 48

int main(int argc, char** argv){

    struct sockaddr_in6 dst_sockaddr;
    char pkt_buffer[BUFSIZE];
    // size_t pkt_len = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
    size_t pkt_len = sizeof(struct icmp6hdr);
    // struct ip6_hdr *ipv6_header;
    // struct icmp6_hdr *icmpv6_header;
    struct ipv6hdr *ip_hdr;
    struct icmp6hdr *icmp_hdr;
    int sock;
    struct in6_addr dst_addr;
    // char *src_str = argv[1];
    char *devname = argv[1];
    char *dst_str = argv[2];


    
    sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    //sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    

    if (sock < 0) {
	perror("Error creating socket.\n");
	return 0;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, devname, strlen(devname)) < 0) {
        perror("Failed to set SO_BINDTODEVICE");
        exit(1);
    }


    

    // ipv6_header = (struct ip6_hdr*) (pkt_buffer);
    // icmpv6_header = (struct icmp6_hdr*) (pkt_buffer + sizeof(struct ip6_hdr));
    


    /* //ipv6_header->ip6_vfc = 6 << 4;
    inet_pton(AF_INET6, dst_str, &(ipv6_header->ip6_dst));
    inet_pton(AF_INET6, src_str, &(ipv6_header->ip6_src));
    //set IP version to 6 (uint32_t, version is upper 4 bits)
    ipv6_header->ip6_flow = 6 << 28;
    ipv6_header->ip6_hlim = 255;
    //58: next header ICMPv6
    ipv6_header->ip6_nxt = 58;
    //8 byte payload length for ICMPv6 Echo Request
    ipv6_header->ip6_plen = 8;
    
    //type 128 for Echo Request, code value 0
    icmpv6_header->icmp6_type = 128;
    icmpv6_header->icmp6_code = 0; */
    
    // icmp_hdr->icmp6_type = 128;
    

    memset(&dst_sockaddr, 0, sizeof(dst_sockaddr));
    dst_sockaddr.sin6_family = AF_INET6;
    //arbitrarily chosen, not needed for ICMPv6
    dst_sockaddr.sin6_port = 0; // htons(10000);
    inet_pton(AF_INET6, dst_str, &(dst_sockaddr.sin6_addr));

    for (int i = 0; i < 10; ++i) {
        memset(pkt_buffer, 0, BUFSIZE);
        icmp_hdr = (struct icmp6hdr *) pkt_buffer;
        icmp_hdr->icmp6_type = 128;
        icmp_hdr->icmp6_code = 0;
        icmp_hdr->icmp6_identifier = htons(2 * i);
        icmp_hdr->icmp6_sequence = htons(i);
        if (sendto(sock, pkt_buffer, BUFSIZE, 0, (struct sockaddr *) &dst_sockaddr, sizeof(dst_sockaddr)) < 0){
            printf("Error: %s, %d\n", strerror(errno), errno);
        } else {
            printf("Sent!\n");
        }
        printf("%d\n", pkt_len);
    }

    return 0;
}
