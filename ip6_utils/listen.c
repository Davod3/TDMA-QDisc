#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>


//

int main(int argc, char **argv) {
    struct sockaddr_in6 src_addr, dst_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in6);
    int sock;

    int pkt_size, buf_size = 65536;
    int one = 1;
    unsigned char *buffer = (unsigned char *) malloc(buf_size);

    char *devname;

    // if (argc > 1)
    //     devname = argv[1];
    // else {
    //     printf("No device specified\n");
    //     exit(1);
    // }

    if ((sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
        perror("Failed to create socket");
        exit(1);
    }

    if (argc > 1) {
        devname = argv[1];
        if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, devname, strlen(devname)) < 0) {
            perror("Failed to set SO_BINDTODEVICE");
            exit(1);
        }
    }

    // if (setsockopt(sock, IPPROTO_IPV6, IPV6_HDRINCL, &one, sizeof(one)) < 0) {
    //     perror("Failed to set IPV6_HDRINCL");
    //     exit(1);
    // }

    while (1) {
        if ((pkt_size = recvfrom(sock, buffer, buf_size, 0, (struct sockaddr *) &dst_addr, &addr_len)) < 0) {
            perror("Failed to receive packet");
            exit(1);
        }

        // struct iphdr *ip_packet = (struct iphdr *) buffer;
        // struct ipv6hdr *ip_hdr = (struct ipv6hdr *) buffer;
        struct icmp6hdr *icmp_hdr = (struct icmp6hdr *) buffer;
        // struct icmp6hdr *icmp_hdr = (struct icmp6hdr *) ((void *) buffer + sizeof(struct ipv6hdr));
        // char src_addr_str[INET6_ADDRSTRLEN];
        char dst_addr_str[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, &dst_addr, dst_addr_str, INET6_ADDRSTRLEN))
            printf("error: %d\n", errno);

        // src_addr.sin6_addr = ip_hdr->saddr;
        // dst_addr.sin6_addr = ip_hdr->daddr;
        

        // memset(&src_addr, 0, sizeof(src_addr));
        // memset(&dst_addr, 0, sizeof(dst_addr));
        // src_addr.sin_addr.s_addr = ip_packet->saddr;
        // dst_addr.sin_addr.s_addr = ip_packet->daddr;

        printf("Incoming Packet: \n");
        printf("Destination: %s\n", dst_addr_str);
        printf("Size: %d, %d\n", pkt_size, sizeof(icmp_hdr->icmp6_type) + sizeof(icmp_hdr->icmp6_code) + sizeof(icmp_hdr->icmp6_cksum));
        printf("Type: %d\n", icmp_hdr->icmp6_type);
        printf("Code: %d\n", icmp_hdr->icmp6_code);
        printf("Checksum: %04x\n", ntohs((icmp_hdr->icmp6_cksum)));
        printf("Identifier: %04x\n", ntohs(icmp_hdr->icmp6_identifier));
        printf("Sequence: %d\n", ntohs(icmp_hdr->icmp6_sequence));
        for (int i = 0; i < pkt_size; ++i)
            printf("%02hhx ", ((char *) buffer)[i]);

        // printf("Source Address: %s\n", (char *) inet_ntop(AF_INET6, (char *) &src_addr, src_addr_str, INET6_ADDRSTRLEN));
        // printf("Destination Address: %s\n", (char *) inet_ntop(AF_INET6, (char *) &dst_addr, dst_addr_str, INET6_ADDRSTRLEN));
        // printf("Length: %d\n", ((struct iphdr *) buffer)->ihl);
        // printf("Version: %d\n", ((struct iphdr *) buffer)->version);
        // printf("Total Length: %d\n", ((struct iphdr *) buffer)->tot_len);
        // printf("ID: %d\n", ((struct iphdr *) buffer)->id);
        // printf("TTL: %d\n", ((struct iphdr *) buffer)->ttl);
        // printf("Protocol: %d\n", ((struct iphdr *) buffer)->protocol);
        // printf("Protocol: %d\n", icmp_hdr->icmp6_type);
        // printf("Flow label: %x:%x:%x\n", ip_hdr->flow_lbl[0], ip_hdr->flow_lbl[1], ip_hdr->flow_lbl[2]);
        // printf("Nexthdr: %d\n", ip_hdr->nexthdr);
        // printf("Length: %d\n", ip_hdr->payload_len);
        // printf("Hop limit: %d\n", ip_hdr->hop_limit);
        // printf("Type: %d\n", ((struct icmp6hdr *) (ip_hdr + sizeof(ip_hdr)))->icmp6_type);
        // printf("Code: %d\n", ((struct icmp6hdr *) (ip_hdr + sizeof(ip_hdr)))->icmp6_code);
        // printf("Checksum: %04x\n", ((struct icmp6hdr *) (ip_hdr + sizeof(ip_hdr)))->icmp6_cksum);
        

        // printf("Nexthdr: %d, %d\n", ip_hdr + );
        

        // printf("Length: %d\n", ip_hdr->payload_len);
        // printf("Type: %d\n", icmp_hdr->icmp6_type);
        // printf("Code: %d\n", icmp_hdr->icmp6_code);
        // printf("Identifier: %d\n", icmp_hdr->icmp6_identifier);
        // printf("Sequence: %d\n", icmp_hdr->icmp6_sequence);
        // printf("Length: %d\n", icmp_hdr->icmp6_datagram_len);
        printf("\n");

        // printf("Destination Address: %s\n", (char *) inet_pton(src_addr));

        // printf("Packet Size (bytes): %d\n", ntohs(ip_packet->tot_len));
        // printf("Packet Size (bytes): %d\n", ntohs(ipv6_packet->tot_len));
        // printf("Source Address: %s\n", (char *) inet_ntoa(src_addr.sin_addr));
        // printf("Destination Address: %s\n", (char *) inet_ntoa(dst_addr.sin_addr));
        // printf("Source Address: %s\n", (char *) inet_pton(src_addr));
        
        // printf("Identification: %d\n\n", ntohs(ip_packet->id));
        // printf("Identification: %d\n\n", ntohs(ipv6_packet->id));
    }
    
    return 0;
}
