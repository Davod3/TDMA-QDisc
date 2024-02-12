#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct sk_buff *create_packet(struct net_device *dev) {
    struct sk_buff *skb;
    struct ethhdr *eth_header;
    unsigned char dest_mac[ETH_ALEN] = {0x00, 0x00, 0xAA, 0x55, 0x01, 0x02};
    unsigned char source_mac[ETH_ALEN] = {0x00, 0x00, 0xAA, 0x55, 0x01, 0x01};

    // Allocate a socket buffer
    skb = dev_alloc_skb(ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr));
    if (!skb) {
        printk(KERN_ERR "Failed to allocate skb\n");
        return -ENOMEM;
    }

    // Set up the Ethernet header
    skb->dev = dev;  // Set the network device
    skb->pkt_type = PACKET_OUTGOING;
    skb_reserve(skb, ETH_HLEN);  // Reserve space for Ethernet header
    skb->protocol = htons(ETH_P_IP);

    // Set up the IP header
    ip_header = (struct iphdr *)skb_put(skb, sizeof(struct iphdr));
    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->saddr = source_ip;
    ip_header->daddr = dest_ip;
    ip_header->tot_len = htons(skb->len - ETH_HLEN);

    // Set up the UDP header
    udp_header = (struct udphdr *)skb_put(skb, sizeof(struct udphdr));
    udp_header->source = udp_src_port;
    udp_header->dest = udp_dest_port;
    udp_header->len = htons(skb->len - ETH_HLEN - sizeof(struct iphdr));
    udp_header->check = 0;  // You may calculate the UDP checksum if needed
    return skb;
}

MODULE_LICENSE("GPL");
