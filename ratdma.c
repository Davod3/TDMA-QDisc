#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/inet.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h> 
#include <linux/ip.h>
#include <net/ip.h> 
#include <linux/udp.h>

#define TDMA_DATA_IP_OPT_TYPE 30
#define TDMA_DATA_IP_OPT_SIZE 4

struct sk_buff* ratdma_annotate_skb(struct sk_buff* skb, s64 transmission_offset, s64 slot_id){

    skb_reset_mac_header(skb);
	skb_set_network_header(skb, sizeof (struct ethhdr));

	struct ethhdr *eth = (struct ethhdr *) skb_mac_header(skb);

	if(eth->h_proto == htons(ETH_P_IP)) {

		if(skb_headroom(skb) < TDMA_DATA_IP_OPT_SIZE) {

			int result = skb_cow_head(skb, TDMA_DATA_IP_OPT_SIZE);

			//printk(KERN_INFO "[TDMA] Not enough space. Allocating more: %d\n", result);
		}

		struct iphdr *iph = ip_hdr(skb);

		//Pointer to start of headers
		void* skb_data_start = skb->data;

		//Pointer to start of clean 4 bytes
		void* skb_start = skb_push(skb, TDMA_DATA_IP_OPT_SIZE);

		int memory_to_move_len = sizeof (struct ethhdr) + (iph->ihl * 4);

		//void* mac_header_before = skb_mac_header(skb);
		//void* ip_header_before = skb_network_header(skb);
		//void* transport_header_before = skb_transport_header(skb);

		//printk(KERN_DEBUG "SKB Start: %d\n", skb_start);
		//printk(KERN_DEBUG "Offset: %d\n", memory_to_move_len);
		//printk(KERN_DEBUG "Data Start: %d\n", skb_data_start);
		//printk(KERN_DEBUG "MAC Start: %d\n", mac_header_before);
		//printk(KERN_DEBUG "IP Start: %d\n", ip_header_before); 
		//printk(KERN_DEBUG "Transport Start: %d\n", transport_header_before);  

		//Shift everything until end of IP Header to the new start of SKB
		memmove(skb_start, skb_data_start, memory_to_move_len);
		
		//Reset Headers
		skb_reset_mac_header(skb);
		skb_set_network_header(skb, sizeof (struct ethhdr));

        //Re-calculate ip header size
		iph = ip_hdr(skb);
		iph->ihl += (TDMA_DATA_IP_OPT_SIZE / 4);
		iph->tot_len = htons(ntohs(iph->tot_len) + TDMA_DATA_IP_OPT_SIZE);

		//printk(KERN_DEBUG "IP Header Len: %d\n", iph->ihl);
		//printk(KERN_DEBUG "IP Version: %d\n", iph->version);


		//void* mac_header_after = skb_mac_header(skb);
		//void* ip_header_after = skb_network_header(skb);
		//void* transport_header_after = skb_transport_header(skb);

		//printk(KERN_DEBUG "SKB Start after: %d\n", skb->data);
		//printk(KERN_DEBUG "MAC Start after: %d\n", mac_header_after);
		//printk(KERN_DEBUG "IP Start after: %d\n", ip_header_after); 
		//printk(KERN_DEBUG "Transport Start after: %d\n", transport_header_after);

		unsigned char* opts = (unsigned char*)(iph + 1); //Start of options field

		//Setup options
		opts[0] = 1; //Option Type
		opts[1] = 1; //Options total size;
		opts[2] = 1;
		opts[3] = 1;

		//Calculate IP checksum
		ip_send_check(iph);
	
	}

	return skb;

}

static int __init ratdma_init(void) {

    printk(KERN_DEBUG "SYNC: Module initialized.\n");

    return 0;

}

static void __exit ratdma_exit(void) {

    printk(KERN_DEBUG "SYNC: Module disabled.\n");

}

EXPORT_SYMBOL_GPL(ratdma_annotate_skb);

module_init(ratdma_init);
module_exit(ratdma_exit);
MODULE_LICENSE("GPL");