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

//THIS STRUCT MUST NOT EXCEED 38 BYTES (MAX IP OPTIONS LENGTH - 2 Bytes for info)
struct ratdma_packet_annotations {

    s64 transmission_offset;    //Amount of time in ns from the start of the slot, to the moment the packet was sent
    s64 slot_id;                //ID of the slot used by the node to transmit the packet
    s64 node_id;                //ID of the node who transmitted the packet
	s64 current_round;          //Current round as seen by the node who sent the packet
};

#define TDMA_DATA_IP_OPT_TYPE 30
#define TDMA_DATA_IP_OPT_SIZE sizeof(struct ratdma_packet_annotations) + 2
#define TDMA_DATA_IP_OPT_PADDING (TDMA_DATA_IP_OPT_SIZE - (intdiv(TDMA_DATA_IP_OPT_SIZE, 4) * 4))
#define TDMA_DATA_IP_OPT_TOTAL_SIZE (TDMA_DATA_IP_OPT_SIZE + TDMA_DATA_IP_OPT_PADDING)

static s64 intdiv(s64 a, u64 b) {
	return (((a * ((a >= 0) ? 1 : -1)) / b) * ((a >= 0) ? 1 : -1)) - ((!(a >= 0)) && (!(((a * ((a >= 0) ? 1 : -1)) % b) == 0)));
}

struct sk_buff* ratdma_annotate_skb(struct sk_buff* skb, s64 slot_start, s64 slot_id, s64 node_id, s64 current_round){

	skb_reset_mac_header(skb);

	struct ethhdr *eth = (struct ethhdr *) skb_mac_header(skb);

	if(eth->h_proto == htons(ETH_P_IP)) {

		skb_set_network_header(skb, sizeof (struct ethhdr));

		if(skb_headroom(skb) < TDMA_DATA_IP_OPT_TOTAL_SIZE) {

			int result = skb_cow_head(skb, TDMA_DATA_IP_OPT_TOTAL_SIZE);

		}

		struct iphdr *iph = ip_hdr(skb);

		//Pointer to start of headers
		void* skb_data_start = skb->data;

		//Pointer to start of clean 4 bytes
		void* skb_start = skb_push(skb, TDMA_DATA_IP_OPT_TOTAL_SIZE);

		int memory_to_move_len = sizeof (struct ethhdr) + (iph->ihl * 4); 

		//Shift everything until end of IP Header to the new start of SKB
		memmove(skb_start, skb_data_start, memory_to_move_len);
		
		//Reset Headers
		skb_reset_mac_header(skb);
		skb_set_network_header(skb, sizeof (struct ethhdr));

        //Re-calculate ip header size
		iph = ip_hdr(skb);

		iph->ihl += intdiv(TDMA_DATA_IP_OPT_TOTAL_SIZE, 4);
		iph->tot_len = htons(ntohs(iph->tot_len) + TDMA_DATA_IP_OPT_TOTAL_SIZE);

		unsigned char* opts = (unsigned char*)(iph + 1); //Start of options field

		//Setup options
		opts[0] = TDMA_DATA_IP_OPT_TYPE; //Option Type
		opts[1] = TDMA_DATA_IP_OPT_TOTAL_SIZE; //Options total size;
		
		s64 now = ktime_get_real_ns();

		struct ratdma_packet_annotations* annotations = (struct ratdma_packet_annotations*) (opts+2);
        annotations->transmission_offset = now - slot_start;
        annotations->slot_id = slot_id;
        annotations->node_id = node_id;
		annotations->current_round = current_round;

		//printk(KERN_DEBUG "Transmission Offset: %lld\n", annotations->transmission_offset);
		
		for (size_t i = TDMA_DATA_IP_OPT_SIZE; i < TDMA_DATA_IP_OPT_TOTAL_SIZE; i++)
		{
			opts[i] = 1; //Set NOP option for padding
		}

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