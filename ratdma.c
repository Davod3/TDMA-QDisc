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
#include <linux/sort.h>

//Get functions from topology module
extern s64 topology_get_reference_node(void);
extern void topology_get_delays_and_reset(void* copy);

//THIS STRUCT MUST NOT EXCEED 40 BYTES (MAX IP OPTIONS LENGTH)
struct ratdma_packet_annotations {

    s64 transmission_offset;    //Amount of time in ns from the start of the slot, to the moment the packet was sent
    s64 slot_id;                //ID of the slot used by the node to transmit the packet
    s64 node_id;                //ID of the node who transmitted the packet
	s64 slot_number				//Sequential number of slots used so far
};

#define TDMA_DATA_IP_OPT_TYPE 30
#define TDMA_DATA_IP_OPT_SIZE sizeof(struct ratdma_packet_annotations) + 2
#define TDMA_DATA_IP_OPT_PADDING (TDMA_DATA_IP_OPT_SIZE - (intdiv(TDMA_DATA_IP_OPT_SIZE, 4) * 4))
#define TDMA_DATA_IP_OPT_TOTAL_SIZE (TDMA_DATA_IP_OPT_SIZE + TDMA_DATA_IP_OPT_PADDING)

#define MAX_NODES 20
#define MAX_DELAYS 5000

s64 previous_offset = 0;

struct ratdma_packet_delays {

    s64 node_delays[MAX_NODES][MAX_DELAYS];
    s64 delay_counters[MAX_NODES];

};

static s64 intdiv(s64 a, u64 b) {
	return (((a * ((a >= 0) ? 1 : -1)) / b) * ((a >= 0) ? 1 : -1)) - ((!(a >= 0)) && (!(((a * ((a >= 0) ? 1 : -1)) % b) == 0)));
}

static s64 mod(s64 a, s64 b)
{
    s64 r = a % b;
    return r < 0 ? r + b : r;
}

struct sk_buff* ratdma_annotate_skb(struct sk_buff* skb, s64 slot_start, s64 slot_id, s64 node_id, s64 slot_number, s64 now, s64 slot_len){

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
		
		//s64 now = ktime_get_real_ns();

		s64 t_offset = now - slot_start;

		struct ratdma_packet_annotations* annotations = (struct ratdma_packet_annotations*) (opts+2);
        annotations->transmission_offset = mod(t_offset, slot_len);
        annotations->slot_id = slot_id;
        annotations->node_id = node_id;
		annotations->slot_number = slot_number;

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

static s64 get_average_delay(struct ratdma_packet_delays* delays, s64 reference_node_id) {

	s64 n_delays = delays->delay_counters[reference_node_id] > MAX_DELAYS ? MAX_DELAYS : delays->delay_counters[reference_node_id];
	s64 total = 0;

	for(int i = 0; i < n_delays; i++) {
		total += delays->node_delays[reference_node_id][i];
	}

	//printk(KERN_DEBUG "TOTAL: %lld\n", total);
	//printk(KERN_DEBUG "N_DELAYS: %lld\n", n_delays);

	s64 avg_delay = intdiv(total, n_delays);

	return avg_delay;

}

static int delay_compare(const void *a, const void *b) {
    return (*(s64 *)a - *(s64 *)b);  
}

static s64 get_median_delay(struct ratdma_packet_delays* delays, s64 reference_node_id) {

	s64 n_delays = delays->delay_counters[reference_node_id] > MAX_DELAYS ? MAX_DELAYS : delays->delay_counters[reference_node_id];
	s64* values = delays->node_delays[reference_node_id];

	sort(values, n_delays, sizeof(s64) , &delay_compare, NULL);

	if (n_delays % 2 == 0) {

		return (values[n_delays / 2 - 1] + values[n_delays / 2]) / 2;

	} else {

		return values[n_delays / 2];

	}

}

s64 ratdma_get_offset(s64 slot_len) {

	//printk(KERN_DEBUG "Getting offsets: \n");

	//Call Topology to get reference node
	s64 reference_node_id = topology_get_reference_node();
	printk(KERN_DEBUG "[PARENT]: %lld\n", reference_node_id);

	//I'm a top level node. Use no offset
	if(reference_node_id < 0) {
		return 0;
	}

	//Call Topology to get delays of reference node and reset
	struct ratdma_packet_delays* delays = (struct ratdma_packet_delays*)kcalloc(1, sizeof(struct ratdma_packet_delays), GFP_KERNEL);
	topology_get_delays_and_reset(delays);
	
	//Calculate offset value
	s64 offset = get_average_delay(delays, reference_node_id);
	//s64 offset = get_median_delay(delays, reference_node_id);

	kfree(delays);

	s64 max_offset = (slot_len * 25) / 100;
	//s64 max_offset = 1000000; //ns

	//Low-Pass Filter
	s64 previous_component = (previous_offset * 80) / 100;
	s64 current_component = (offset * 20) / 100;
	s64 smooth_offset = previous_component + current_component;

	s64 return_value = 0;

	//Return offset value to TDMA 
	if(smooth_offset > 0){
		return_value = smooth_offset < max_offset ? smooth_offset : max_offset;
	} else {
		return_value = smooth_offset > -max_offset ? smooth_offset : -max_offset;
	}

	previous_offset = return_value;

	return return_value;

}

static int __init ratdma_init(void) {

    printk(KERN_DEBUG "SYNC: Module initialized.\n");

    return 0;

}

static void __exit ratdma_exit(void) {

    printk(KERN_DEBUG "SYNC: Module disabled.\n");

}

EXPORT_SYMBOL_GPL(ratdma_annotate_skb);
EXPORT_SYMBOL_GPL(ratdma_get_offset);

module_init(ratdma_init);
module_exit(ratdma_exit);
MODULE_LICENSE("GPL");
