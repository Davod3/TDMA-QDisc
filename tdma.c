// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * THIS QDISC IS AN ADAPTATION OF: 
 * 
 * net/sched/sch_tbf.c	Token Bucket Filter queue.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *		Dmitry Torokhov <dtor@mail.ru> - allow attaching inner qdiscs -
 *						 original idea by Martin Devera
 * 
 * ADAPTED TO TDMA BY:
 * 
 * *Authors* 
 * 
 * ADAPTED TO SYNCED TDMA BY:
 * 
 * *Authors*
 */
#ifndef TDMA_K
#define TDMA_K

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <net/pkt_sched.h>
#include <net/gso.h>

#include <linux/init.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h> 
#include <linux/ip.h>
#include <net/ip.h> 
#include <linux/udp.h>

#include "netlink_sock.h"

#define IP_Header_RM 20
#define UDP_Header_RM 8

#define MAX_SLOT_GUARD 30000000 //ns = 30 ms 

char devname[] = "wlo1"; //Change to interface that will be used
u32 limit = 0;
s64 node_id = 0;
s64 n_nodes = 0;
s64 slot_size= 0;
s64 slot_guard = 0;
s64 use_guard = 0;
s64 self_configured = 0;
s64 broadcast_port = 0;
s64 clockless_sync = 0;
s64 previous_round = 0;
int send_broadcast_flag = 0;
int8_t reset_flag = 0;
s64 slot_start = 0;
s64 slot_end = 0;
s64 round_start = 0;
uint8_t slot_end_flag = 0;
uint8_t slot_start_flag = 0;
uint8_t calculate_offsets_flag = 0;
uint8_t single_node_flag = 1;
s64 total_offset = 0;
s64 slot_number = 0;

//TODO: Is this necessary?
EXPORT_SYMBOL(devname);
EXPORT_SYMBOL(limit);
EXPORT_SYMBOL(node_id);
EXPORT_SYMBOL(n_nodes);
EXPORT_SYMBOL(slot_size);
EXPORT_SYMBOL(use_guard);
EXPORT_SYMBOL(self_configured);
EXPORT_SYMBOL(broadcast_port);
EXPORT_SYMBOL(clockless_sync);

//Get functions from topology module
extern void topology_enable(s64 nodeID, s64 broadcast_port, char* qdisc_dev_name, s64 slot_len_external);
extern s64 topology_get_network_size(void);
extern int topology_get_slot_id(void);
extern void* topology_get_info(void);
extern size_t topology_get_info_size(void);
extern int8_t topology_is_active(void);
extern void topology_set_slot_start(s64 slot_start_external);
extern void topology_update_spanning_tree(void);
extern void topology_set_delays_flag(int value);


//Placeholders if topology module is not loaded
void (*__topology_enable)(s64 nodeID, s64 broadcast_port, char* qdisc_dev_name, s64 slot_len_external);
s64 (*__topology_get_network_size)(void);
int (*__topology_get_slot_id)(void);
void* (*__topology_get_info)(void);
size_t (*__topology_get_info_size)(void);
int8_t (*__topology_is_active)(void);
void (*__topology_set_slot_start)(s64 slot_start_external);
void (*__topology_update_spanning_tree)(void);
void (*__topology_set_delays_flag)(int value);

//Get functions from ratdma module
extern struct sk_buff* ratdma_annotate_skb(struct sk_buff* skb, s64 slot_start, s64 slot_id, s64 node_id, s64 slot_number);
extern s64 ratdma_get_offset(s64 slot_len);

//Placeholders if ratdma module is not loaded
struct sk_buff* (*__ratdma_annotate_skb)(struct sk_buff* skb, s64 slot_start, s64 slot_id, s64 node_id, s64 slot_number);
s64 (*__ratdma_get_offset)(s64 slot_len);

struct tdma_sched_data {
/* Parameters */
	u32		limit;		/* Maximal length of backlog: bytes */

	s64 frame_len;
	s64 slot_len;
	s64	slot_offset;			/* Time check-point */
	s64 broadcast_port;			/* UDP port to broadcast topology packet*/
	s64 node_id;
	s64 slot_id;

	struct Qdisc	*qdisc;		/* Inner qdisc, default - bfifo queue */
	struct qdisc_watchdog watchdog;	/* Watchdog timer */
};

static s64 mod(s64 a, s64 b)
{
    s64 r = a % b;
    return r < 0 ? r + b : r;
}

static s64 intdiv(s64 a, u64 b) {
	return (((a * ((a >= 0) ? 1 : -1)) / b) * ((a >= 0) ? 1 : -1)) - ((!(a >= 0)) && (!(((a * ((a >= 0) ? 1 : -1)) % b) == 0)));
}


/* GSO packet is too big, segment it so that tdma can transmit
 * each segment in time
 */
static int tdma_segment(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free)
{
	struct tdma_sched_data *q = qdisc_priv(sch);
	struct sk_buff *segs, *nskb;
	netdev_features_t features = netif_skb_features(skb);
	unsigned int len = 0;
	int ret, nb, nt;

	segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);

	if (IS_ERR_OR_NULL(segs)) {
		//printk(KERN_DEBUG "drop\t%u\t%s\t(gso)\n", len, qdisc_dev(sch)->name);
		return qdisc_drop(skb, sch, to_free);
	}

	nb = 0;
	nt = 0;
	skb_list_walk_safe(segs, segs, nskb) {
		skb_mark_not_on_list(segs);
		qdisc_skb_cb(segs)->pkt_len = segs->len;

		len = segs->len;
		ret = qdisc_enqueue(segs, q->qdisc, to_free);
		if (ret != NET_XMIT_SUCCESS) {
			if (net_xmit_drop_count(ret))
				qdisc_qstats_drop(sch);
			//printk(KERN_DEBUG "drop\t%u\t%s\t(gso %d)\n", len, qdisc_dev(sch)->name, nt + 1);
		} else {
			
			//printk(KERN_DEBUG "enqueue\t%u\t%s\t(gso %d)\n", len, qdisc_dev(sch)->name, nt + 1);

			sch->qstats.backlog += len;
			sch->q.qlen++;
			nb++;
		}
		nt++;
	}

	consume_skb(skb);
	return nb > 0 ? NET_XMIT_SUCCESS : NET_XMIT_DROP;
}

static void compute_tdma_parameters(struct tdma_sched_data *q) {

	s64 n_nodes = __topology_get_network_size(); //Get from topology module
	s64 slot_id = __topology_get_slot_id(); //Get from topology module
	__topology_update_spanning_tree();

	printk(KERN_DEBUG "[TDMA] Self-Configured (n_nodes --- slot_id --- port)=(%d --- %d -- %lld) \n", n_nodes, slot_id);
	printk(KERN_DEBUG "[SLOT_ID]: %lld\n", slot_id);

	//Compute TDMA Parameters based on Topology
	q->frame_len = q->slot_len * n_nodes;
	q->slot_offset = q->slot_len * slot_id;
	q->slot_id = slot_id;

	//Check if single node
	single_node_flag = (n_nodes == 1);

}

static int tdma_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free)
{

	struct tdma_sched_data *q = qdisc_priv(sch);
	unsigned int len = qdisc_pkt_len(skb), max_len = psched_mtu(qdisc_dev(sch));
	int ret;

	// TODO: make choice of split-gso configurable
	if (qdisc_pkt_len(skb) > max_len) {
		if (skb_is_gso(skb) && skb_gso_validate_mac_len(skb, max_len))
			return tdma_segment(skb, sch, to_free);

		//printk(KERN_DEBUG "\eDROP:\t%u\t%s\e---A---\n", len, qdisc_dev(sch)->name);

		return qdisc_drop(skb, sch, to_free);
	}

	ret = qdisc_enqueue(skb, q->qdisc, to_free);
	if (ret != NET_XMIT_SUCCESS) {
		if (net_xmit_drop_count(ret))
			qdisc_qstats_drop(sch);

		//printk(KERN_DEBUG "DROP:\t%d\t%s\t---B---\n", ret, qdisc_dev(sch)->name);

		return ret;
	}

	//printk(KERN_DEBUG "enqueue\t%u\t%s\n", len, qdisc_dev(sch)->name);

	sch->qstats.backlog += len;
	sch->q.qlen++;
	return NET_XMIT_SUCCESS;
}

/* Code adapted from https://stackoverflow.com/questions/59382141/obtain-interface-netmask-in-linux-kernel-module */
unsigned int inet_addr(struct net_device* dev, int broadcast) {

	//broadcast == 1 -> IPv4 Broadcast Address

	struct in_ifaddr *ifa;
	char addr[16];

	// roughly
	rcu_read_lock();

	for(ifa = rcu_dereference(dev->ip_ptr->ifa_list);
			ifa;
			ifa = rcu_dereference(ifa->ifa_next))

		if(broadcast == 1) {
			snprintf(addr, sizeof(addr), "%pI4", &ifa->ifa_broadcast);
		} else {
			snprintf(addr, sizeof(addr), "%pI4", &ifa->ifa_address);
		}

	rcu_read_unlock();

    int a, b, c, d;
    char arr[4];
    sscanf(addr, "%d.%d.%d.%d", &a, &b, &c, &d);
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
    return *(unsigned int *)arr;
}

/* Code adapted from https://github.com/dmytroshytyi-6WIND/KERNEL-sk_buff-helloWorld */
static struct sk_buff *generate_topology_packet(char* dev_name, struct tdma_sched_data *q, int port) {

	//printk(KERN_INFO "generate_topology_packet: Starting generation...\n");

	//Get network device struct from name
	struct net_device* device = dev_get_by_name(&init_net, dev_name);
	if(device == NULL) {
		printk(KERN_INFO "generate_topology_packet: No such device %s\n", dev_name);
		return NULL;
	}

	//Setup variables
	u_int16_t proto;
	static char addr[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
	u_int8_t dest_addr[ETH_ALEN];
	memcpy(dest_addr, addr, ETH_ALEN);
	proto = ETH_P_IP;
	unsigned char* data;
	void* content = __topology_get_info();
	int data_len = __topology_get_info_size();

	//printk(KERN_INFO "generate_topology_packet: Defined variables... %d\n", __topology_get_info_size());

	//Setup UDP dimensions
	int udp_header_len = 8;
	int udp_payload_len = data_len;
	int udp_total_len = udp_header_len + udp_payload_len;

	//Setup IP dimensions
	int ip_header_len = 20;
	int ip_payload_len = udp_total_len;
	int ip_total_len = ip_header_len + ip_payload_len;

	//Setup skb
	struct sk_buff* skb = alloc_skb(ETH_HLEN + ip_total_len, GFP_ATOMIC);
	skb->dev = device;
	skb->pkt_type = PACKET_OUTGOING;
	skb_reserve(skb, ETH_HLEN + ip_header_len + udp_header_len);

	//printk(KERN_INFO "generate_topology_packet: Reserved packet space...\n");

	//Setup data
	data = skb_put(skb, udp_payload_len);
	memcpy(data, content, data_len);

	//printk(KERN_INFO "generate_topology_packet: Added data...\n");

	//Setup UDP header
	struct udphdr* uh = (struct udphdr*)skb_push(skb,udp_header_len);
	uh->len = htons(udp_total_len);
	uh->source = htons(port == 0 ? q->broadcast_port : port);
	uh->dest = htons(port == 0 ? q->broadcast_port : port);

	//printk(KERN_INFO "generate_topology_packet: Setup udp header...\n");

	//Setup IP header
	struct iphdr* iph = (struct iphdr*)skb_push(skb, ip_header_len);
	iph->ihl = ip_header_len/4;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(ip_total_len);
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;
	iph->saddr = inet_addr(device, 0);
	iph->daddr = inet_addr(device, 1);

	//printk(KERN_INFO "generate_topology_packet: Setup ip header...\n");

	//Setup Ethernet header
	struct ethhdr* eth = (struct ethhdr*)skb_push(skb, sizeof (struct ethhdr));
	skb->protocol = eth->h_proto = htons(proto);
	skb->no_fcs = 1;
	memcpy(eth->h_source, device->dev_addr, ETH_ALEN);
	memcpy(eth->h_dest, dest_addr, ETH_ALEN);

	//printk(KERN_INFO "generate_topology_packet: Setup ethernet header...\n");

	//Calculate IP checksum
	ip_send_check(iph);

	return skb;

}

static struct sk_buff *tdma_dequeue(struct Qdisc *sch)
{

	struct tdma_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;

	s64 now = ktime_get_real_ns();
	s64 relative_timestamp = mod(now, q->frame_len); //[0, frame_len]
	s64 current_round = intdiv(now, q->frame_len); //Number of rounds since start of epoch

    //Runs at the start of each round.
	if(previous_round  != current_round) {
		previous_round = current_round;

		//Round has changed, update variables
		compute_tdma_parameters(q);

		if(single_node_flag){

			//Start collecting delays again
			if(__topology_set_delays_flag)
				__topology_set_delays_flag(1);

			//Set slot start flag to 0
			slot_start_flag = 0;

			//Set slot end flag to 0
			slot_end_flag = 0;

			//Allow for a broadcast to be made when slot starts
			send_broadcast_flag = 0;

			//Allow for offsets to be calculated when slot starts
			calculate_offsets_flag = 0;

		}

		//Recalculate slot structure with updated parameters
		//current_round = intdiv(now, q->frame_len);
		//round_start = (current_round * q->frame_len);// + total_offset;
		//slot_start = mod(q->slot_offset + total_offset, q->frame_len);
		//slot_end = mod(slot_start + q->slot_len - slot_guard, q->frame_len);
		__topology_set_slot_start(slot_start);
	}

	int8_t slot_flag = 0;

	if(slot_start < slot_end) {

		slot_flag = relative_timestamp > slot_start && relative_timestamp <= slot_end;

	} else {

		slot_flag = relative_timestamp > slot_start || relative_timestamp <= slot_end;

	}

    //Check if within slot
    if (slot_flag) {

        //Slot start procedure. Runs at the start of each slot
        if(!slot_start_flag) {

			if(__ratdma_get_offset && __topology_set_delays_flag && !calculate_offsets_flag) {

				printk(KERN_DEBUG "[TDMA ROUND] %lld\n", slot_number);

				//Do this only once per slot start
				calculate_offsets_flag = 1;

				//Stop collecting delays
				__topology_set_delays_flag(0);

				//Get slot offset
				s64 offset = __ratdma_get_offset(q->slot_len);
				total_offset+=offset;
				u64 wait_period = total_offset > 0 ? total_offset : 0;

				printk(KERN_DEBUG "[OFFSET]: %lld\n", offset);
				printk(KERN_DEBUG "[TOTAL OFFSET]: %lld\n", total_offset);
				//printk(KERN_DEBUG "[WAIT]: %llu\n", wait_period);

				//Calculate new slot boundaries
				slot_start = mod(q->slot_offset + total_offset, q->frame_len);
				slot_end = mod(slot_start + q->slot_len - 1, q->frame_len);

				//printk(KERN_DEBUG "[SLOT_START]: %lld\n", slot_start);
				//printk(KERN_DEBUG "[SLOT_END]: %lld\n", slot_end);

				//Check if there are packets in the queue
				if (q->qdisc->ops->peek(q->qdisc)) {

					//If so, wait until they can be transmitted
					qdisc_watchdog_schedule_ns(&q->watchdog, wait_period);

				} else {

					//Queue is empty. Schedule follow up check.
					if(!reset_flag){
						__netif_schedule(sch);
					}

				}

				return NULL;

			}

			//Slot start procedure has finished
			slot_start_flag = 1;
			slot_end_flag = 0;
			slot_number++;

            if(__topology_is_active && __topology_is_active() && !send_broadcast_flag){

				printk(KERN_DEBUG "[SLOT_START]: %lld\n", slot_number);

				//Send broadcast with topology at the start of the slot and no more.
				send_broadcast_flag = 1;

                struct sk_buff* skb = generate_topology_packet(qdisc_dev(sch)->name, q, 0);
                //printk(KERN_INFO "generate_topology_packet: Generated skb!\n");

                if (unlikely(!skb)) {
                    printk(KERN_INFO "generate_topology_packet: Broken packet!\n");
                    return NULL;
                }

				if(__ratdma_annotate_skb) {
					return __ratdma_annotate_skb(skb, slot_start, q->slot_id, q->node_id, slot_number);
				} else {
					return skb;
				}

            } 

        }

        //Check if there is any packet to transmit
        if (q->qdisc->ops->peek(q->qdisc)) {
			
			//If slot guard is enabled, extra check to make sure we don't cross it.
			if(relative_timestamp <= mod(slot_end - slot_guard, q->frame_len) || relative_timestamp > slot_start) {

				skb = qdisc_dequeue_peeked(q->qdisc);
				
				if (unlikely(!skb))
					return NULL;
							
				qdisc_qstats_backlog_dec(sch, skb);
				sch->q.qlen--;
				qdisc_bstats_update(sch, skb);

				printk(KERN_DEBUG "PACKET SENT!!\n");

				if(__ratdma_annotate_skb) {
					return __ratdma_annotate_skb(skb, slot_start, q->slot_id, q->node_id, slot_number);
				} else {
					return skb;
				}

			}

        } else {
            //Queue is empty
			if(!reset_flag){
				__netif_schedule(sch);
			}
			
        }


    } else {

		//Slot end procedure. Occurs once when the slot ends.
		if(!slot_end_flag){

			printk(KERN_DEBUG "[SLOT_END]: %lld\n", slot_number);

			//Slot has ended. Prepare to broadcast again when slot starts.
			send_broadcast_flag = 0;

			//Start collecting delays again
			if(__topology_set_delays_flag)
				__topology_set_delays_flag(1);

			//Slot has finished
			slot_end_flag = 1;

			//Reset slot start
			slot_start_flag = 0;

			//Reset offset calculation
			calculate_offsets_flag = 0;

			//TODO - REMOVE
			struct sk_buff* skb = generate_topology_packet(qdisc_dev(sch)->name, q, 15903);
			return skb;

		}

    }

	qdisc_watchdog_schedule_ns(&q->watchdog, q->frame_len - (relative_timestamp - slot_start));

	return NULL;
}

static void tdma_reset(struct Qdisc *sch)
{

	reset_flag = 1;

	struct tdma_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);

	qdisc_reset(q->qdisc);

}

static const struct nla_policy tdma_policy[TCA_TDMA_MAX + 1] = {
	[TCA_TDMA_PARMS] = { .len = sizeof(struct tc_tdma_qopt) },
};

static void stop_topology(void) {

	//Stop using topology module
	if (__topology_enable)
    	symbol_put(topology_enable);
	if (__topology_get_network_size)
    	symbol_put(topology_get_network_size);
	if (__topology_get_slot_id)
		symbol_put(topology_get_slot_id);
	if (__topology_get_info)
		symbol_put(topology_get_info);
	if (__topology_get_info_size)
		symbol_put(topology_get_info_size);
	if (__topology_is_active)
		symbol_put(topology_is_active);
	if (__topology_set_slot_start)
		symbol_put(topology_set_slot_start);
	if (__topology_update_spanning_tree)
		symbol_put(topology_update_spanning_tree);
	if (__topology_set_delays_flag)
		symbol_put(topology_set_delays_flag);

}

static void stop_ratdma(void) {

	if(__ratdma_annotate_skb){
		symbol_put(ratdma_annotate_skb);
	}
	if(__ratdma_get_offset){
		symbol_put(ratdma_get_offset);
	}

}

static int tdma_change(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack)
{
	int err;
	struct tdma_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_TDMA_MAX + 1];
	struct tc_tdma_qopt *qopt;
	struct Qdisc *child;

	//printk(KERN_DEBUG "[RA-TDMA]######################CHANGE TDMA###############\n");

	if (!opt)
		return -EINVAL;

	if ((err = nla_parse_nested_deprecated(tb, TCA_TDMA_MAX, opt, tdma_policy, NULL)) < 0)
		return err;

	if (!tb[TCA_TDMA_PARMS])
		return -EINVAL;

	qopt = nla_data(tb[TCA_TDMA_PARMS]);

	if ((child = q->qdisc) == &noop_qdisc) {
		if (!(child = qdisc_create_dflt(sch->dev_queue, &bfifo_qdisc_ops, sch->handle, extack)))
			return -ENOMEM;
		qdisc_hash_add(child, true);
	}

	//Limit for backlog packets
	if (qopt->limit && (err = fifo_set_limit(child, qopt->limit)) < 0)
		return err;

	sch_tree_lock(sch);

	q->qdisc = child;

	q->limit = child->limit;

	if (qopt->n_nodes > 0 && qopt->slot_size > 0 && qopt->node_id >= 0) {

		q->node_id = qopt->node_id;

		if(qopt->use_guard){

			//Compute slot guard such that it is 5% of the slot size or MAX_SLOT_GUARD
			s64 possible_slot_guard = (qopt->slot_size * 30) / 100;
			slot_guard = (possible_slot_guard <= MAX_SLOT_GUARD) ? possible_slot_guard : MAX_SLOT_GUARD;

			printk(KERN_DEBUG "[TDMA] Using slot guard - %lld nanoseconds\n", slot_guard);

		} else {

			slot_guard = 0;

			printk(KERN_DEBUG "[TDMA] Slot guard disabled! \n");

		}

		//If desired, enable topology tracker
		if(qopt->self_configured){

			__topology_enable = symbol_get(topology_enable);
			__topology_get_network_size = symbol_get(topology_get_network_size);
			__topology_get_slot_id = symbol_get(topology_get_slot_id);
			__topology_get_info = symbol_get(topology_get_info);
			__topology_get_info_size = symbol_get(topology_get_info_size);
			__topology_is_active = symbol_get(topology_is_active);
			__topology_set_slot_start = symbol_get(topology_set_slot_start);
			__topology_update_spanning_tree = symbol_get(topology_update_spanning_tree);
			__topology_set_delays_flag = symbol_get(topology_set_delays_flag);

			//Check if module is available
			if(__topology_enable && __topology_get_network_size && __topology_get_slot_id && __topology_get_info && __topology_get_info_size && __topology_set_slot_start && __topology_is_active && __topology_update_spanning_tree && __topology_set_delays_flag){

				printk(KERN_DEBUG "[TDMA] Found topology symbols. Self-Configuring Network. \n");

				q->broadcast_port = qopt->broadcast_port;
				__topology_enable(qopt->node_id, qopt->broadcast_port, qdisc_dev(sch)->name, qopt->slot_size);

				q->slot_len = qopt->slot_size;

				compute_tdma_parameters(q);


			} else {

				//Failed to get required symbols. Calculate manually.
				printk(KERN_DEBUG "[TDMA] Failed to find topology symbols. Falling back to manual config. \n");

				//Compute TDMA parameters manually
				q->slot_len = qopt->slot_size;
				q->frame_len = qopt->slot_size * qopt->n_nodes;
				q->slot_offset = qopt->slot_size * qopt->node_id;

			}
		} else {

			//Make sure topology module stops being used
			stop_topology();

			//Compute TDMA parameters manually
			q->slot_len = qopt->slot_size;
			q->frame_len = qopt->slot_size * qopt->n_nodes;
			q->slot_offset = qopt->slot_size * qopt->node_id;

		}

		if(qopt->clockless_sync) {

			//Load required functions from the module
			printk(KERN_DEBUG "[TDMA] Using clockless sync! \n");

			__ratdma_annotate_skb = symbol_get(ratdma_annotate_skb);
			__ratdma_get_offset = symbol_get(ratdma_get_offset);

			//Check if symbols are available
			if(__ratdma_annotate_skb && __ratdma_get_offset) {
				printk(KERN_DEBUG "[TDMA] Clockless symbols found!\n");
			} else {
				printk(KERN_DEBUG "[TDMA] Failed to find clockless sync symbols. Network not syncing.\n");
			}

		} else {

			//Unload functions to allow module to shutdown
			stop_ratdma();

		}

	}

	sch_tree_unlock(sch);

    __netif_schedule(sch);

	qdisc_watchdog_schedule_ns(&q->watchdog, 0);

	return 0;
}

static int tdma_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct tdma_sched_data *q = qdisc_priv(sch);

	q->limit = 0;

	q->frame_len = q->slot_len = 1;
	q->slot_offset = 0;

	q->qdisc = &noop_qdisc;

	qdisc_watchdog_init(&q->watchdog, sch);

	return tdma_change(sch, opt, extack);
}

static void tdma_destroy(struct Qdisc *sch)
{

	struct tdma_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);
	qdisc_put(q->qdisc);
}

static int tdma_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct tdma_sched_data *q = qdisc_priv(sch);
	struct nlattr *nest;
	struct tc_tdma_qopt opt;

	nest = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;


	opt.limit = q->limit;

	printk(KERN_DEBUG "(dump %08x) dev: (name, tx_queue_len, psched_mtu) = (%s, %d, %d)\n", sch->handle, qdisc_dev(sch)->name, qdisc_dev(sch)->tx_queue_len, psched_mtu(qdisc_dev(sch)));
	printk(KERN_DEBUG "(dump %08x) bfifo: (limit, qlen, backlog, drops) = (%d, %d, %d, %d)\n", sch->handle, q->qdisc->limit, q->qdisc->q.qlen, q->qdisc->qstats.backlog, q->qdisc->qstats.drops);
	printk(KERN_DEBUG "(dump %08x) tdma: (limit, qlen, backlog, drops) = (%d, %d, %d, %d)\n", sch->handle, q->limit, sch->q.qlen, sch->qstats.backlog, sch->qstats.drops);
	printk(KERN_DEBUG "(dump %08x) frame_len: %lld\n", sch->handle, q->frame_len);
	printk(KERN_DEBUG "(dump %08x) slot_len: %lld\n", sch->handle, q->slot_len);
	printk(KERN_DEBUG "(dump %08x) slot_offset: %lld\n", sch->handle, q->slot_offset);

	if (nla_put(skb, TCA_TDMA_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}


static struct Qdisc_ops tdma_qdisc_ops __read_mostly = {
	.next		=	NULL,
	.id			=	"tdma",
	.priv_size	=	sizeof(struct tdma_sched_data),
	.enqueue	=	tdma_enqueue,
	.dequeue	=	tdma_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	tdma_init,
	.reset		=	tdma_reset,
	.destroy	=	tdma_destroy,
	.change		=	tdma_change,
	.dump		=	tdma_dump,
	.owner		=	THIS_MODULE,
};

static int __init tdma_module_init(void)
{

	printk(KERN_DEBUG "[TDMA] Qdisc registered!\n");
	return register_qdisc(&tdma_qdisc_ops);
}

static void __exit tdma_module_exit(void)
{	
	printk(KERN_DEBUG "[TDMA] Qdisc unregistered!\n");
	unregister_qdisc(&tdma_qdisc_ops);
	stop_topology();
	stop_ratdma();
}

module_init(tdma_module_init)
module_exit(tdma_module_exit)
MODULE_LICENSE("GPL");

#endif
